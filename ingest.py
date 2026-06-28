#!/usr/bin/env python3
"""Ingest PDFs and Sliver reference docs into ChromaDB vector store."""

import re
import sys
from pathlib import Path

from pypdf import PdfReader
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.console import Console

from config import (
    PDF_DIR, DATA_DIR, CHROMA_DIR, ARTICLES_DIR, CHUNK_SIZE, CHUNK_OVERLAP,
    get_embedding_function,
)

SLIVER_HELP_FILE = DATA_DIR / "sliver_v173_help.txt"

console = Console()


def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract all text from a PDF file."""
    try:
        reader = PdfReader(str(pdf_path))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        return text.strip()
    except Exception as e:
        console.print(f"[yellow]Warning: Could not read {pdf_path.name}: {e}[/yellow]")
        return ""


def parse_module_metadata(filename: str) -> dict:
    """Extract module number, title, and type from filename."""
    match = re.match(r"(\d+)_(.+?)_(TEXT|Text|Demo_Video)\.pdf", filename)
    if match:
        num, title, content_type = match.groups()
        return {
            "module_number": int(num),
            "title": title.replace("_", " "),
            "content_type": content_type.lower().replace("_", " "),
            "filename": filename,
        }
    # Fallback: use the full filename stem as title
    match2 = re.match(r"(\d+)_(.+)\.pdf", filename)
    if match2:
        num, title = match2.groups()
        return {
            "module_number": int(num),
            "title": title.replace("_", " "),
            "content_type": "text",
            "filename": filename,
        }
    return {
        "module_number": 0,
        "title": filename.replace(".pdf", "").replace("_", " "),
        "content_type": "unknown",
        "filename": filename,
    }


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks at sentence boundaries."""
    if not text:
        return []

    # Split into sentences
    sentences = re.split(r'(?<=[.!?])\s+', text)
    chunks = []
    current_chunk = ""

    for sentence in sentences:
        if len(current_chunk) + len(sentence) > chunk_size and current_chunk:
            chunks.append(current_chunk.strip())
            # Keep overlap from end of current chunk
            words = current_chunk.split()
            overlap_text = " ".join(words[-overlap // 5:]) if len(words) > overlap // 5 else ""
            current_chunk = overlap_text + " " + sentence
        else:
            current_chunk += " " + sentence if current_chunk else sentence

    if current_chunk.strip():
        chunks.append(current_chunk.strip())

    return chunks


def chunk_sliver_help(text: str) -> list[dict]:
    """Split Sliver help text into per-command chunks with metadata."""
    chunks = []
    # Split on command boundaries: "Command: ..." or "Usage:\n   <cmd>"
    # We'll split on lines that start a new command section
    sections = re.split(r'\n(?=Command: |={40,})', text)

    for section in sections:
        section = section.strip()
        if not section or len(section) < 30:
            continue

        # Try to extract a command name
        cmd_match = re.match(r'Command:\s+(\S+)', section)
        if cmd_match:
            cmd_name = cmd_match.group(1)
            title = f"Sliver {cmd_name}"
        elif section.startswith("==="):
            title = "Sliver Command Reference"
            cmd_name = "overview"
        else:
            # Grab from "Usage:" line
            usage_match = re.search(r'Usage:\s*\n\s+(\S+)', section)
            if usage_match:
                cmd_name = usage_match.group(1)
                title = f"Sliver {cmd_name}"
            else:
                # Use first line as title
                first_line = section.split('\n')[0][:60]
                title = f"Sliver - {first_line}"
                cmd_name = "misc"

        # If section is too long, sub-chunk it
        if len(section) > CHUNK_SIZE * 2:
            sub_chunks = chunk_text(section, CHUNK_SIZE, CHUNK_OVERLAP)
            for i, sc in enumerate(sub_chunks):
                chunks.append({
                    "text": sc,
                    "title": title,
                    "cmd": cmd_name,
                    "chunk_index": i,
                })
        else:
            chunks.append({
                "text": section,
                "title": title,
                "cmd": cmd_name,
                "chunk_index": 0,
            })

    return chunks


def classify_modes(filename: str, text: str = "") -> str:
    """Classify which engagement modes an article is relevant to.

    Returns a comma-separated string of modes (ChromaDB metadata values
    must be scalars, not lists). Articles default to "all" if no specific
    mode signals are detected.

    Mode signals:
      ctf   — CTF writeups, HTB/THM walkthroughs, flag capture techniques
      le    — live environment techniques (general pentesting)
      rt    — red team specific: defense evasion, OPSEC, adversary emulation,
              persistence, phishing, C2, exfiltration
    """
    name = filename.lower()
    combined = (name + " " + text[:3000]).lower()

    modes = set()

    # CTF signals
    ctf_patterns = ["htb_", "thm_", "ctf_", "hackthebox", "tryhackme",
                    "flag capture", "root.txt", "user.txt", "flag.txt"]
    if any(p in combined for p in ctf_patterns):
        modes.add("ctf")

    # Red Team signals — defense evasion, OPSEC, adversary emulation
    rt_patterns = ["defense_evasion", "adversary_emulation", "amsi",
                   "etw_patch", "unhooking", "process_injection",
                   "lolbin", "phishing", "payload_development",
                   "c2_", "exfiltration", "persistence", "evasion",
                   "red_team", "opsec", "detection risk",
                   "infrastructure_", "redirector", "domain_reputation"]
    if any(p in combined for p in rt_patterns):
        modes.add("rt")

    # General pentesting / LE signals (broad techniques)
    le_patterns = ["privilege_escalation", "privesc", "credential",
                   "pivoting", "tunneling", "lateral_movement",
                   "enumeration", "exploitation", "post_exploitation",
                   "portswigger", "sql_injection", "xss", "ssrf",
                   "container_escape", "cloud_", "iam_", "adcs",
                   "tool_", "mssql", "kerberos", "bloodhound"]
    if any(p in combined for p in le_patterns):
        modes.add("le")

    # Research mode signals — vuln research, fuzzing, CWE, exploit dev, patch diff
    research_patterns = ["cwe-", "cwe_", "fuzzing", "harness", "crash_triage",
                         "patch_diff", "bindiff", "diaphora", "exploitdev",
                         "mitigation_bypass", "heap_overflow", "use_after_free",
                         "reverse_engineer", "variant_hunt", "0-day", "0day",
                         "byovd", "driver_vuln"]
    if any(p in combined for p in research_patterns):
        modes.add("research")

    # If nothing matched, it's general knowledge — available to all modes
    if not modes:
        return "all"

    # Technique articles (privesc, tools, web vulns) are useful across all modes
    # Only restrict if the article is EXCLUSIVELY one mode
    if modes == {"ctf"}:
        return "ctf"
    if modes == {"rt"}:
        return "rt,le"  # RT techniques also useful in LE
    if modes == {"research"}:
        return "research"
    # Mixed or LE-only → available to all
    return "all"


def parse_article_metadata(filename: str, text: str = "") -> dict:
    """Extract metadata from an article markdown filename."""
    stem = Path(filename).stem
    title = stem.replace("_", " ").title()
    return {
        "title": title,
        "filename": filename,
        "content_type": "article",
        "modes": classify_modes(filename, text),
    }


def ingest():
    """Main ingestion pipeline."""
    import chromadb

    console.print("[bold blue]Knowledge Base Ingestion[/bold blue]\n")

    # Collect PDFs
    pdfs = sorted(PDF_DIR.glob("*.pdf"))
    if not pdfs:
        console.print(f"[yellow]No PDFs found in {PDF_DIR}[/yellow]")
    else:
        console.print(f"Found [green]{len(pdfs)}[/green] PDFs in {PDF_DIR}")

    # Check for Sliver help
    has_sliver = SLIVER_HELP_FILE.exists()
    if has_sliver:
        console.print(f"Found [green]Sliver v1.7.3 command reference[/green]")
    else:
        console.print(f"[yellow]No Sliver help file at {SLIVER_HELP_FILE}[/yellow]")

    # Collect articles
    articles = sorted(ARTICLES_DIR.glob("*.md")) if ARTICLES_DIR.exists() else []
    if articles:
        console.print(f"Found [green]{len(articles)}[/green] articles in {ARTICLES_DIR}")
    else:
        console.print(f"[yellow]No articles found in {ARTICLES_DIR}[/yellow]")

    if not pdfs and not has_sliver and not articles:
        console.print("[red]No data sources found. Nothing to ingest.[/red]")
        sys.exit(1)

    console.print()

    # Initialize ChromaDB
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Delete existing collections if re-ingesting
    for coll_name in ["redops", "crto"]:
        try:
            client.delete_collection(coll_name)
        except Exception:
            pass

    collection = client.create_collection(
        name="redops",
        metadata={"description": "Red Team Ops knowledge base + Sliver C2 reference"},
        embedding_function=get_embedding_function(),
    )

    all_docs = []
    all_ids = []
    all_metadatas = []

    # --- Ingest PDFs ---
    if pdfs:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Processing PDFs...", total=len(pdfs))

            for pdf_path in pdfs:
                metadata = parse_module_metadata(pdf_path.name)
                text = extract_text_from_pdf(pdf_path)

                if not text or len(text) < 50:
                    progress.advance(task)
                    continue

                # Skip demo video stubs — they contain no useful content
                # (just "Title Demo\nMARK INCOMPLETE CONTINUE\n4:55")
                if metadata["content_type"] == "demo video":
                    progress.advance(task)
                    continue

                chunks = chunk_text(text)

                file_stem = pdf_path.stem
                for i, chunk in enumerate(chunks):
                    doc_id = f"{file_stem}_chunk{i:03d}"
                    all_docs.append(chunk)
                    all_ids.append(doc_id)
                    all_metadatas.append({
                        "module": metadata["module_number"],
                        "title": metadata["title"],
                        "content_type": metadata["content_type"],
                        "chunk_index": i,
                        "source": metadata["filename"],
                        "modes": "all",
                    })

                progress.advance(task)

    # --- Ingest Sliver help reference ---
    if has_sliver:
        console.print("\nProcessing Sliver command reference...")
        sliver_text = SLIVER_HELP_FILE.read_text(errors="replace")
        sliver_chunks = chunk_sliver_help(sliver_text)

        for chunk in sliver_chunks:
            doc_id = f"sliver_{chunk['cmd']}_{chunk['chunk_index']:03d}"
            # Deduplicate IDs in case of collision
            suffix = 0
            orig_id = doc_id
            while doc_id in all_ids:
                suffix += 1
                doc_id = f"{orig_id}_{suffix}"

            all_docs.append(chunk["text"])
            all_ids.append(doc_id)
            all_metadatas.append({
                "module": 9000,
                "title": chunk["title"],
                "content_type": "sliver_reference",
                "chunk_index": chunk["chunk_index"],
                "source": "sliver_v173_help.txt",
                "modes": "all",
            })

        console.print(f"  Extracted [green]{len(sliver_chunks)}[/green] Sliver command chunks")

    # --- Ingest Articles ---
    if articles:
        console.print("\nProcessing articles...")
        for article_path in articles:
            text = article_path.read_text(errors="replace").strip()

            if not text or len(text) < 50:
                continue

            metadata = parse_article_metadata(article_path.name, text)
            chunks = chunk_text(text)
            file_stem = article_path.stem

            for i, chunk in enumerate(chunks):
                doc_id = f"article_{file_stem}_chunk{i:03d}"
                # Deduplicate IDs
                suffix = 0
                orig_id = doc_id
                while doc_id in all_ids:
                    suffix += 1
                    doc_id = f"{orig_id}_{suffix}"

                all_docs.append(chunk)
                all_ids.append(doc_id)
                all_metadatas.append({
                    "module": 8000 + articles.index(article_path),
                    "title": metadata["title"],
                    "content_type": "article",
                    "chunk_index": i,
                    "source": metadata["filename"],
                    "modes": metadata["modes"],
                })

        article_chunks = sum(1 for m in all_metadatas if m["content_type"] == "article")
        console.print(f"  Extracted [green]{article_chunks}[/green] article chunks from {len(articles)} articles")

    # Batch insert into ChromaDB (max 5461 per batch)
    console.print(f"\nIndexing [green]{len(all_docs)}[/green] total chunks into ChromaDB...")

    batch_size = 5000
    for i in range(0, len(all_docs), batch_size):
        end = min(i + batch_size, len(all_docs))
        collection.add(
            documents=all_docs[i:end],
            ids=all_ids[i:end],
            metadatas=all_metadatas[i:end],
        )

    pdf_count = len(pdfs) if pdfs else 0
    article_count = len(articles) if articles else 0
    console.print(f"\n[bold green]Done![/bold green] Indexed {len(all_docs)} chunks ({pdf_count} PDFs + {'Sliver ref' if has_sliver else 'no Sliver ref'} + {article_count} articles).")
    console.print(f"Vector store saved to: {CHROMA_DIR}")


def ingest_incremental(file_path: Path):
    """Add a single file to the existing collection without rebuilding.

    Supports .md articles and .pdf files.
    """
    import chromadb

    if not file_path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        sys.exit(1)

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = None
    for name in ("redops", "crto"):
        try:
            collection = client.get_collection(
                name, embedding_function=get_embedding_function()
            )
            break
        except Exception:
            continue
    if collection is None:
        console.print("[red]No collection found ('redops' or 'crto'). Run a full ingest first.[/red]")
        sys.exit(1)

    existing_ids = set(collection.get()["ids"])
    docs, ids, metadatas = [], [], []

    suffix = file_path.suffix.lower()

    if suffix == ".md":
        text = file_path.read_text(errors="replace").strip()
        if not text or len(text) < 50:
            console.print("[yellow]File too short, skipping.[/yellow]")
            return
        metadata = parse_article_metadata(file_path.name, text)
        chunks = chunk_text(text)
        file_stem = file_path.stem
        # Remove old chunks for this article if re-ingesting
        old_ids = [eid for eid in existing_ids if eid.startswith(f"article_{file_stem}_")]
        if old_ids:
            collection.delete(ids=old_ids)
            console.print(f"[dim]Removed {len(old_ids)} old chunks for {file_path.name}[/dim]")

        existing_articles = len([eid for eid in existing_ids if eid.startswith("article_")])
        module_num = 8000 + existing_articles

        for i, chunk in enumerate(chunks):
            doc_id = f"article_{file_stem}_chunk{i:03d}"
            docs.append(chunk)
            ids.append(doc_id)
            metadatas.append({
                "module": module_num,
                "title": metadata["title"],
                "content_type": "article",
                "chunk_index": i,
                "source": metadata["filename"],
                "modes": metadata["modes"],
            })

    elif suffix == ".pdf":
        metadata = parse_module_metadata(file_path.name)
        text = extract_text_from_pdf(file_path)
        if not text or len(text) < 50:
            console.print("[yellow]Could not extract text or file too short.[/yellow]")
            return
        chunks = chunk_text(text)
        file_stem = file_path.stem
        # Remove old chunks
        old_ids = [eid for eid in existing_ids if eid.startswith(f"{file_stem}_chunk")]
        if old_ids:
            collection.delete(ids=old_ids)
            console.print(f"[dim]Removed {len(old_ids)} old chunks for {file_path.name}[/dim]")

        for i, chunk in enumerate(chunks):
            doc_id = f"{file_stem}_chunk{i:03d}"
            docs.append(chunk)
            ids.append(doc_id)
            metadatas.append({
                "module": metadata["module_number"],
                "title": metadata["title"],
                "content_type": metadata["content_type"],
                "chunk_index": i,
                "source": metadata["filename"],
            })
    else:
        console.print(f"[red]Unsupported file type: {suffix}. Use .md or .pdf[/red]")
        return

    if docs:
        collection.add(documents=docs, ids=ids, metadatas=metadatas)
        console.print(f"[bold green]Done![/bold green] Added {len(docs)} chunks from {file_path.name}.")
        console.print(f"Total chunks in collection: {collection.count()}")


def backfill_modes():
    """Patch all existing chunks that lack a 'modes' metadata field with 'all'."""
    import chromadb

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = None
    for name in ("redops", "crto"):
        try:
            collection = client.get_collection(
                name, embedding_function=get_embedding_function()
            )
            break
        except Exception:
            continue
    if collection is None:
        console.print("[red]No collection found. Run a full ingest first.[/red]")
        sys.exit(1)

    all_data = collection.get(include=["metadatas"])
    ids_to_patch = []
    metas_to_patch = []
    for chunk_id, meta in zip(all_data["ids"], all_data["metadatas"]):
        if "modes" not in meta:
            meta["modes"] = "all"
            ids_to_patch.append(chunk_id)
            metas_to_patch.append(meta)

    if not ids_to_patch:
        console.print("[green]All chunks already have modes metadata.[/green]")
        return

    batch_size = 5000
    for i in range(0, len(ids_to_patch), batch_size):
        end = min(i + batch_size, len(ids_to_patch))
        collection.update(
            ids=ids_to_patch[i:end],
            metadatas=metas_to_patch[i:end],
        )

    console.print(f"[bold green]Done![/bold green] Backfilled 'modes' on {len(ids_to_patch)} chunks.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest training data into redops knowledge base")
    parser.add_argument(
        "--incremental", "-i",
        type=str,
        help="Path to a single .md or .pdf file to add without full rebuild",
    )
    parser.add_argument(
        "--backfill-modes",
        action="store_true",
        help="Patch existing chunks with modes='all' metadata for mode filtering",
    )
    args = parser.parse_args()

    if args.backfill_modes:
        backfill_modes()
    elif args.incremental:
        ingest_incremental(Path(args.incremental))
    else:
        ingest()
