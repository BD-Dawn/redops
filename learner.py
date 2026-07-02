"""Auto-learning system — extracts techniques from engagements and ingests into RAG.

Three learning triggers:
1. Milestone hit — extract the successful technique chain
2. Engagement completion — generate lessons learned from the full chain
3. Stuck-kill — capture what failed and why

Also supports retroactive learning from past engagement findings.

Chunks are tagged with source="learned" in ChromaDB metadata so they can be
identified and managed separately from the base knowledge.
"""

import hashlib
import json
import os
import re
import subprocess

import claude_client
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

# Bounded thread pool — prevents spawning unlimited learner threads
_learner_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="learner")


def _run_async(fn, *args, **kwargs):
    """Run a function in the learner thread pool. Never blocks the caller. Max 2 concurrent."""
    try:
        _learner_pool.submit(fn, *args, **kwargs)
    except RuntimeError:
        pass  # Pool shut down — ignore

from config import CHROMA_DIR, FINDINGS_DIR, EVIDENCE_DIR, ENGAGEMENTS_DIR, MODEL_FAST, get_embedding_function

# Chunk size for learned content — shorter than base KB since these are focused
_LEARNED_CHUNK_SIZE = 1200
_LEARNED_CHUNK_OVERLAP = 150


def _chunk_text(text: str, chunk_size: int = _LEARNED_CHUNK_SIZE,
                overlap: int = _LEARNED_CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk.strip())
        start = end - overlap
    return chunks


def _stable_id(text: str, prefix: str = "learned") -> str:
    """Generate a stable ID for a chunk to avoid duplicates."""
    h = hashlib.md5(text.encode()).hexdigest()[:12]
    return f"{prefix}_{h}"


def _get_collection():
    """Get the ChromaDB collection."""
    import chromadb
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    for name in ["redops", "crto"]:
        try:
            return client.get_collection(
                name, embedding_function=get_embedding_function()
            )
        except Exception:
            continue
    collections = client.list_collections()
    if collections:
        return collections[0]
    raise RuntimeError("No ChromaDB collection found")


def _ingest_chunks(chunks: list[str], metadata: dict, source_name: str) -> int:
    """Ingest chunks into ChromaDB. Returns count of new chunks added."""
    if not chunks:
        return 0

    try:
        collection = _get_collection()
    except Exception as e:
        print(f"[learner] ChromaDB error: {e}")
        return 0

    # Check for existing IDs to avoid duplicates
    ids = [_stable_id(c, source_name) for c in chunks]
    existing = set()
    try:
        result = collection.get(ids=ids)
        existing = set(result["ids"]) if result and result.get("ids") else set()
    except Exception:
        pass

    # Filter out duplicates
    new_docs = []
    new_ids = []
    new_meta = []
    for doc, doc_id in zip(chunks, ids):
        if doc_id not in existing:
            new_docs.append(doc)
            new_ids.append(doc_id)
            new_meta.append({
                **metadata,
                "source": "learned",
                "ingested_at": datetime.now().isoformat(),
            })

    if not new_docs:
        return 0

    try:
        collection.add(documents=new_docs, ids=new_ids, metadatas=new_meta)
        return len(new_docs)
    except Exception as e:
        print(f"[learner] Ingestion error: {e}")
        return 0


def learn_from_finding(finding_path: Path, engagement_id: str = "",
                       mode: str = "", target: str = "") -> int:
    """Extract technique knowledge from a finding markdown file and ingest.

    Converts a structured finding into a technique-focused chunk that answers:
    "When you see X, try Y because Z."

    Returns count of chunks ingested.
    """
    if not finding_path.exists():
        return 0

    content = finding_path.read_text()
    if len(content) < 100:
        return 0

    # Extract key fields
    title = ""
    for line in content.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break

    # Build a technique-focused summary using the fast model
    prompt = f"""Convert this security finding into a concise TECHNIQUE REFERENCE for future use.
Focus on: when to apply this technique, exact commands, what to look for, common pitfalls.
Do NOT include target-specific details (IPs, hostnames, usernames) — generalize the technique.

Format:
## Technique: [name]
**When to use:** [conditions that indicate this technique applies]
**Detection:** [how to identify this vulnerability class]
**Exploitation:**
1. [step with exact command template]
2. [step]
**Gotchas:** [common mistakes, things that block it, how to work around them]
**Pivoting:** [what to do after successful exploitation]

Finding:
{content[:3000]}"""

    try:
        result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=60)
        if result.returncode != 0 or not result.stdout.strip():
            # Fallback: use the raw finding as-is
            technique_doc = content
        else:
            technique_doc = result.stdout.strip()
    except Exception:
        technique_doc = content

    chunks = _chunk_text(technique_doc)
    metadata = {
        "title": title[:100],
        "type": "technique",
        "source_file": finding_path.name,
        "engagement_id": engagement_id,
        "mode": mode,
        "target": target,
    }
    return _ingest_chunks(chunks, metadata, f"finding_{finding_path.stem}")


def learn_from_milestone(agent_response: str, milestone_label: str,
                         target: str = "", engagement_id: str = "",
                         mode: str = "") -> int:
    """Extract technique from a milestone-triggering agent response.

    Called automatically when a milestone is detected (RCE, shell, creds, etc.)
    The response text is distilled into a technique reference and ingested.

    Returns count of chunks ingested.
    """
    if len(agent_response) < 200:
        return 0

    # Use the fast model to distill the technique
    prompt = f"""Extract the TECHNIQUE used to achieve this milestone from the agent's response.
Generalize it — remove target-specific IPs, hostnames, and usernames.

Milestone: {milestone_label}

Format your response as:
## Technique: [name]
**When to use:** [conditions/indicators]
**Steps:**
1. [generalized step with command template]
2. [step]
**Key insight:** [what made this work — the non-obvious part]

Agent response (excerpt):
{agent_response[:2000]}"""

    try:
        result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=60)
        if result.returncode != 0 or not result.stdout.strip():
            return 0
        technique_doc = result.stdout.strip()
    except Exception:
        return 0

    chunks = _chunk_text(technique_doc)
    metadata = {
        "title": f"Milestone: {milestone_label}",
        "type": "technique_milestone",
        "target": target,
        "engagement_id": engagement_id,
        "mode": mode,
    }
    return _ingest_chunks(chunks, metadata, f"milestone_{milestone_label[:30]}")


def learn_from_stuck(stuck_msg: str, approach_summary: str,
                     agent_name: str = "", engagement_id: str = "",
                     mode: str = "") -> int:
    """Record what DIDN'T work so the agent avoids it in future engagements.

    Called when an agent is killed for being stuck. Captures the failed
    approach so RAG can warn against repeating it in similar contexts.

    Returns count of chunks ingested.
    """
    if not stuck_msg or len(stuck_msg) < 50:
        return 0

    anti_pattern = (
        f"## Anti-Pattern: Failed Approach\n"
        f"**Agent:** {agent_name}\n"
        f"**What happened:** {stuck_msg}\n"
        f"**Approaches tried:** {approach_summary}\n"
        f"**Lesson:** When encountering a similar setup, skip these approaches "
        f"and try alternative vectors first. The techniques listed above were "
        f"exhausted without success.\n"
        f"**Recorded:** {datetime.now().isoformat()}\n"
    )

    chunks = _chunk_text(anti_pattern)
    metadata = {
        "title": f"Anti-pattern: {agent_name} stuck",
        "type": "anti_pattern",
        "engagement_id": engagement_id,
        "mode": mode,
    }
    return _ingest_chunks(chunks, metadata, f"stuck_{agent_name}_{datetime.now().strftime('%Y%m%d')}")


def learn_from_engagement(engagement_path: Path) -> int:
    """Generate and ingest lessons learned from a completed engagement.

    Reads the engagement JSON + associated findings to build a comprehensive
    technique chain document.

    Returns count of chunks ingested.
    """
    if not engagement_path.exists():
        return 0

    data = json.loads(engagement_path.read_text())
    target = data.get("target", "")
    mode = data.get("engagement_mode", data.get("mode", ""))
    # Stable per-engagement id (`<mode>/<safe_target>`) so this engagement's
    # learned chunks only resurface for this engagement, never another target.
    safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_").replace(" ", "_")
    engagement_id = f"{mode}/{safe_target}" if target else ""
    notes = data.get("notes", [])
    resume = data.get("resume_point", "")
    creds = data.get("credentials", [])
    compromised = data.get("compromised_hosts", [])

    if not notes and not resume:
        return 0

    # Build a summary of the engagement
    engagement_summary = f"## Engagement Summary\n"
    engagement_summary += f"**Notes:**\n"
    for n in notes:
        # Generalize: remove specific IPs
        n_clean = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "TARGET_IP", n)
        engagement_summary += f"- {n_clean}\n"

    if compromised:
        engagement_summary += f"\n**Access achieved:** {len(compromised)} hosts\n"
        for h in compromised:
            engagement_summary += f"- {h.get('access_level', 'unknown')} access\n"

    if creds:
        engagement_summary += f"\n**Credentials found:** {len(creds)} sets\n"
        for c in creds:
            engagement_summary += f"- Type: {c.get('type', '?')}, Source: {c.get('source', '?')}\n"

    # Find associated findings
    findings_content = ""
    findings_dir = FINDINGS_DIR
    if findings_dir.exists():
        for f in sorted(findings_dir.glob("*.md")):
            content = f.read_text()
            # Check if this finding is related to the target
            if target in content or any(h in content for h in data.get("discovered_hosts", [])):
                findings_content += f"\n\n---\n{content[:1500]}"

    if findings_content:
        engagement_summary += f"\n## Associated Findings\n{findings_content[:4000]}"

    # Use LLM to distill into technique chains
    prompt = f"""Analyze this completed penetration test engagement and extract ALL reusable techniques.
For each technique, generalize it — remove specific IPs, usernames, and hostnames.

Format as a series of technique references:
## Technique Chain: [engagement type]
**Attack path:** [step1] → [step2] → [step3]

### Technique 1: [name]
**When to use:** [indicators]
**Commands:** [generalized commands]
**Key insight:** [what made it work]

### Technique 2: [name]
...

Engagement data:
{engagement_summary[:4000]}"""

    try:
        result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=90)
        if result.returncode != 0 or not result.stdout.strip():
            # Fallback: ingest raw summary
            technique_doc = engagement_summary
        else:
            technique_doc = result.stdout.strip()
    except Exception:
        technique_doc = engagement_summary

    chunks = _chunk_text(technique_doc)
    metadata = {
        "title": f"Engagement: {target}",
        "type": "engagement_chain",
        "engagement_id": engagement_id,
        "mode": mode,
        "target": target,
    }
    return _ingest_chunks(chunks, metadata, f"engagement_{engagement_path.stem}")


def retroactive_learn_all() -> dict:
    """Retroactively learn from ALL past engagement artifacts.

    Scans findings directory and engagement files, ingests everything
    that hasn't been learned yet. Returns stats dict.
    """
    stats = {"findings": 0, "engagements": 0, "chunks": 0}

    # Learn from all findings
    if FINDINGS_DIR.exists():
        for f in sorted(FINDINGS_DIR.glob("*.md")):
            n = learn_from_finding(f)
            if n > 0:
                stats["findings"] += 1
                stats["chunks"] += n
                print(f"[learner] Learned {n} chunks from finding: {f.name}")

    # Learn from all engagement files
    if ENGAGEMENTS_DIR.exists():
        for f in sorted(ENGAGEMENTS_DIR.glob("*.json")):
            if f.name.startswith("_"):
                continue  # Skip metadata files
            try:
                data = json.loads(f.read_text())
                if data.get("notes") or data.get("resume_point"):
                    n = learn_from_engagement(f)
                    if n > 0:
                        stats["engagements"] += 1
                        stats["chunks"] += n
                        print(f"[learner] Learned {n} chunks from engagement: {f.name}")
            except Exception:
                continue

    return stats


# --- Async wrappers (non-blocking) ---
# These are called from agent hot paths where blocking would freeze the engagement.

def learn_from_milestone_async(agent_response: str, milestone_label: str, target: str = "",
                               engagement_id: str = "", mode: str = ""):
    """Non-blocking version of learn_from_milestone."""
    _run_async(learn_from_milestone, agent_response, milestone_label, target,
               engagement_id=engagement_id, mode=mode)

def learn_from_stuck_async(stuck_msg: str, approach_summary: str, agent_name: str = "",
                           engagement_id: str = "", mode: str = ""):
    """Non-blocking version of learn_from_stuck."""
    _run_async(learn_from_stuck, stuck_msg, approach_summary, agent_name,
               engagement_id=engagement_id, mode=mode)


if __name__ == "__main__":
    """CLI: python3 learner.py [retroactive|finding <path>|engagement <path>]"""
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 learner.py retroactive")
        print("       python3 learner.py finding <path.md>")
        print("       python3 learner.py engagement <path.json>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "retroactive":
        print("[learner] Starting retroactive learning from all past engagements...")
        stats = retroactive_learn_all()
        print(f"\n[learner] Done: {stats['findings']} findings, "
              f"{stats['engagements']} engagements, {stats['chunks']} total chunks ingested")
    elif cmd == "finding" and len(sys.argv) > 2:
        n = learn_from_finding(Path(sys.argv[2]))
        print(f"[learner] Ingested {n} chunks from finding")
    elif cmd == "engagement" and len(sys.argv) > 2:
        n = learn_from_engagement(Path(sys.argv[2]))
        print(f"[learner] Ingested {n} chunks from engagement")
    else:
        print(f"Unknown command: {cmd}")
