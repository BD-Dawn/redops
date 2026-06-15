"""Research knowledge base — separate RAG collection for vulnerability research.

Uses ChromaDB collection "research" (separate from "redops"/"crto" used by
pentest agents). Prevents knowledge pollution between pentest tradecraft
and vulnerability research methodology.

Content: CWE patterns, vulnerability templates, fuzzing harness examples,
exploit development techniques, crash triage methodology.
"""

import chromadb
from pathlib import Path

from config import DATA_DIR, TOP_K, RAG_MAX_DISTANCE

RESEARCH_CHROMA_DIR = DATA_DIR / "chroma_db_research"
RESEARCH_CHROMA_DIR.mkdir(parents=True, exist_ok=True)

_COLLECTION_NAME = "research"

# Tighter distance cutoff for research queries
_EFFECTIVE_MAX_DISTANCE = min(RAG_MAX_DISTANCE, 1.10)
_MIN_CHUNK_LEN = 80


class ResearchKnowledgeBase:
    """Interface to the research ChromaDB vector store."""

    def __init__(self):
        self.client = chromadb.PersistentClient(path=str(RESEARCH_CHROMA_DIR))
        try:
            self.collection = self.client.get_or_create_collection(_COLLECTION_NAME)
        except Exception:
            self.collection = self.client.create_collection(_COLLECTION_NAME)
        self._cache: dict[str, list[dict]] = {}

    def search(self, query: str, n_results: int = TOP_K,
               max_distance: float = _EFFECTIVE_MAX_DISTANCE) -> list[dict]:
        """Search the research knowledge base."""
        cache_key = f"{query}|{n_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.collection.count() == 0:
            return []

        results = self.collection.query(
            query_texts=[query],
            n_results=min(n_results, self.collection.count()),
        )

        hits = []
        for i in range(len(results["documents"][0])):
            distance = results["distances"][0][i] if results.get("distances") else None
            if distance and distance > max_distance:
                continue
            text = results["documents"][0][i]
            if len(text) < _MIN_CHUNK_LEN:
                continue
            meta = results["metadatas"][0][i] if results.get("metadatas") else {}
            hits.append({
                "text": text,
                "distance": distance,
                "metadata": meta,
            })

        self._cache[cache_key] = hits
        return hits

    def add(self, text: str, metadata: dict | None = None, doc_id: str = "") -> None:
        """Add a single chunk to the research knowledge base."""
        import hashlib
        if not doc_id:
            doc_id = hashlib.md5(text.encode()).hexdigest()
        self.collection.upsert(
            ids=[doc_id],
            documents=[text],
            metadatas=[metadata or {}],
        )

    def add_batch(self, chunks: list[dict]) -> int:
        """Add multiple chunks. Each: {text, metadata, id (optional)}.

        Returns number of chunks added.
        """
        import hashlib
        ids = []
        docs = []
        metas = []
        for chunk in chunks:
            text = chunk["text"]
            if len(text) < _MIN_CHUNK_LEN:
                continue
            doc_id = chunk.get("id", hashlib.md5(text.encode()).hexdigest())
            ids.append(doc_id)
            docs.append(text)
            metas.append(chunk.get("metadata", {}))

        if ids:
            self.collection.upsert(ids=ids, documents=docs, metadatas=metas)
        return len(ids)

    def count(self) -> int:
        return self.collection.count()

    def format_context(self, hits: list[dict]) -> str:
        """Format hits into a context string for prompt injection."""
        parts = []
        for h in hits:
            meta = h.get("metadata", {})
            title = meta.get("title", "")
            source = meta.get("source", "")
            header = f"[{title}]" if title else f"[{source}]" if source else ""
            parts.append(f"{header}\n{h['text']}")
        return "\n\n---\n\n".join(parts)


def seed_initial_knowledge() -> int:
    """Seed the research KB with foundational vulnerability knowledge.

    Call this once to bootstrap the collection. Returns chunks added.
    """
    kb = ResearchKnowledgeBase()
    if kb.count() > 0:
        return 0  # already seeded

    chunks = []

    # CWE Top 25 (condensed)
    _CWE_ENTRIES = [
        ("CWE-787", "Out-of-bounds Write", "Writing data past the end or before the beginning of a buffer. Common in C/C++ with memcpy, strcpy, sprintf without length checks. Look for: array indexing without bounds validation, loop boundary errors, off-by-one in buffer size calculations. Exploitation: heap corruption → controlled write → code execution."),
        ("CWE-79", "Cross-site Scripting (XSS)", "Untrusted input rendered in web output without sanitization. Types: reflected (URL params), stored (database), DOM-based (client-side). Look for: echo/print of user input, template injection, innerHTML assignment. Exploitation: session hijacking, credential theft, defacement."),
        ("CWE-89", "SQL Injection", "User input concatenated into SQL queries. Look for: string formatting/concatenation in query building, lack of parameterized queries. Exploitation: data extraction, auth bypass, RCE via xp_cmdshell or INTO OUTFILE."),
        ("CWE-416", "Use After Free", "Accessing memory after it has been freed. Common in C/C++ with complex object lifecycles. Look for: free() followed by use of the same pointer, error handling paths that free then fall through. Exploitation: heap manipulation → type confusion → code execution."),
        ("CWE-78", "OS Command Injection", "User input passed to system(), popen(), exec() without sanitization. Look for: shell=True in Python subprocess, backtick/system() in PHP/Ruby, Runtime.exec() in Java with string concat. Exploitation: direct RCE."),
        ("CWE-20", "Improper Input Validation", "Insufficient validation of user input before processing. Look for: missing length checks, type confusion, integer overflow in size calculations, negative index acceptance. Exploitation: depends on what the unvalidated input reaches."),
        ("CWE-125", "Out-of-bounds Read", "Reading data past buffer boundaries. Less severe than write (usually info leak, not RCE). Look for: buffer reads with attacker-controlled length/offset. Exploitation: info leak (ASLR bypass, secret extraction), crash."),
        ("CWE-22", "Path Traversal", "User input in file path operations without sanitization. Look for: ../../../etc/passwd patterns, missing canonicalization, improper path joining. Exploitation: arbitrary file read/write."),
        ("CWE-352", "Cross-Site Request Forgery", "Missing CSRF tokens on state-changing requests. Look for: POST/PUT/DELETE without token validation, cookie-based auth without SameSite. Exploitation: unauthorized actions on behalf of authenticated users."),
        ("CWE-434", "Unrestricted Upload of File with Dangerous Type", "File upload without type/content validation. Look for: extension-only checks (bypassable), missing content-type validation, uploads to web-accessible directories. Exploitation: webshell upload → RCE."),
        ("CWE-862", "Missing Authorization", "Actions performed without checking user permissions. Look for: IDOR (direct object references), missing role checks, admin functions accessible without auth. Exploitation: privilege escalation, data access."),
        ("CWE-476", "NULL Pointer Dereference", "Dereferencing a pointer that may be NULL. Look for: missing NULL checks after malloc/calloc, error returns that set pointer to NULL. Exploitation: usually DoS only, occasionally exploitable for info leak."),
        ("CWE-190", "Integer Overflow or Wraparound", "Arithmetic operation produces a value too large for the integer type. Look for: multiplication of user-controlled values used as buffer sizes, addition without overflow checks. Exploitation: undersized buffer allocation → heap overflow."),
        ("CWE-502", "Deserialization of Untrusted Data", "Deserializing attacker-controlled data. Look for: pickle.loads(), yaml.load(), Java ObjectInputStream, PHP unserialize(), JSON.parse() with reviver. Exploitation: RCE via gadget chains."),
        ("CWE-287", "Improper Authentication", "Authentication can be bypassed. Look for: hardcoded credentials, default passwords, auth logic flaws, JWT none algorithm, timing attacks. Exploitation: unauthorized access."),
    ]

    for cwe_id, name, desc in _CWE_ENTRIES:
        chunks.append({
            "text": f"# {cwe_id}: {name}\n\n{desc}",
            "metadata": {"title": f"{cwe_id}: {name}", "type": "cwe", "source": "cwe_top25"},
        })

    # Fuzzing harness templates
    _FUZZ_TEMPLATES = [
        ("AFL++ harness template (C)", """# AFL++ Fuzzing Harness Template (C)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the target library header
#include "target.h"

int main(int argc, char *argv[]) {
    // Read input from file (AFL provides via @@)
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Limit input size to prevent OOM
    if (size > 1024 * 1024) { fclose(f); return 1; }

    char *buf = malloc(size);
    fread(buf, 1, size, f);
    fclose(f);

    // Call the target function with fuzzer input
    target_parse(buf, size);

    free(buf);
    return 0;
}
```

Compile: `afl-clang-fast -fsanitize=address -g harness.c -o harness -ltarget`
Run: `afl-fuzz -i seeds/ -o findings/ -- ./harness @@`
Stop condition: 5 unique crashes or coverage plateau (no new paths for 30 min)."""),

        ("libFuzzer harness template (C)", """# libFuzzer Harness Template (C)

```c
#include <stdint.h>
#include <stddef.h>

// Include target header
#include "target.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Limit to prevent timeouts
    if (size > 1024 * 1024) return 0;

    // Call target function
    target_parse(data, size);

    return 0;
}
```

Compile: `clang -fsanitize=fuzzer,address -g harness.c -o harness_fuzzer -ltarget`
Run: `./harness_fuzzer -max_len=1048576 corpus/`
Seeds: place valid sample inputs in corpus/ directory."""),

        ("Crash triage with ASAN", """# Crash Triage Methodology

1. **Deduplicate**: Group crashes by stack trace hash
   `for f in crashes/*; do ./target_asan $f 2>&1 | md5sum; done | sort | uniq -w 32`

2. **Classify with ASAN**: Run each unique crash under AddressSanitizer
   - heap-buffer-overflow → likely exploitable (write = weaponizable, read = info leak)
   - heap-use-after-free → likely exploitable (type confusion, controlled read/write)
   - stack-buffer-overflow → exploitable if canary not present
   - null-dereference → usually DoS only
   - double-free → exploitable (heap manipulation)

3. **GDB exploitable plugin**: `gdb -batch -ex run -ex exploitable ./target crash_input`
   - EXPLOITABLE: controlled instruction pointer or write-what-where
   - PROBABLY_EXPLOITABLE: access violation on write, stack corruption
   - PROBABLY_NOT_EXPLOITABLE: read AV, divide by zero
   - NOT_EXPLOITABLE: null dereference at low address

4. **Minimize**: `afl-tmin -i crash_input -o minimized -- ./target @@`

5. **Root cause**: What input bytes control the crash? Use binary diff between
   crashing and non-crashing inputs. Modify bytes systematically to find control."""),
    ]

    for title, text in _FUZZ_TEMPLATES:
        chunks.append({
            "text": text,
            "metadata": {"title": title, "type": "technique", "source": "fuzzing_templates"},
        })

    return kb.add_batch(chunks)
