"""Knowledge retriever for redops vector store.

Improvements over baseline:
- Auto-detects collection name (redops or crto)
- Batch queries to reduce ChromaDB round-trips
- Tighter distance threshold to cut noise
- Result cache to avoid re-querying identical queries within a session
"""

import re
import chromadb
from config import CHROMA_DIR, TOP_K, RAG_MAX_DISTANCE, get_embedding_function

# Conjunctions / connectors that signal distinct sub-topics in a query
_SPLIT_RE = re.compile(
    r"\b(?:and then|then|after that|followed by|and|before|or)\b",
    re.IGNORECASE,
)

# Minimum length for a sub-query to be worth searching
_MIN_SUBQUERY_LEN = 12

# Distance cutoff comes straight from config — do NOT re-clamp here. A previous
# min(RAG_MAX_DISTANCE, 1.05) clamp silently overrode the config value and
# starved retrieval (all-MiniLM hits land at 1.2-1.35).
_EFFECTIVE_MAX_DISTANCE = RAG_MAX_DISTANCE

# Minimum chunk text length — filters out stubs with no actionable content
_MIN_CHUNK_LEN = 80


_TECHNICAL_TERMS = re.compile(
    r"\b("
    r"RAG|LLM|MCP|ReAct|RLHF|FGSM|PGD|"
    r"prompt.?injection|jailbreak|guardrail|evasion|"
    r"poisoning|exfiltration|deserialization|"
    r"vector.?database|embedding|retrieval|knowledge.?base|"
    r"qdrant|chromadb|weaviate|pinecone|"
    r"ollama|vllm|triton|mlflow|huggingface|"
    r"garak|promptfoo|pyrit|deepteam|ragdrag|"
    r"pickle|pytorch|safetensors|onnx|"
    r"agent|tool.?shadow|confused.?deputy|rug.?pull|"
    r"unicode|homoglyph|token.?split|smuggling|"
    r"privesc|lateral|pivot|kerberos|bloodhound|"
    r"enumerate|fingerprint|recon|exploit|attack|"
    r"RCE|SSRF|SSTI|SQLi|XSS|CSRF|"
    r"nmap|nuclei|burp|ferox|ffuf|gobuster|"
    r"impacket|crackmapexec|certipy|rubeus|"
    r"metasploit|sliver|cobalt.?strike"
    r")\b",
    re.IGNORECASE,
)


def decompose_query(query: str) -> list[str]:
    """Split a complex operator query into focused sub-queries.

    Uses lightweight heuristic splitting on conjunctions so each sub-topic
    gets its own vector search.  Also extracts technical terms to form a
    focused keyword sub-query that embeds closer to tagged RAG chunks.
    Falls back to the original query when splitting yields nothing useful.
    """
    parts = _SPLIT_RE.split(query)
    subs = [p.strip(" ,;.\t\n") for p in parts]
    subs = [s for s in subs if len(s) >= _MIN_SUBQUERY_LEN]

    result = [query]

    if len(subs) > 1:
        result.extend(subs)

    # Extract technical terms into a focused keyword query.
    # Duplicate key terms to boost their embedding weight and add
    # related retrieval anchors (e.g. "RAG" -> "RAG pipeline attack").
    _TERM_EXPANSIONS = {
        "rag": "RAG pipeline attack poisoning retrieval",
        "llm": "LLM prompt injection jailbreak",
        "mcp": "MCP tool poisoning agent",
        "agent": "agent attack ReAct injection tool",
        "prompt injection": "prompt injection bypass guardrails evasion",
        "evasion": "evasion bypass filter unicode token",
        "guardrail": "guardrail bypass evasion filter detection",
        "vector database": "vector database qdrant chromadb exploitation",
        "embedding": "embedding collision vector retrieval",
    }
    terms = list(dict.fromkeys(m.lower() for m in _TECHNICAL_TERMS.findall(query)))
    if terms:
        expanded = []
        for t in terms:
            expansion = _TERM_EXPANSIONS.get(t)
            if expansion:
                expanded.append(expansion)
            else:
                expanded.append(t)
        keyword_query = " ".join(expanded)
        if keyword_query not in result and len(keyword_query) >= _MIN_SUBQUERY_LEN:
            result.append(keyword_query)

    return result


class KnowledgeBase:
    """Interface to the redops ChromaDB vector store.

    Features:
    - Auto-detects collection name (tries 'redops' then 'crto')
    - Batch query support for multiple queries in one ChromaDB call
    - In-memory result cache to avoid redundant vector searches
    """

    # Collection name preference order
    _COLLECTION_NAMES = ["redops", "crto"]

    def __init__(self):
        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self.collection = self._find_collection()
        self._cache: dict[str, list[dict]] = {}  # query -> hits

    def _find_collection(self):
        """Auto-detect the collection name."""
        for name in self._COLLECTION_NAMES:
            try:
                return self.client.get_collection(
                    name, embedding_function=get_embedding_function()
                )
            except Exception:
                continue
        # Last resort: first available collection — re-fetch by name with the
        # pinned EF so the handle never falls back to Chroma's implicit default.
        collections = self.client.list_collections()
        if collections:
            return self.client.get_collection(
                collections[0].name, embedding_function=get_embedding_function()
            )
        raise RuntimeError(
            f"No ChromaDB collection found in {CHROMA_DIR}. "
            f"Run: python3 ingest.py"
        )

    @staticmethod
    def _build_where(scope: str | None, module_filter: int | None) -> dict | None:
        """Build the ChromaDB metadata filter enforcing engagement isolation.

        Curated reference knowledge (``source`` != "learned") is global and
        always retrievable. Engagement-derived "learned" chunks are private to
        the engagement that produced them: they only surface when *scope*
        (the active engagement_id) matches their tagged ``engagement_id``.

        With no scope, ALL learned content is excluded — a safe default that
        also hides legacy learned chunks ingested before scoping existed.
        """
        clauses: list[dict] = []
        if scope:
            clauses.append({"$or": [
                {"source": {"$ne": "learned"}},
                {"engagement_id": {"$eq": scope}},
            ]})
        else:
            clauses.append({"source": {"$ne": "learned"}})
        if module_filter is not None:
            clauses.append({"module": {"$eq": module_filter}})
        if len(clauses) == 1:
            return clauses[0]
        return {"$and": clauses}

    def search(
        self,
        query: str,
        n_results: int = TOP_K,
        module_filter: int | None = None,
        max_distance: float = _EFFECTIVE_MAX_DISTANCE,
        scope: str | None = None,
    ) -> list[dict]:
        """Search the knowledge base and return relevant chunks with metadata.

        Chunks with a distance score above max_distance are discarded to
        prevent irrelevant material from diluting the system prompt.

        *scope* is the active engagement_id; it isolates engagement-derived
        "learned" knowledge so one target's distilled techniques never surface
        in another engagement.
        """
        # Check cache
        cache_key = f"{query}|{n_results}|{module_filter}|{max_distance}|{scope}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        where = self._build_where(scope, module_filter)

        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where,
        )

        hits = []
        for i in range(len(results["documents"][0])):
            distance = results["distances"][0][i] if results.get("distances") else None
            if distance is not None and distance > max_distance:
                continue
            text = results["documents"][0][i]
            if len(text) < _MIN_CHUNK_LEN:
                continue
            hits.append({
                "text": text,
                "metadata": results["metadatas"][0][i],
                "distance": distance,
            })

        self._cache[cache_key] = hits
        return hits

    def batch_search(
        self,
        queries: list[str],
        n_results: int = TOP_K,
        max_distance: float = _EFFECTIVE_MAX_DISTANCE,
        scope: str | None = None,
    ) -> list[dict]:
        """Search multiple queries in a single ChromaDB call.

        Deduplicates results across queries. Much faster than calling
        search() in a loop since ChromaDB batches the embedding computation.

        *scope* (active engagement_id) isolates engagement-derived knowledge.
        """
        if not queries:
            return []

        where = self._build_where(scope, None)

        # Split into cached and uncached
        cached_hits = []
        uncached_queries = []
        uncached_indices = []

        for i, q in enumerate(queries):
            cache_key = f"{q}|{n_results}|None|{max_distance}|{scope}"
            if cache_key in self._cache:
                cached_hits.extend(self._cache[cache_key])
            else:
                uncached_queries.append(q)
                uncached_indices.append(i)

        # Batch query uncached
        if uncached_queries:
            results = self.collection.query(
                query_texts=uncached_queries,
                n_results=n_results,
                where=where,
            )

            for qi in range(len(uncached_queries)):
                query_hits = []
                for di in range(len(results["documents"][qi])):
                    distance = results["distances"][qi][di] if results.get("distances") else None
                    if distance is not None and distance > max_distance:
                        continue
                    text = results["documents"][qi][di]
                    if len(text) < _MIN_CHUNK_LEN:
                        continue
                    query_hits.append({
                        "text": text,
                        "metadata": results["metadatas"][qi][di],
                        "distance": distance,
                    })
                # Cache individual query results
                cache_key = f"{uncached_queries[qi]}|{n_results}|None|{max_distance}|{scope}"
                self._cache[cache_key] = query_hits
                cached_hits.extend(query_hits)

        # Deduplicate by chunk text prefix
        seen = set()
        unique = []
        for hit in cached_hits:
            key = hit["text"][:120]
            if key not in seen:
                seen.add(key)
                unique.append(hit)

        unique.sort(key=lambda h: h["distance"] or 0)
        return unique[:n_results]

    def multi_search(
        self,
        query: str,
        n_results: int = TOP_K,
        module_filter: int | None = None,
        max_distance: float = _EFFECTIVE_MAX_DISTANCE,
        scope: str | None = None,
    ) -> list[dict]:
        """Decompose *query* into sub-queries and merge deduplicated results.

        Uses batch_search when possible for better performance.

        *scope* (active engagement_id) isolates engagement-derived knowledge.
        """
        sub_queries = decompose_query(query)

        if len(sub_queries) == 1 and not module_filter:
            return self.search(sub_queries[0], n_results=n_results,
                               max_distance=max_distance, scope=scope)

        if module_filter:
            # Can't batch with module filter — fall back to sequential
            per_query = max(3, n_results // len(sub_queries))
            all_hits: list[dict] = []
            seen: set[str] = set()

            for sq in sub_queries:
                for hit in self.search(sq, n_results=per_query,
                                       module_filter=module_filter,
                                       max_distance=max_distance, scope=scope):
                    key = hit["text"][:120]
                    if key not in seen:
                        seen.add(key)
                        all_hits.append(hit)

            all_hits.sort(key=lambda h: h["distance"] or 0)
            return all_hits[:n_results]

        # Batch search all sub-queries in one ChromaDB call
        per_query = max(3, n_results // len(sub_queries))
        return self.batch_search(sub_queries, n_results=per_query,
                                 max_distance=max_distance, scope=scope)

    def format_context(self, hits: list[dict]) -> str:
        """Format search results into a context string for the LLM."""
        if not hits:
            return ""

        sections = []
        for hit in hits:
            meta = hit["metadata"]
            title = meta.get("title", "Reference")
            module = meta.get("module", "?")
            header = f"[Module {module}: {title}]"
            sections.append(f"{header}\n{hit['text']}")

        return "\n\n---\n\n".join(sections)

    @property
    def stats(self) -> dict:
        """Return collection statistics."""
        return {
            "total_chunks": self.collection.count(),
            "name": self.collection.name,
        }
