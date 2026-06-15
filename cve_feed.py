"""CVE intelligence feed — fetches fresh vulnerability data and PoCs.

Three-tier pipeline:
  Tier 1: NVD API + CISA KEV + searchsploit (official, structured)
  Tier 2: GitHub repo/code search (fast, where PoCs land first)
  Tier 3: Security blog RSS feeds + Reddit (unstructured, freshest)

Ingests into redops RAG collection. Downloads PoC code to data/pocs/.
"""

import hashlib
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from config import DATA_DIR

# --- Storage ---

POCS_DIR = DATA_DIR / "pocs"
POCS_DIR.mkdir(parents=True, exist_ok=True)

CVE_CACHE_DIR = DATA_DIR / "cve_cache"
CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)


# --- Data model ---

@dataclass
class CVERecord:
    """A CVE with enriched intelligence."""
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""          # critical, high, medium, low
    affected: list[str] = field(default_factory=list)  # product/version strings
    published: str = ""         # ISO date
    exploited_in_wild: bool = False   # CISA KEV
    poc_available: bool = False
    poc_sources: list[dict] = field(default_factory=list)  # [{url, type, local_path}]
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # "lpe", "rce", "web", etc.
    source: str = ""            # "nvd", "kev", "github", "feed"

    def to_dict(self) -> dict:
        return asdict(self)

    def rag_text(self) -> str:
        """Format for RAG ingestion."""
        parts = [f"# {self.cve_id}: {self.description[:200]}"]
        if self.cvss_score:
            parts.append(f"CVSS: {self.cvss_score} ({self.severity})")
        if self.affected:
            parts.append(f"Affected: {', '.join(self.affected[:10])}")
        if self.exploited_in_wild:
            parts.append("STATUS: Actively exploited in the wild (CISA KEV)")
        if self.poc_available:
            sources = [s.get("url", s.get("local_path", "")) for s in self.poc_sources]
            parts.append(f"PoC: {', '.join(sources[:5])}")
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)


# --- HTTP helper ---

def _fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch URL content via curl."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", str(timeout), "-L", url],
            capture_output=True, text=True, timeout=timeout + 10,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return ""


def _fetch_json(url: str, timeout: int = 30) -> dict | list | None:
    """Fetch and parse JSON from URL."""
    text = _fetch_url(url, timeout)
    if text:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return None


# ==========================================================================
# TIER 1: Official sources (NVD, CISA KEV, searchsploit)
# ==========================================================================

def fetch_nvd(days: int = 7, severity: str = "HIGH", on_status=None) -> list[CVERecord]:
    """Fetch recent CVEs from NVD API v2.0.

    Args:
        days: How many days back to search
        severity: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
    """
    records = []
    end = datetime.utcnow()
    start = end - timedelta(days=days)

    start_str = start.strftime("%Y-%m-%dT00:00:00.000")
    end_str = end.strftime("%Y-%m-%dT23:59:59.999")

    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"pubStartDate={start_str}&pubEndDate={end_str}"
        f"&cvssV3Severity={severity}"
        f"&resultsPerPage=100"
    )

    if on_status:
        on_status(f"[cve-sync] Fetching NVD: {severity}+ CVEs from last {days} days...")

    data = _fetch_json(url, timeout=45)
    if not data or "vulnerabilities" not in data:
        # Try CRITICAL if HIGH failed
        if severity == "HIGH":
            url2 = url.replace(f"cvssV3Severity={severity}", "cvssV3Severity=CRITICAL")
            data = _fetch_json(url2, timeout=45)
        if not data or "vulnerabilities" not in data:
            if on_status:
                on_status("[cve-sync] NVD API returned no results or is unavailable")
            return records

    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        # Description
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        cvss_severity = ""
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version in metrics:
                m = metrics[version][0].get("cvssData", {})
                cvss_score = m.get("baseScore", 0.0)
                cvss_vector = m.get("vectorString", "")
                cvss_severity = m.get("baseSeverity", "").lower()
                break

        # Affected products (CPE)
        affected = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        # Extract readable product:version from CPE
                        parts = cpe.split(":")
                        if len(parts) >= 6:
                            product = parts[4].replace("_", " ")
                            version = parts[5] if parts[5] != "*" else "all"
                            affected.append(f"{product} {version}")

        # References
        refs = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]

        # Tags from description
        tags = _extract_tags(desc)

        # Published date
        published = cve_data.get("published", "")[:10]

        records.append(CVERecord(
            cve_id=cve_id,
            description=desc,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=cvss_severity or severity.lower(),
            affected=affected[:15],
            published=published,
            references=refs[:10],
            tags=tags,
            source="nvd",
        ))

    if on_status:
        on_status(f"[cve-sync] NVD: {len(records)} CVEs fetched")

    # Also fetch CRITICAL if we fetched HIGH
    if severity == "HIGH" and records:
        critical = fetch_nvd(days, "CRITICAL", on_status=None)
        # Dedup
        seen = {r.cve_id for r in records}
        for c in critical:
            if c.cve_id not in seen:
                records.append(c)

    return records


def fetch_cisa_kev(on_status=None) -> list[CVERecord]:
    """Fetch CISA Known Exploited Vulnerabilities catalog.

    These are confirmed exploited in the wild — highest priority.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    if on_status:
        on_status("[cve-sync] Fetching CISA KEV (actively exploited)...")

    data = _fetch_json(url, timeout=30)
    if not data or "vulnerabilities" not in data:
        if on_status:
            on_status("[cve-sync] CISA KEV unavailable")
        return []

    records = []
    # Only return recent entries (last 30 days)
    cutoff = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")

    for v in data["vulnerabilities"]:
        date_added = v.get("dateAdded", "")
        if date_added < cutoff:
            continue

        cve_id = v.get("cveID", "")
        if not cve_id:
            continue

        records.append(CVERecord(
            cve_id=cve_id,
            description=v.get("shortDescription", v.get("vulnerabilityName", "")),
            severity="critical",
            affected=[f"{v.get('vendorProject', '')} {v.get('product', '')}"],
            published=date_added,
            exploited_in_wild=True,
            tags=["kev", "exploited_in_wild"] + _extract_tags(v.get("shortDescription", "")),
            source="kev",
        ))

    if on_status:
        on_status(f"[cve-sync] CISA KEV: {len(records)} actively exploited CVEs (last 30 days)")
    return records


def searchsploit_lookup(cve_id: str) -> list[dict]:
    """Search local Exploit-DB for a CVE. Returns list of {title, path, type}."""
    try:
        result = subprocess.run(
            ["searchsploit", "--json", cve_id],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            exploits = []
            for e in data.get("RESULTS_EXPLOIT", []):
                exploits.append({
                    "title": e.get("Title", ""),
                    "path": e.get("Path", ""),
                    "type": e.get("Type", ""),
                })
            return exploits
    except Exception:
        pass
    return []


def searchsploit_batch(cve_ids: list[str], on_status=None) -> dict[str, list[dict]]:
    """Batch searchsploit lookup for multiple CVEs."""
    results = {}
    for cve_id in cve_ids:
        exploits = searchsploit_lookup(cve_id)
        if exploits:
            results[cve_id] = exploits
    if on_status and results:
        on_status(f"[cve-sync] searchsploit: PoCs for {len(results)} CVEs")
    return results


# ==========================================================================
# TIER 2: GitHub PoC hunting
# ==========================================================================

def github_search_repos(cve_id: str) -> list[dict]:
    """Search GitHub for repos matching a CVE ID.

    Returns list of {name, url, stars, description, language, updated}.
    Sorted by stars descending.
    """
    url = (
        f"https://api.github.com/search/repositories?"
        f"q={cve_id}+poc+exploit&sort=stars&order=desc&per_page=10"
    )
    data = _fetch_json(url, timeout=15)
    if not data or "items" not in data:
        return []

    repos = []
    for item in data["items"][:10]:
        repos.append({
            "name": item.get("full_name", ""),
            "url": item.get("html_url", ""),
            "stars": item.get("stargazers_count", 0),
            "description": (item.get("description") or "")[:200],
            "language": item.get("language", ""),
            "updated": item.get("updated_at", "")[:10],
        })
    return repos


def github_search_code(cve_id: str) -> list[dict]:
    """Search GitHub code for CVE references in exploit files.

    Finds PoCs that reference a CVE in comments/strings but aren't
    in a dedicated CVE repo. This catches the unindexed stuff.
    """
    # GitHub code search requires auth for reliable results
    # Fall back to repo search if no token
    token = os.getenv("GITHUB_TOKEN", "")

    url = (
        f"https://api.github.com/search/code?"
        f"q={cve_id}+language:python+language:c+language:ruby&per_page=10"
    )
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        cmd = ["curl", "-s", "-m", "15", url]
        if token:
            cmd.extend(["-H", f"Authorization: token {token}"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            hits = []
            for item in data.get("items", [])[:10]:
                repo = item.get("repository", {})
                hits.append({
                    "file": item.get("name", ""),
                    "path": item.get("path", ""),
                    "repo": repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "stars": repo.get("stargazers_count", 0),
                })
            return hits
    except Exception:
        pass
    return []


def github_hunt_pocs(cve_ids: list[str], on_status=None) -> dict[str, list[dict]]:
    """Hunt for PoCs on GitHub for a batch of CVEs.

    Searches both repos and code. Rate-limited to avoid GitHub 403.
    Returns {cve_id: [repo/code results]}.
    """
    results = {}

    for i, cve_id in enumerate(cve_ids):
        if on_status and i % 10 == 0:
            on_status(f"[cve-sync] GitHub search: {i}/{len(cve_ids)} CVEs...")

        repos = github_search_repos(cve_id)
        code = github_search_code(cve_id)

        if repos or code:
            results[cve_id] = {
                "repos": repos,
                "code": code,
            }

        # Rate limit: 10 req/min unauthenticated, 30/min authenticated
        if not os.getenv("GITHUB_TOKEN"):
            time.sleep(6)  # ~10 req/min
        else:
            time.sleep(2)  # ~30 req/min

    if on_status:
        on_status(f"[cve-sync] GitHub: PoCs found for {len(results)}/{len(cve_ids)} CVEs")
    return results


def download_poc(repo_url: str, cve_id: str, on_status=None) -> Path | None:
    """Clone/download a PoC repo to data/pocs/<CVE-ID>/.

    Returns path to downloaded directory, or None on failure.
    """
    poc_dir = POCS_DIR / cve_id
    if poc_dir.exists() and any(poc_dir.iterdir()):
        return poc_dir  # already downloaded

    poc_dir.mkdir(parents=True, exist_ok=True)

    # Try shallow clone
    try:
        git_url = repo_url
        if not git_url.endswith(".git"):
            git_url += ".git"

        result = subprocess.run(
            ["git", "clone", "--depth", "1", git_url, str(poc_dir)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            if on_status:
                on_status(f"[cve-sync] Downloaded PoC: {cve_id} → {poc_dir}")
            return poc_dir
    except Exception:
        pass

    # Fallback: try downloading raw files from the default branch
    # (for repos that block git clone)
    try:
        # Get repo contents via API
        parts = repo_url.rstrip("/").split("/")
        owner, repo = parts[-2], parts[-1]
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
        data = _fetch_json(api_url)
        if data and isinstance(data, list):
            for item in data[:20]:  # limit files
                if item.get("type") == "file" and item.get("download_url"):
                    fname = item["name"]
                    content = _fetch_url(item["download_url"])
                    if content:
                        (poc_dir / fname).write_text(content)
            if any(poc_dir.iterdir()):
                return poc_dir
    except Exception:
        pass

    return None


# ==========================================================================
# TIER 3: Unstructured feeds (RSS/Atom, Reddit)
# ==========================================================================

# Security blog RSS feeds
_RSS_FEEDS = [
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss"),
    ("Rapid7", "https://blog.rapid7.com/rss/"),
    ("Qualys", "https://blog.qualys.com/feed"),
    ("Assetnote", "https://blog.assetnote.io/feed.xml"),
    ("watchTowr", "https://labs.watchtowr.com/rss/"),
    ("PortSwigger", "https://portswigger.net/research/rss"),
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
]

# Reddit
_REDDIT_FEEDS = [
    ("r/netsec", "https://www.reddit.com/r/netsec/.rss"),
    ("r/exploitdev", "https://www.reddit.com/r/ExploitDev/.rss"),
]


def _parse_rss_for_cves(feed_url: str, feed_name: str) -> list[dict]:
    """Parse an RSS/Atom feed and extract CVE references.

    Returns list of {cve_id, title, link, published, source}.
    """
    content = _fetch_url(feed_url, timeout=15)
    if not content:
        return []

    results = []
    # Simple regex-based RSS/Atom parsing (avoid xml dependency)
    # Extract items/entries
    items = re.findall(r"<item>([\s\S]*?)</item>|<entry>([\s\S]*?)</entry>", content)

    for item_match in items:
        item = item_match[0] or item_match[1]

        title = ""
        title_match = re.search(r"<title[^>]*>(.*?)</title>", item, re.DOTALL)
        if title_match:
            title = re.sub(r"<!\[CDATA\[|\]\]>", "", title_match.group(1)).strip()

        link = ""
        link_match = re.search(r'<link[^>]*href=["\']([^"\']+)', item)
        if link_match:
            link = link_match.group(1)
        elif re.search(r"<link>(.*?)</link>", item):
            link = re.search(r"<link>(.*?)</link>", item).group(1)

        pub_date = ""
        date_match = re.search(r"<pubDate>(.*?)</pubDate>|<published>(.*?)</published>", item)
        if date_match:
            pub_date = (date_match.group(1) or date_match.group(2) or "").strip()

        # Extract all CVE IDs mentioned
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", title + " " + item)
        cve_ids = list(set(cve_ids))

        for cve_id in cve_ids:
            results.append({
                "cve_id": cve_id,
                "title": title[:200],
                "link": link,
                "published": pub_date,
                "source": feed_name,
            })

    return results


def fetch_security_feeds(on_status=None) -> list[dict]:
    """Fetch all security RSS feeds and extract CVE references.

    Runs feeds in parallel for speed.
    """
    all_results = []

    if on_status:
        on_status(f"[cve-sync] Fetching {len(_RSS_FEEDS) + len(_REDDIT_FEEDS)} security feeds...")

    all_feeds = [(name, url) for name, url in _RSS_FEEDS + _REDDIT_FEEDS]

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(_parse_rss_for_cves, url, name): name
            for name, url in all_feeds
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results = future.result()
                all_results.extend(results)
            except Exception:
                pass

    # Dedup by CVE ID (keep first occurrence)
    seen = set()
    deduped = []
    for r in all_results:
        if r["cve_id"] not in seen:
            seen.add(r["cve_id"])
            deduped.append(r)

    if on_status:
        on_status(f"[cve-sync] Feeds: {len(deduped)} unique CVE references from blogs/reddit")
    return deduped


# ==========================================================================
# Tag extraction
# ==========================================================================

def _extract_tags(text: str) -> list[str]:
    """Extract vulnerability type tags from description text."""
    tags = []
    lower = text.lower()
    tag_patterns = [
        ("rce", r"\b(remote code execution|rce)\b"),
        ("lpe", r"\b(local privilege escalation|lpe|privilege escalation)\b"),
        ("dos", r"\b(denial of service|dos)\b"),
        ("sqli", r"\b(sql injection|sqli)\b"),
        ("xss", r"\b(cross.site scripting|xss)\b"),
        ("ssrf", r"\b(server.side request forgery|ssrf)\b"),
        ("deserialization", r"\b(deserialization|unserialize)\b"),
        ("buffer_overflow", r"\b(buffer overflow|heap overflow|stack overflow|out.of.bounds)\b"),
        ("uaf", r"\b(use.after.free|uaf)\b"),
        ("auth_bypass", r"\b(authentication bypass|auth bypass)\b"),
        ("info_leak", r"\b(information disclosure|info leak|memory leak)\b"),
        ("path_traversal", r"\b(path traversal|directory traversal)\b"),
    ]
    for tag, pattern in tag_patterns:
        if re.search(pattern, lower):
            tags.append(tag)
    return tags


# ==========================================================================
# Full sync pipeline
# ==========================================================================

def sync_all(days: int = 7, download_pocs: bool = True,
             on_status=None) -> dict:
    """Run full CVE sync pipeline (all 3 tiers).

    Returns summary dict with counts.
    """
    summary = {
        "nvd_cves": 0,
        "kev_cves": 0,
        "feed_cves": 0,
        "pocs_found": 0,
        "pocs_downloaded": 0,
        "total_unique_cves": 0,
        "records": [],
    }

    # --- Tier 1: NVD + CISA KEV ---
    nvd_records = fetch_nvd(days, "HIGH", on_status)
    summary["nvd_cves"] = len(nvd_records)

    kev_records = fetch_cisa_kev(on_status)
    summary["kev_cves"] = len(kev_records)

    # Merge KEV status into NVD records
    kev_ids = {r.cve_id for r in kev_records}
    for r in nvd_records:
        if r.cve_id in kev_ids:
            r.exploited_in_wild = True
            r.tags.append("kev")

    # Add KEV-only CVEs (not in NVD recent)
    nvd_ids = {r.cve_id for r in nvd_records}
    all_records = list(nvd_records)
    for r in kev_records:
        if r.cve_id not in nvd_ids:
            all_records.append(r)

    # searchsploit batch lookup
    all_cve_ids = [r.cve_id for r in all_records]
    sploits = searchsploit_batch(all_cve_ids, on_status)
    for r in all_records:
        if r.cve_id in sploits:
            r.poc_available = True
            for s in sploits[r.cve_id]:
                r.poc_sources.append({
                    "url": f"exploit-db:{s['path']}",
                    "type": "searchsploit",
                    "local_path": s["path"],
                })

    # --- Tier 2: GitHub PoC hunt ---
    # Only search for CVEs that look interesting (high severity or exploited)
    hunt_ids = [r.cve_id for r in all_records
                if r.severity in ("critical", "high") or r.exploited_in_wild][:50]  # cap at 50
    if hunt_ids:
        github_results = github_hunt_pocs(hunt_ids, on_status)
        for cve_id, gh_data in github_results.items():
            for r in all_records:
                if r.cve_id == cve_id:
                    r.poc_available = True
                    for repo in gh_data.get("repos", [])[:3]:
                        r.poc_sources.append({
                            "url": repo["url"],
                            "type": "github_repo",
                            "stars": repo.get("stars", 0),
                            "language": repo.get("language", ""),
                        })
                    for code in gh_data.get("code", [])[:3]:
                        r.poc_sources.append({
                            "url": code.get("repo_url", ""),
                            "type": "github_code",
                            "file": code.get("file", ""),
                        })
                    break
        summary["pocs_found"] = len(github_results)

    # --- Tier 3: Security feeds ---
    feed_cves = fetch_security_feeds(on_status)
    summary["feed_cves"] = len(feed_cves)

    # Merge feed CVEs — add as new records if not already present
    existing_ids = {r.cve_id for r in all_records}
    for fc in feed_cves:
        if fc["cve_id"] not in existing_ids:
            all_records.append(CVERecord(
                cve_id=fc["cve_id"],
                description=fc.get("title", ""),
                references=[fc.get("link", "")],
                tags=_extract_tags(fc.get("title", "")),
                source=f"feed:{fc.get('source', '')}",
            ))
            existing_ids.add(fc["cve_id"])
        else:
            # Add feed reference to existing record
            for r in all_records:
                if r.cve_id == fc["cve_id"]:
                    if fc.get("link"):
                        r.references.append(fc["link"])
                    break

    # --- Download PoCs ---
    if download_pocs:
        downloaded = 0
        for r in all_records:
            if not r.poc_available:
                continue
            for src in r.poc_sources:
                if src.get("type") == "github_repo" and src.get("url"):
                    local = download_poc(src["url"], r.cve_id, on_status)
                    if local:
                        src["local_path"] = str(local)
                        downloaded += 1
                    break  # one download per CVE
        summary["pocs_downloaded"] = downloaded

    summary["total_unique_cves"] = len(all_records)
    summary["records"] = all_records

    # Cache results
    cache_path = CVE_CACHE_DIR / f"sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        cache_data = {
            "synced_at": datetime.now().isoformat(),
            "days": days,
            "summary": {k: v for k, v in summary.items() if k != "records"},
            "records": [r.to_dict() for r in all_records],
        }
        cache_path.write_text(json.dumps(cache_data, indent=2))
    except Exception:
        pass

    if on_status:
        on_status(
            f"[cve-sync] Complete: {summary['total_unique_cves']} CVEs, "
            f"{summary['pocs_found']} with PoCs, "
            f"{summary['pocs_downloaded']} downloaded"
        )

    return summary


def sync_single_cve(cve_id: str, on_status=None) -> CVERecord | None:
    """Fetch full intelligence for a single CVE."""
    if on_status:
        on_status(f"[cve-sync] Looking up {cve_id}...")

    # NVD
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    data = _fetch_json(url, timeout=45)

    record = CVERecord(cve_id=cve_id)

    if data and data.get("vulnerabilities"):
        cve_data = data["vulnerabilities"][0].get("cve", {})
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                record.description = d.get("value", "")
                break
        metrics = cve_data.get("metrics", {})
        for v in ("cvssMetricV31", "cvssMetricV30"):
            if v in metrics:
                m = metrics[v][0].get("cvssData", {})
                record.cvss_score = m.get("baseScore", 0.0)
                record.severity = m.get("baseSeverity", "").lower()
                break
        record.tags = _extract_tags(record.description)

    # searchsploit
    sploits = searchsploit_lookup(cve_id)
    if sploits:
        record.poc_available = True
        for s in sploits:
            record.poc_sources.append({
                "url": f"exploit-db:{s['path']}",
                "type": "searchsploit",
                "local_path": s["path"],
            })

    # GitHub
    repos = github_search_repos(cve_id)
    if repos:
        record.poc_available = True
        for repo in repos[:5]:
            record.poc_sources.append({
                "url": repo["url"],
                "type": "github_repo",
                "stars": repo.get("stars", 0),
            })
        # Download top repo
        if repos[0].get("url"):
            local = download_poc(repos[0]["url"], cve_id, on_status)
            if local:
                record.poc_sources[0]["local_path"] = str(local)

    if on_status:
        poc_str = f", {len(record.poc_sources)} PoCs" if record.poc_available else ""
        on_status(f"[cve-sync] {cve_id}: CVSS {record.cvss_score} ({record.severity}){poc_str}")

    return record


# ==========================================================================
# RAG ingestion
# ==========================================================================

def ingest_to_rag(records: list[CVERecord], on_status=None) -> int:
    """Ingest CVE records into the redops RAG knowledge base.

    Returns number of chunks ingested.
    """
    try:
        from retriever import KnowledgeBase
        kb = KnowledgeBase()
    except Exception:
        if on_status:
            on_status("[cve-sync] RAG ingestion failed — knowledge base not available")
        return 0

    count = 0
    for r in records:
        text = r.rag_text()
        if len(text) < 50:
            continue
        try:
            doc_id = hashlib.md5(r.cve_id.encode()).hexdigest()
            kb.collection.upsert(
                ids=[doc_id],
                documents=[text],
                metadatas=[{
                    "title": f"{r.cve_id}: {r.description[:80]}",
                    "type": "cve",
                    "source": "cve_feed",
                    "cve_id": r.cve_id,
                    "severity": r.severity,
                    "exploited": str(r.exploited_in_wild),
                }],
            )
            count += 1
        except Exception:
            pass

    if on_status:
        on_status(f"[cve-sync] Ingested {count} CVEs into RAG")
    return count
