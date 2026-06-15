"""REDOPS MCP Server — Exposes Sliver C2, OPSEC scoring, and knowledge base
as MCP tools for Claude Code.

No guardrails, no refusal logic. This is YOUR server for YOUR authorized
red team operations.

Usage:
    python3 /home/kali/OffensiveAI/redops/mcp_server.py

Register in ~/.claude/settings.json:
    {
        "mcpServers": {
            "redops": {
                "command": "python3",
                "args": ["/home/kali/OffensiveAI/redops/mcp_server.py"]
            }
        }
    }
"""

import sys
import os
import json

# Ensure project imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

from sliver_c2 import SliverManager
from opsec import score_command, OpsecResult
from retriever import KnowledgeBase

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "redops",
    instructions=(
        "REDOPS — Red Team Operator MCP Server. "
        "Provides Sliver C2 management, OPSEC command scoring, "
        "redops knowledge base retrieval, and CVE/exploit lookup "
        "for authorized offensive security operations."
    ),
)

# Lazy-initialized singletons
_c2: SliverManager | None = None
_kb: KnowledgeBase | None = None


def _get_c2() -> SliverManager:
    global _c2
    if _c2 is None:
        _c2 = SliverManager()
    return _c2


def _get_kb() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb


def _active_scope() -> str | None:
    """Read the active engagement_id from disk to scope learned-knowledge
    retrieval. Runs in a separate process, so it has no in-memory state —
    the active engagement is the source of truth in `_active.json`.
    """
    try:
        from config import ENGAGEMENTS_DIR
        data = json.loads((ENGAGEMENTS_DIR / "_active.json").read_text())
        target = data.get("target", "")
        if not target:
            return None
        mode = data.get("mode", "ctf")
        safe = target.replace(".", "_").replace("/", "_").replace(":", "_").replace(" ", "_")
        return f"{mode}/{safe}"
    except Exception:
        return None


# ===========================================================================
# Sliver C2 — Server Management
# ===========================================================================

@mcp.tool()
def c2_status() -> str:
    """Get full Sliver C2 status: server daemon, listeners, sessions, beacons."""
    return _get_c2().full_status()


@mcp.tool()
def c2_start_server(lhost: str = "0.0.0.0", lport: int = 31337) -> str:
    """Start the Sliver C2 server daemon and connect.

    Args:
        lhost: Listen address for the gRPC server (default 0.0.0.0)
        lport: Listen port for the gRPC server (default 31337)
    """
    return _get_c2().start_server(lhost, lport)


@mcp.tool()
def c2_stop_server() -> str:
    """Stop the Sliver C2 server daemon."""
    return _get_c2().stop_server()


# ===========================================================================
# Sliver C2 — Listeners
# ===========================================================================

@mcp.tool()
def c2_start_listener(
    protocol: str = "mtls",
    lhost: str = "0.0.0.0",
    lport: int = 8443,
    domain: str = "",
) -> str:
    """Start a Sliver C2 listener.

    Args:
        protocol: Listener protocol — mtls, http, https, dns, or wg
        lhost: Bind address (default 0.0.0.0)
        lport: Bind port (default 8443)
        domain: Domain for DNS/HTTPS listeners (required for DNS)
    """
    return _get_c2().start_listener(protocol, lhost, lport, domain)


@mcp.tool()
def c2_list_jobs() -> str:
    """List all active Sliver listeners/jobs."""
    return _get_c2().list_jobs()


@mcp.tool()
def c2_kill_job(job_id: int) -> str:
    """Kill a Sliver listener/job by its ID.

    Args:
        job_id: The numeric job ID to kill (from c2_list_jobs)
    """
    return _get_c2().kill_job(job_id)


# ===========================================================================
# Sliver C2 — Implant Generation
# ===========================================================================

@mcp.tool()
def c2_generate_implant(
    listener_url: str,
    os_target: str = "windows",
    arch: str = "amd64",
    implant_type: str = "beacon",
    format: str = "exe",
    name: str = "",
    interval: int = 60,
    jitter: int = 30,
) -> str:
    """Generate a Sliver C2 implant.

    Args:
        listener_url: C2 callback URL (e.g. mtls://10.10.10.1:8443, https://c2.example.com:443)
        os_target: Target OS — windows, linux, or darwin
        arch: CPU architecture — amd64, 386, or arm64
        implant_type: beacon (async callbacks) or session (interactive)
        format: Output format — exe, shared (DLL), shellcode, or service
        name: Implant name (auto-generated if empty)
        interval: Beacon callback interval in seconds (default 60)
        jitter: Beacon jitter in seconds (default 30)
    """
    return _get_c2().generate_implant(
        listener_url, os_target, arch, implant_type, format, name, interval, jitter
    )


@mcp.tool()
def c2_list_builds() -> str:
    """List all generated Sliver implant builds."""
    return _get_c2().list_implant_builds()


# ===========================================================================
# Sliver C2 — Sessions & Beacons
# ===========================================================================

@mcp.tool()
def c2_list_sessions() -> str:
    """List all active Sliver sessions (interactive implants)."""
    return _get_c2().list_sessions()


@mcp.tool()
def c2_list_beacons() -> str:
    """List all active Sliver beacons (async implants)."""
    return _get_c2().list_beacons()


@mcp.tool()
def c2_exec(session_id: str, command: str) -> str:
    """Execute a command on a Sliver session (interactive).

    Args:
        session_id: Session ID or prefix (from c2_list_sessions)
        command: The command to execute on the target
    """
    return _get_c2().interact_session(session_id, command)


@mcp.tool()
def c2_task(beacon_id: str, command: str) -> str:
    """Queue a command on a Sliver beacon (async — runs on next check-in).

    Args:
        beacon_id: Beacon ID or prefix (from c2_list_beacons)
        command: The command to queue for execution
    """
    return _get_c2().interact_beacon(beacon_id, command)


# ===========================================================================
# Sliver C2 — Session Operations
# ===========================================================================

@mcp.tool()
def c2_screenshot(session_id: str) -> str:
    """Take a screenshot from a Sliver session. Saved to evidence directory.

    Args:
        session_id: Session ID or prefix
    """
    return _get_c2().session_screenshot(session_id)


@mcp.tool()
def c2_ps(session_id: str) -> str:
    """List running processes on a Sliver session (top 50).

    Args:
        session_id: Session ID or prefix
    """
    return _get_c2().session_ps(session_id)


@mcp.tool()
def c2_upload(session_id: str, local_path: str, remote_path: str) -> str:
    """Upload a file from the local machine to a Sliver session.

    Args:
        session_id: Session ID or prefix
        local_path: Path to the local file to upload
        remote_path: Destination path on the target
    """
    return _get_c2().session_upload(session_id, local_path, remote_path)


@mcp.tool()
def c2_download(session_id: str, remote_path: str) -> str:
    """Download a file from a Sliver session. Saved to evidence directory.

    Args:
        session_id: Session ID or prefix
        remote_path: Path on the target to download
    """
    return _get_c2().session_download(session_id, remote_path)


# ===========================================================================
# OPSEC Scoring
# ===========================================================================

@mcp.tool()
def opsec_score(command: str) -> str:
    """Score a command for OPSEC risk before executing it.

    Returns risk level (LOW/MEDIUM/HIGH/CRITICAL), reasons, and quieter alternatives.

    Args:
        command: The command string to evaluate
    """
    result = score_command(command)
    output = {
        "level": result.level_name,
        "score": result.score,
        "reasons": result.reasons,
        "alternatives": result.alternatives,
    }
    return json.dumps(output, indent=2)


# ===========================================================================
# Knowledge Base (RAG)
# ===========================================================================

@mcp.tool()
def kb_search(query: str, n_results: int = 8) -> str:
    """Search the red team knowledge base for techniques, commands, and tradecraft.

    Queries the ChromaDB vector store containing redops material and ingested articles.
    Returns the most relevant chunks with module info and relevance scores.

    Args:
        query: Natural language search query (e.g. "Kerberoasting techniques", "AMSI bypass methods")
        n_results: Maximum number of results to return (default 8)
    """
    kb = _get_kb()
    hits = kb.multi_search(query, n_results=n_results, scope=_active_scope())
    if not hits:
        return "No relevant material found for this query."
    return kb.format_context(hits)


@mcp.tool()
def kb_stats() -> str:
    """Get knowledge base statistics (total chunks, collection name)."""
    kb = _get_kb()
    stats = kb.stats
    return json.dumps(stats, indent=2)


# ===========================================================================
# CVE Lookup
# ===========================================================================

@mcp.tool()
def cve_search(product: str, version: str = "", max_results: int = 10) -> str:
    """Search for CVEs affecting a product/service via the NVD API.

    Args:
        product: Product or service name (e.g. "Apache 2.4", "OpenSSH", "Microsoft Exchange")
        version: Optional version to narrow results (e.g. "2.4.49")
        max_results: Maximum CVEs to return (default 10)
    """
    import subprocess

    query = f"{product} {version}".strip()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query.replace(' ', '+')}&resultsPerPage={max_results}"

    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "15", url],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return f"NVD API request failed: {result.stderr.strip() or 'no response'}"

        data = json.loads(result.stdout)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"No CVEs found for: {query}"

        lines = [f"Found {data.get('totalResults', len(vulns))} CVEs for '{query}' (showing {len(vulns)}):\n"]
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "?")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")
            # Truncate long descriptions
            if len(desc) > 200:
                desc = desc[:200] + "..."

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            cvss = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss = f"{cvss_data.get('baseScore', '?')} ({cvss_data.get('baseSeverity', '?')})"
                    break

            lines.append(f"**{cve_id}** — CVSS: {cvss}")
            lines.append(f"  {desc}")
            lines.append("")

        return "\n".join(lines)

    except json.JSONDecodeError:
        return "Failed to parse NVD API response."
    except Exception as e:
        return f"CVE search error: {e}"


@mcp.tool()
def cve_exploitdb(search_term: str, cve_id: str = "") -> str:
    """Search ExploitDB via searchsploit for exploits and PoCs.

    Args:
        search_term: Product, service, or keyword to search (e.g. "Apache 2.4.49", "PrintNightmare")
        cve_id: Optional CVE ID to search directly (e.g. "2021-34527")
    """
    import subprocess

    cmd = ["searchsploit", "--json"]
    if cve_id:
        cmd.extend(["--cve", cve_id.replace("CVE-", "")])
    else:
        cmd.append(search_term)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return f"searchsploit failed: {result.stderr.strip()}"

        data = json.loads(result.stdout)
        exploits = data.get("RESULTS_EXPLOIT", [])
        if not exploits:
            return f"No exploits found for: {cve_id or search_term}"

        lines = [f"Found {len(exploits)} exploit(s):\n"]
        for ex in exploits[:15]:
            edb_id = ex.get("EDB-ID", "?")
            title = ex.get("Title", "?")
            path = ex.get("Path", "?")
            date = ex.get("Date Published", "?")
            lines.append(f"  [{edb_id}] {title}")
            lines.append(f"         Date: {date} | Path: {path}")
            lines.append(f"         Mirror: searchsploit -m {edb_id}")
            lines.append("")

        return "\n".join(lines)

    except json.JSONDecodeError:
        # Fallback to plain text output
        result = subprocess.run(
            ["searchsploit"] + (["--cve", cve_id.replace("CVE-", "")] if cve_id else [search_term]),
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.strip() or "No results."
    except Exception as e:
        return f"searchsploit error: {e}"


@mcp.tool()
def cve_find_poc(cve_id: str) -> str:
    """Search GitHub for proof-of-concept exploits for a specific CVE.

    Args:
        cve_id: The CVE ID (e.g. "CVE-2021-34527" or "2021-34527")
    """
    import subprocess

    if not cve_id.upper().startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    # Search GitHub repos
    url = f"https://api.github.com/search/repositories?q={cve_id}+poc&sort=stars&per_page=10"

    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "15",
             "-H", "Accept: application/vnd.github.v3+json",
             url],
            capture_output=True, text=True, timeout=20,
        )

        lines = [f"PoC search results for {cve_id}:\n"]

        # GitHub results
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                repos = data.get("items", [])
                if repos:
                    lines.append(f"**GitHub PoCs** ({len(repos)} found):")
                    for r in repos[:8]:
                        stars = r.get("stargazers_count", 0)
                        lang = r.get("language", "?")
                        updated = r.get("updated_at", "?")[:10]
                        lines.append(f"  [{stars} stars] [{lang}] {r['full_name']}")
                        lines.append(f"           {r.get('description', 'No description')[:100]}")
                        lines.append(f"           URL: {r['html_url']}  Updated: {updated}")
                        lines.append("")
                else:
                    lines.append("**GitHub:** No PoC repos found.")
            except json.JSONDecodeError:
                lines.append("**GitHub:** Failed to parse response.")

        # Also check searchsploit
        lines.append("")
        edb_result = subprocess.run(
            ["searchsploit", "--cve", cve_id.replace("CVE-", "")],
            capture_output=True, text=True, timeout=15,
        )
        edb_out = edb_result.stdout.strip()
        if edb_out and "No Results" not in edb_out:
            lines.append(f"**ExploitDB:**")
            lines.append(edb_out)
        else:
            lines.append("**ExploitDB:** No matching exploits.")

        return "\n".join(lines)

    except Exception as e:
        return f"PoC search error: {e}"


# ===========================================================================
# Engagement State
# ===========================================================================

@mcp.tool()
def engagement_load(name: str = "default") -> str:
    """Load a saved engagement state.

    Args:
        name: Engagement name (default loads the auto-saved state)
    """
    from config import ENGAGEMENTS_DIR
    path = ENGAGEMENTS_DIR / f"{name}.json"
    if not path.exists():
        return f"No engagement found: {name}"
    return path.read_text()


@mcp.tool()
def engagement_list() -> str:
    """List all saved engagements."""
    from config import ENGAGEMENTS_DIR
    files = sorted(ENGAGEMENTS_DIR.glob("*.json"))
    if not files:
        return "No saved engagements."
    lines = ["Saved engagements:"]
    for f in files:
        size = f.stat().st_size
        lines.append(f"  {f.stem} ({size / 1024:.1f} KB)")
    return "\n".join(lines)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()
