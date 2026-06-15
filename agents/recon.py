"""Recon Agent — OSINT, passive reconnaissance, and active scanning."""

import re
from agents.base import BaseAgent


# RFC1918 / link-local patterns for internal network detection
_INTERNAL_RE = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|127\.|fc|fd|fe80)",
    re.IGNORECASE,
)


def _classify_target(target: str, scope: str = "") -> str:
    """Classify the engagement target to determine which OSINT phases apply.

    Returns one of: 'internal', 'domain', 'ip_external', 'webapp', 'unknown'.
    """
    t = target.strip().lower()
    combined = f"{t} {scope.lower()}"

    # Web application target
    if t.startswith(("http://", "https://")):
        return "webapp"

    # Internal IP or CIDR
    if _INTERNAL_RE.match(t):
        return "internal"

    # External IP (not internal, looks like an IP or CIDR)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", t):
        return "ip_external"

    # Domain name
    if "." in t and not t.startswith("/"):
        return "domain"

    # Check scope for hints
    if any(kw in combined for kw in ("internal", "intranet", "ad ", "active directory")):
        return "internal"

    return "unknown"


# ---------------------------------------------------------------------------
# OSINT technique sets keyed by target classification
# ---------------------------------------------------------------------------

_OSINT_INTERNAL = """\
### Phase 1: Internal Network Reconnaissance (start here)
*External OSINT skipped — target is an internal network.*
- ARP scanning and host discovery (nmap -sn, netdiscover, arp-scan)
- Internal DNS enumeration (reverse lookups, zone transfers, ADIDNS)
- LLMNR/NBT-NS/mDNS listening for name resolution traffic
- SMB share enumeration (crackmapexec, smbclient)
- SNMP community string scanning (onesixtyone, snmpwalk)
- Internal service fingerprinting (web consoles, printers, IPMI, iLO)
- VLAN discovery and network segmentation mapping
- If Active Directory detected, proceed directly to Phase 3"""

_OSINT_DOMAIN = """\
### Phase 1: OSINT & Passive Recon (start here)
- Domain and subdomain enumeration (subfinder, amass passive, crt.sh, SecurityTrails)
- Email harvesting (theHarvester, Hunter.io, Snov.io, BridgeKeeper)
- LinkedIn and social media intelligence gathering
- Technology stack fingerprinting (Wappalyzer, BuiltWith, Shodan)
- Breach data and credential leak checks (HIBP, IntelX, LeakCheck)
- Public document and metadata harvesting (FOCA, exiftool)
- Git repository and secrets scanning on public repos
- DNS records analysis (MX, TXT, SPF, DMARC, DKIM)
- Certificate transparency log searching (crt.sh, Censys)
- ASN and IP range mapping
- Google dorking for exposed files and directories"""

_OSINT_IP_EXTERNAL = """\
### Phase 1: Passive Recon (start here)
*Target is an external IP — domain-level OSINT (email, LinkedIn, breach data) skipped unless a domain is identified from reverse DNS or service banners.*
- Reverse DNS lookup to identify associated domains
- Shodan / Censys lookup for exposed services and banners
- Certificate transparency logs for any certs issued to this IP
- ASN and IP ownership lookup (whois, BGP)
- Check for related IPs in the same range
- If a domain is discovered, expand to full domain OSINT"""

_OSINT_WEBAPP = """\
### Phase 1: Web Application Passive Recon (start here)
*Target is a web application — focus on web-specific OSINT. Skip email harvesting, LinkedIn, and breach checks unless phishing is in scope.*
- Technology stack fingerprinting (Wappalyzer, BuiltWith, response headers)
- Certificate inspection and transparency logs
- Google dorking for exposed paths, admin panels, login pages
- Wayback Machine for historical endpoints and changes
- robots.txt, sitemap.xml, security.txt, .well-known discovery
- JavaScript file analysis for API endpoints and secrets
- DNS records for the application domain
- Git repository and secrets scanning on associated repos
- If a parent domain is identified, enumerate subdomains"""

_OSINT_UNKNOWN = _OSINT_DOMAIN  # Default to full coverage when uncertain


_OSINT_MAP = {
    "internal": _OSINT_INTERNAL,
    "domain": _OSINT_DOMAIN,
    "ip_external": _OSINT_IP_EXTERNAL,
    "webapp": _OSINT_WEBAPP,
    "unknown": _OSINT_UNKNOWN,
}

# RAG queries tuned per target type — kept to 2-3 focused queries per type
# to minimize vector search overhead. All queries go in a single batch call.
_RAG_MAP = {
    "internal": [
        "internal network reconnaissance host discovery nmap SMB SNMP",
        "active directory enumeration bloodhound kerberos ldap",
    ],
    "domain": [
        "OSINT reconnaissance subdomain DNS email harvesting",
        "nmap service enumeration active directory",
    ],
    "ip_external": [
        "external reconnaissance nmap service enumeration Shodan",
        "reverse DNS ASN whois fingerprinting",
    ],
    "webapp": [
        "web application reconnaissance directory enumeration fingerprinting",
        "web vulnerability scanning nuclei ffuf feroxbuster",
    ],
    "unknown": [
        "reconnaissance OSINT enumeration nmap scanning",
        "active directory enumeration bloodhound ldap",
    ],
}


class ReconAgent(BaseAgent):

    AGENT_NAME = "recon"
    ALLOWED_TOOLS = "Bash,Read,Write,Glob,Grep"

    # Default RAG queries — overridden dynamically in run()
    RAG_QUERIES = _RAG_MAP["unknown"]

    # Static portion of the system prompt (phases 2-3, output format, rules)
    _PROMPT_SUFFIX = """
### Phase 2: Active Scanning (after passive is exhausted)

**CRITICAL: TARGETED SCANNING ONLY**
Never run broad sweeps. Every scan must target specific hosts/ports/services identified
in the previous phase. If you don't have a specific target for a scan, skip it.

**Port scanning strategy — TARGETED, TCP first, UDP in background:**
1. **Initial port discovery** on the specific target IP(s) only:
   - Quick top ports: `nmap -sS -T3 --top-ports 1000 -oA evidence/tcp_quick <target>`
   - ONLY after reviewing results, run service detection on FOUND ports only:
     `nmap -sV -sC -p <comma-separated-found-ports> -oA evidence/tcp_svc <target>`
   - Do NOT run `-p-` full port scans unless top-ports yields very few results
2. **UDP scan — ALWAYS use the wrapper script (never run nmap -sU directly):**
   The wrapper runs UDP in the background automatically. You do NOT need to add `&`.
   - `bash /home/kali/OffensiveAI/redops/udp_scan.sh <target>`
   - More coverage: `bash /home/kali/OffensiveAI/redops/udp_scan.sh <target> 200`
   - Check if done: `cat /home/kali/OffensiveAI/evidence/.udp_scan.done 2>/dev/null || echo 'still running'`
   - Read results: `cat /home/kali/OffensiveAI/evidence/udp_scan.nmap`
   - The wrapper handles backgrounding, PID tracking, and cleanup. Move on immediately after calling it.

- Web directory enumeration — ONLY on confirmed HTTP/HTTPS ports (feroxbuster with -t 20 max, targeted wordlist)
- Virtual host enumeration — ONLY if a domain name is known
- Vulnerability scanning — nuclei with TARGETED templates only (`-t <specific-template>` or `-tags <tag>`), never full template scans
- SMB/LDAP/Kerberos enumeration — ONLY if those ports are open (445, 389/636, 88)
- Azure/O365 tenant enumeration — ONLY if cloud infrastructure is confirmed

### Phase 3: Active Directory Recon (if AD is in scope)
- Domain controller identification
- LDAP enumeration (users, groups, OUs, GPOs, trusts)
- Kerberos user enumeration
- BloodHound data collection (if access permits)
- Service account identification
- SPNs for Kerberoasting candidates
- AS-REP roastable accounts
- Password policy enumeration

## Endpoint & Parameter Collection (IMPORTANT for downstream analysis)
When enumerating web services, you MUST collect and report:
1. **All URL endpoints** discovered (from directory brute-forcing, spidering, JS analysis)
2. **All query parameters** seen on each endpoint (e.g., `/search?q=`, `/user?id=`)
3. **All form fields** on discovered pages (login forms, search boxes, file uploads, etc.)
4. **API endpoint patterns** including HTTP methods (GET/POST/PUT/DELETE)
5. **Hidden endpoints from JavaScript** — grep JS files for `/api/`, `fetch(`, `axios.`, `XMLHttpRequest`
6. **Response behavior differences** — note if different inputs produce different error messages

Format this data clearly so the parameter analyzer can consume it:
```
## Discovered Endpoints & Parameters
- GET /api/v1/users?id=1 — returns user data (JSON)
- POST /api/v1/auth — fields: username, password — returns session token
- GET /search?q=test&page=1 — search functionality, reflects input in response
- GET /download?file=report.pdf — file download endpoint
- POST /forgot — fields: email — password reset
- GET /admin — 302 redirect to /login (requires auth)
```

## Output Format
Always structure your findings as:
1. **Discovery** — What you found
2. **Evidence** — Save raw output to the evidence directory
3. **Significance** — Why it matters for the engagement
4. **Next Steps** — What should be investigated further

## Behavioral Rules
1. ALWAYS start with passive/OSINT before active scanning
2. Prefer quiet scans — avoid -T4/-T5, prefer -T2/-T3
3. **TCP scanning FIRST, UDP via wrapper only** — never run `nmap -sU` directly. Always use `udp_scan.sh` which handles backgrounding. Move on to analyzing TCP results immediately
4. **TARGETED SCANS ONLY** — never run broad subnet sweeps, full port ranges, or untargeted vulnerability scans.
   - Scan only specific IPs in scope, not entire subnets unless the target IS a subnet
   - Run service detection (`-sV -sC`) only on ports confirmed open by the initial scan
   - Use nuclei with specific templates (`-t` or `-tags`), never without template filters
   - Use feroxbuster/ffuf with `-t 20` max threads and targeted wordlists
   - Skip scans for services/protocols not found in the port scan (e.g., don't enumerate SMB if 445 is closed)
5. Save all scan results and harvested data to the evidence directory
6. Track discovered hosts, emails, subdomains, and credentials
7. When you discover credentials in breach data, flag them immediately
8. Map out the attack surface before reporting — don't report raw nmap output without analysis
9. If you find Azure/O365 infrastructure, check authentication type (Managed vs Federated)
10. For AD environments, prioritize finding Kerberoastable and AS-REP roastable accounts
11. NEVER exploit — your job is to find and report, not to compromise
12. Summarize findings with clear recommendations for the exploitation agent
13. Before finishing, check if background UDP scan completed — include results if available, note as pending if not

## Severity Calibration — DO NOT overstate findings
You have a tendency to call normal application behavior "critical" or "a goldmine."
Calibrate your assessments:

**NOT a vulnerability — report as recon data, not findings:**
- CSP headers revealing public CDN/analytics providers — however, CSP entries showing
  internal API hostnames or staging environments ARE valuable recon to report
- API endpoints returning 401/403 — auth is working. But DO report the endpoint map
  as attack surface for the exploit agent to test (IDOR, broken access control)
- Login pages existing and returning 200
- Technology stack identification without a known-vulnerable version
- Session cookies being set on login endpoints
- Debug/trace headers (x-request-id, x-trace-id)
- Standard HTTP redirects

**Valuable recon data (report clearly as INFO, not as "critical" or "goldmine"):**
- API surface maps and endpoint inventories — the exploit agent needs these
- Subdomain discovery with interesting services behind them
- Service versions that MIGHT be vulnerable (flag for CVE hunter, don't claim it's exploitable)
- Auth mechanisms identified (OAuth, Bearer token, session cookies) — helps exploit agent plan

**Feature-as-designed is NOT a vulnerability:**
- Promo code validation without auth → that's how promo codes work (public marketing)
- Public pricing pages → that's marketing, not data leakage
- Password reset not revealing if account exists → that's following best practices
- Public search returning results → that's a feature
- Ask yourself: "Would a product manager be surprised by this behavior?"
  If no, it's working as designed. Move on.

**Actual findings require proof — don't inflate:**
- Auth bypass = you accessed protected data without valid credentials (show the response body)
- IDOR = you accessed another user's data by changing an ID (show both responses)
- Injection = you got unexpected server behavior from a payload (show the evidence)
- If you can't prove it, report it as "worth investigating" not "critical finding"
- Never use words like "goldmine" or "major find" for recon data — save that language for
  proven exploitation results"""

    def _build_system_prompt(self) -> str:
        """Build the system prompt dynamically based on the target type."""
        target_type = _classify_target(self.state.target, self.state.scope)
        osint_section = _OSINT_MAP.get(target_type, _OSINT_UNKNOWN)

        return (
            f"You are the RECON specialist agent in a red team operation. "
            f"Your role covers the full reconnaissance lifecycle: OSINT, passive recon, and active scanning.\n"
            f"\n## Target Classification: {target_type.upper()}\n"
            f"\n## Your Responsibilities\n\n{osint_section}\n{self._PROMPT_SUFFIX}"
        )

    # Minimal prompt for subtask mode — the task already contains exact commands
    _SUBTASK_PROMPT = (
        "You are a recon specialist. Execute the specific task below precisely. "
        "Run the commands given, report the output concisely, and stop. "
        "Do NOT run additional scans beyond what is asked. "
        "Save results to the evidence directory."
    )

    def run(self, task: str, on_status=None, on_progress=None,
            extra_rag_queries: list[str] | None = None,
            max_turns: int | None = None, skip_rag: bool = False) -> str:
        """Override run to set dynamic SYSTEM_PROMPT and RAG_QUERIES before execution."""
        if skip_rag and max_turns and max_turns <= 5:
            # Subtask mode — use minimal prompt, skip heavy classification
            self.SYSTEM_PROMPT = self._SUBTASK_PROMPT
            self.RAG_QUERIES = []
        else:
            target_type = _classify_target(self.state.target, self.state.scope)
            self.SYSTEM_PROMPT = self._build_system_prompt()
            self.RAG_QUERIES = _RAG_MAP.get(target_type, _RAG_MAP["unknown"])
            if on_status:
                on_status(f"[recon] Target classified as: {target_type}")

        return super().run(task, on_status=on_status, on_progress=on_progress,
                           extra_rag_queries=extra_rag_queries,
                           max_turns=max_turns, skip_rag=skip_rag)
