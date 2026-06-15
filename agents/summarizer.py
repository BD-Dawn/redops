"""Output summarizer — compresses agent outputs for inter-phase handoff.

Uses the fast model (Haiku) to distill raw agent output into structured
findings. Raw output is cached to disk; summaries are passed downstream.
Also extracts structured findings into the findings DB.
"""

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_FAST, EVIDENCE_DIR
from findings_db import FindingsDB, Finding

# Cache directory for raw outputs
_CACHE_DIR = EVIDENCE_DIR / ".output_cache"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Summary prompts per agent type
_SUMMARY_PROMPTS = {
    "recon": """Summarize this reconnaissance output into a structured brief for downstream agents.
Extract ONLY actionable findings:

1. **Open Ports & Services** — list each as: port/proto service version (host)
2. **Credentials Found** — username:password/hash pairs with source
3. **Hostnames & IPs** — discovered hosts with any DNS/NetBIOS names
4. **Web Applications** — URLs, technologies, interesting endpoints
5. **Attack Surface** — specific vulnerabilities, misconfigs, or weak points identified
6. **AD/Domain Info** — domain name, DCs, user accounts, SPNs, policies

Drop all raw tool output, scan noise, and verbose explanations.
Keep it under 1500 words. Be precise — downstream agents act on this directly.""",

    "exploit": """Summarize this exploitation output into a structured brief.
Extract ONLY:

1. **Access Gained** — each compromised host with access level (user/admin/SYSTEM)
2. **Credentials Obtained** — username:password/hash with type and source
3. **Methods Used** — vulnerability/technique that worked, with key details
4. **Failed Attempts** — what was tried and why it failed (prevents retries)
5. **Active Sessions** — C2 sessions/beacons with IDs if mentioned
6. **Persistence** — any persistence mechanisms established

Drop tool output noise. Under 1000 words.""",

    "postex": """Summarize this post-exploitation output into a structured brief.
Extract ONLY:

1. **New Access** — hosts compromised, privilege levels achieved
2. **Credentials Harvested** — all creds with type and source
3. **Lateral Movement** — paths taken, methods used
4. **Domain Status** — domain admin achieved? current domain position
5. **Key Findings** — sensitive data, misconfigurations, GPO issues
6. **Failed Paths** — what didn't work

Drop raw command output. Under 1000 words.""",

    "cvehunter": """Summarize CVE hunting results into a structured brief.
Extract ONLY:

1. **Confirmed Vulnerabilities** — CVE-ID, service@version, host, exploitability
2. **PoCs Available** — CVE-ID with PoC path/status (downloaded/adapted/ready)
3. **Recommended Exploitation Order** — prioritized list by impact and reliability
4. **Not Vulnerable** — services checked and confirmed not vulnerable (prevents retries)

Drop raw searchsploit/nmap output. Under 800 words.""",

    "codereview": """Summarize code review findings into a structured brief.
Extract ONLY:

1. **Critical Findings** — exploitable vulns with file:line, CWE, severity
2. **Credentials/Secrets** — exact values found with file locations
3. **Exploitation Steps** — for each finding, exact attack commands/payloads
4. **Lower Priority** — info disclosure, bad practices (brief list)

Drop code snippets unless they contain credentials. Under 800 words.""",
}

# Fallback for unknown agent types
_DEFAULT_PROMPT = """Summarize this agent output into a concise structured brief.
Extract only actionable findings: hosts, ports, credentials, vulnerabilities, access gained.
Drop raw tool output. Under 1000 words."""


def cache_output(agent_name: str, task: str, raw_output: str) -> Path:
    """Cache raw agent output to disk and return the cache path."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cache_file = _CACHE_DIR / f"{agent_name}_{timestamp}.md"
    cache_file.write_text(
        f"# {agent_name.upper()} Output — {timestamp}\n\n"
        f"## Task\n{task[:500]}\n\n"
        f"## Raw Output\n{raw_output}\n"
    )
    return cache_file


def summarize_output(agent_name: str, raw_output: str, on_status=None) -> str:
    """Summarize agent output using the fast model.

    Returns the summary text. If summarization fails, returns a truncated
    version of the raw output as fallback.
    """
    if not raw_output or len(raw_output) < 200:
        return raw_output  # Too short to bother summarizing

    summary_prompt = _SUMMARY_PROMPTS.get(agent_name, _DEFAULT_PROMPT)

    # Truncate input to avoid token limits on the fast model
    max_input = 12000
    truncated = raw_output[:max_input]
    if len(raw_output) > max_input:
        truncated += "\n\n... (output truncated for summarization)"

    prompt = f"{summary_prompt}\n\n---\n\n{truncated}"

    if on_status:
        on_status(f"[orchestrator] Summarizing {agent_name} output...")

    try:
        result = subprocess.run(
            [
                "claude", "-p",
                "--output-format", "text",
                "--max-turns", "1",
                "--model", MODEL_FAST,
            ],
            input=prompt,
            capture_output=True, text=True, timeout=90,
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()

    except Exception:
        pass

    # Fallback: return first 3000 chars
    if len(raw_output) > 3000:
        return raw_output[:3000] + "\n\n... (truncated — full output cached in evidence/.output_cache/)"
    return raw_output


def extract_findings_from_summary(
    agent_name: str, summary_text: str, host: str, db: FindingsDB | None = None
) -> list[Finding]:
    """Extract structured findings from a summarized agent output.

    Uses regex patterns to parse the structured sections that the summarizer
    produces (Open Ports, Credentials, Hostnames, etc.). Writes to DB if provided.

    This is intentionally regex-based (not LLM-based) for speed and determinism.
    False negatives are acceptable — the raw output is always preserved.
    """
    findings = []
    _db = db  # Don't auto-create — caller controls DB writes

    # --- Extract open ports / services ---
    # Pattern: port/proto service version (host) or "80/tcp http Apache 2.4.29"
    port_pattern = re.compile(
        r"(\d+)[/\s](?:tcp|udp)?\s+[\-–]?\s*(\S+)\s*([\w\d\.\-]*)",
        re.IGNORECASE,
    )
    for match in port_pattern.finditer(summary_text):
        port_num = int(match.group(1))
        service = match.group(2).strip(" -–")
        version = match.group(3).strip() if match.group(3) else ""
        if service.lower() in ("open", "filtered", "closed"):
            continue
        findings.append(Finding(
            host=host,
            port=port_num,
            service=service,
            finding_type="service",
            severity="info",
            title=f"{service} {version}".strip(),
            description=f"Port {port_num}: {service} {version}".strip(),
            agent=agent_name,
        ))

    # --- Extract credentials ---
    # Patterns: "user:pass", "username : password", "admin/P@ssw0rd"
    cred_patterns = [
        re.compile(r"(\S+)\s*:\s*(\S+)\s+\[?(password|hash|ntlm|krb|kerberos)\]?", re.IGNORECASE),
        re.compile(r"(?:username|user|login)\s*[:=]\s*(\S+).*?(?:password|pass|secret)\s*[:=]\s*(\S+)", re.IGNORECASE),
    ]
    for pattern in cred_patterns:
        for match in pattern.finditer(summary_text):
            findings.append(Finding(
                host=host,
                finding_type="credential",
                severity="high",
                title=f"Credential: {match.group(1)}",
                description=match.group(0)[:200],
                agent=agent_name,
                exploitable=True,
            ))

    # --- Extract CVEs ---
    cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
    seen_cves = set()
    for match in cve_pattern.finditer(summary_text):
        cve_id = match.group(1).upper()
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        # Try to get surrounding context for description
        start = max(0, match.start() - 100)
        end = min(len(summary_text), match.end() + 100)
        context = summary_text[start:end].strip()
        findings.append(Finding(
            host=host,
            finding_type="cve",
            severity="high",
            title=cve_id,
            description=context[:300],
            cve_id=cve_id,
            agent=agent_name,
            exploitable=True,
        ))

    # --- Extract access gained ---
    access_patterns = [
        re.compile(r"(?:gained|obtained|achieved)\s+(\w+)\s+(?:access|shell|session)", re.IGNORECASE),
        re.compile(r"(?:compromised|pwned)\s+(\S+)", re.IGNORECASE),
        re.compile(r"(?:SYSTEM|root|admin(?:istrator)?)\s+(?:access|shell|session)", re.IGNORECASE),
    ]
    for pattern in access_patterns:
        for match in pattern.finditer(summary_text):
            findings.append(Finding(
                host=host,
                finding_type="access_gained",
                severity="critical",
                title=f"Access gained: {match.group(0)[:80]}",
                description=match.group(0)[:200],
                agent=agent_name,
                exploitable=True,
                exploited=True,
            ))

    # --- Extract discovered hosts ---
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    seen_hosts = {host}  # Don't re-add the primary target
    for match in ip_pattern.finditer(summary_text):
        ip = match.group(1)
        if ip in seen_hosts or ip.startswith(("127.", "0.0.0.0", "255.")):
            continue
        seen_hosts.add(ip)
        findings.append(Finding(
            host=ip,
            finding_type="host_discovery",
            severity="info",
            title=f"Discovered host: {ip}",
            agent=agent_name,
        ))

    # Write to DB only if explicitly provided
    if findings and _db is not None:
        _db.add_many(findings)

    return findings
