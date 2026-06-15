"""PoC builder agent — turns confirmed bugs into working exploits.

Takes confirmed bugs with root cause analysis from crash_triager or
static_auditor. Uses LLM to build PoC scripts. Attempts full
weaponization — bypass ASLR, canaries, NX where possible.

PoC maturity levels:
  CRASH      — Triggers the bug, causes crash/DoS
  CONTROLLED — Demonstrates memory corruption with controlled values
  WEAPONIZED — Full exploit: code execution, auth bypass, data exfil

Also generates CVE advisory drafts.
"""

import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST
from research_engagement import ResearchEngagement


# --- PoC generation ---

def generate_poc(engagement: ResearchEngagement, bug: dict,
                 crash_input: str = "", on_status=None) -> Path | None:
    """Generate a PoC exploit script for a confirmed bug.

    Uses Opus for exploit development (complex reasoning needed).
    Returns path to PoC script, or None on failure.
    """
    bug_id = bug.get("id", "?")
    bug_type = bug.get("type", "unknown")
    cwe = bug.get("cwe", "")

    # Build context for exploit development
    context_parts = [
        f"Bug ID: {bug_id}",
        f"Type: {bug_type} ({cwe})",
        f"Location: {bug.get('location', '?')}",
        f"Root cause: {bug.get('why', bug.get('root_cause', '?'))}",
        f"Impact: {bug.get('impact', '?')}",
    ]

    if bug.get("what"):
        context_parts.append(f"Description: {bug['what']}")
    if bug.get("data_flow"):
        context_parts.append(f"Data flow: {bug['data_flow']}")
    if bug.get("weaponization_path"):
        context_parts.append(f"Weaponization hint: {bug['weaponization_path']}")
    if bug.get("stack_trace"):
        context_parts.append(f"Stack trace:\n{bug['stack_trace']}")
    if bug.get("evidence"):
        context_parts.append(f"Evidence: {bug['evidence'][:500]}")

    # If we have a crash input, include its hex dump
    crash_hex = ""
    if crash_input and os.path.exists(crash_input):
        try:
            data = open(crash_input, "rb").read()[:256]
            crash_hex = data.hex()
            context_parts.append(f"Crash input ({len(data)} bytes): {crash_hex}")
        except Exception:
            pass

    # Target info
    profile = engagement.profile
    context_parts.append(f"\nTarget: {engagement.target_name}")
    context_parts.append(f"Type: {profile.target_type} ({profile.language}, {profile.arch})")

    prompt = f"""You are an exploit developer. Write a proof-of-concept exploit for this vulnerability.

{chr(10).join(context_parts)}

Requirements:
1. Write a self-contained Python script (use pwntools if needed for binary exploits)
2. The script should demonstrate maximum impact:
   - For memory corruption: attempt to achieve code execution, not just crash
   - For web bugs: demonstrate data extraction or auth bypass, not just error
   - For injection: demonstrate command execution or data access
3. Include bypass techniques for common mitigations:
   - ASLR: use info leak if available, or brute force for 32-bit
   - Stack canary: overwrite only up to the canary if needed
   - NX: use ROP chain or ret2libc if needed
4. If full weaponization isn't achievable, demonstrate the most impactful primitive
   and document what mitigations are blocking full exploitation
5. Include comments explaining each step
6. Include a usage line: # Usage: python3 exploit.py [target]

Output ONLY the Python exploit code in a code block. No explanation outside the code."""

    if on_status:
        on_status(f"[poc_builder] Building PoC for BUG-{bug_id} ({bug_type})...")

    try:
        # Use Opus for exploit development — needs strong reasoning
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text",
             "--max-turns", "1", "--model", MODEL],
            input=prompt, capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Extract code block
            code_match = re.search(r"```(?:python)?\n([\s\S]*?)```", result.stdout)
            if code_match:
                poc_code = code_match.group(1)
            else:
                poc_code = result.stdout.strip()

            # Save PoC
            poc_filename = f"bug_{bug_id:03d}_poc.py" if isinstance(bug_id, int) else f"bug_{bug_id}_poc.py"
            poc_path = engagement.poc_dir / poc_filename
            poc_path.write_text(poc_code)
            poc_path.chmod(0o755)

            if on_status:
                on_status(f"[poc_builder] PoC written: {poc_path}")
            return poc_path
    except Exception as e:
        if on_status:
            on_status(f"[poc_builder] Failed: {e}")

    return None


def test_poc(poc_path: Path, target_binary: str = "", timeout: int = 30,
             on_status=None) -> dict:
    """Test a PoC script and assess its maturity.

    Returns {success, maturity, output, error}.
    Maturity: crash, controlled, weaponized (based on output analysis).
    """
    result_info = {
        "success": False,
        "maturity": "crash",
        "output": "",
        "error": "",
    }

    try:
        cmd = ["python3", str(poc_path)]
        if target_binary:
            cmd.append(target_binary)

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PWNLIB_NOTERM": "1"},
        )
        output = result.stdout + result.stderr
        result_info["output"] = output[:2000]
        result_info["success"] = result.returncode == 0

        # Assess maturity from output
        lower = output.lower()
        if any(kw in lower for kw in ("shell", "uid=0", "root", "code execution",
                                       "rce achieved", "command executed", "pwned")):
            result_info["maturity"] = "weaponized"
        elif any(kw in lower for kw in ("controlled", "overwrite", "rip control",
                                         "eip control", "write-what-where",
                                         "arbitrary write", "controlled value")):
            result_info["maturity"] = "controlled"
        elif any(kw in lower for kw in ("crash", "segfault", "sigsegv", "sigabrt",
                                         "denied", "error", "overflow detected")):
            result_info["maturity"] = "crash"

        if on_status:
            on_status(f"[poc_builder] Test result: {result_info['maturity']}")

    except subprocess.TimeoutExpired:
        result_info["error"] = f"Timeout ({timeout}s)"
    except Exception as e:
        result_info["error"] = str(e)[:200]

    return result_info


# --- CVE Advisory generation ---

def generate_advisory(engagement: ResearchEngagement, bug: dict,
                      poc_path: str = "", on_status=None) -> Path | None:
    """Generate a CVE advisory draft for a confirmed bug.

    Returns path to advisory markdown file.
    """
    bug_id = bug.get("id", "?")

    prompt = f"""Write a CVE advisory for this vulnerability.

Bug: {bug.get('title', bug.get('type', 'Unknown'))}
CWE: {bug.get('cwe', 'N/A')}
Location: {bug.get('location', '?')}
Root cause: {bug.get('why', bug.get('root_cause', '?'))}
Impact: {bug.get('impact', '?')}
Exploitability: {bug.get('exploitability', '?')}
Target: {engagement.target_name} ({engagement.profile.language}, {engagement.profile.arch})
PoC available: {'yes' if poc_path else 'no'}

Write the advisory in markdown format with these sections:
# [Title]
## Summary
## Affected Versions
## Description
## Impact
## Proof of Concept
## Mitigation
## Timeline
## Credit

Be concise and professional. This is for responsible disclosure."""

    if on_status:
        on_status(f"[poc_builder] Generating advisory for BUG-{bug_id}...")

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text",
             "--max-turns", "1", "--model", MODEL_FAST],
            input=prompt, capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            advisory_path = engagement.poc_dir / f"bug_{bug_id:03d}_advisory.md" if isinstance(bug_id, int) \
                else engagement.poc_dir / f"bug_{bug_id}_advisory.md"
            advisory_path.write_text(result.stdout.strip())
            if on_status:
                on_status(f"[poc_builder] Advisory: {advisory_path}")
            return advisory_path
    except Exception:
        pass
    return None


# --- Main pipeline ---

def build_pocs(engagement: ResearchEngagement, target_binary: str = "",
               on_status=None) -> dict:
    """Build PoCs for all confirmed bugs that don't have one yet.

    1. For each confirmed bug without a PoC: generate → test → rate maturity
    2. Generate CVE advisory for weaponizable/promising bugs
    3. Update engagement state

    Returns summary.
    """
    # Find bugs needing PoCs
    needs_poc = []
    existing_bug_ids = {p.get("bug_id") for p in engagement.pocs}

    for bug in engagement.confirmed_bugs:
        if bug["id"] not in existing_bug_ids:
            needs_poc.append(bug)

    # Also check high-confidence candidates that haven't been confirmed yet
    for bug in engagement.bug_candidates:
        if (bug["status"] == "candidate"
                and bug.get("exploitability") in ("weaponizable", "promising")
                and bug["id"] not in existing_bug_ids):
            needs_poc.append(bug)

    if not needs_poc:
        if on_status:
            on_status("[poc_builder] No bugs need PoCs")
        return {"built": 0}

    if on_status:
        on_status(f"[poc_builder] Building PoCs for {len(needs_poc)} bugs...")

    summary = {"built": 0, "tested": 0, "by_maturity": {}, "advisories": 0}

    for bug in needs_poc:
        # Find crash input if this bug came from fuzzing
        crash_input = ""
        if bug.get("evidence", "").startswith("crash:"):
            crash_id = bug["evidence"].split(":")[1]
            for c in engagement.crash_corpus:
                if str(c.get("id")) == crash_id:
                    crash_input = c.get("minimized_path", c.get("input_file", ""))
                    break

        # Generate PoC
        poc_path = generate_poc(engagement, bug, crash_input, on_status)
        if not poc_path:
            continue

        # Test PoC
        test_result = test_poc(poc_path, target_binary, on_status=on_status)
        maturity = test_result.get("maturity", "crash")
        summary["tested"] += 1

        # Register in engagement
        engagement.add_poc(
            bug["id"], str(poc_path), maturity,
            tested=True,
            test_output=test_result.get("output", "")[:500],
            mitigations_bypassed=[],
        )
        summary["built"] += 1
        summary["by_maturity"][maturity] = summary["by_maturity"].get(maturity, 0) + 1

        # Generate advisory for weaponizable/promising
        if maturity in ("weaponized", "controlled") or bug.get("exploitability") in ("weaponizable", "promising"):
            adv = generate_advisory(engagement, bug, str(poc_path), on_status)
            if adv:
                summary["advisories"] += 1

    engagement.current_phase = "poc"
    if "poc" not in engagement.completed_phases:
        engagement.completed_phases.append("poc")
    engagement.save()

    if on_status:
        on_status(f"[poc_builder] Done: {summary['built']} PoCs, "
                  f"maturity: {json.dumps(summary['by_maturity'])}, "
                  f"{summary['advisories']} advisories")
    return summary
