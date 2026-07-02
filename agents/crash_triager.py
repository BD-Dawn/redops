"""Crash triager agent — analyzes fuzzer crashes for exploitability.

Pipeline per crash:
  1. Deduplicate by stack trace hash
  2. Run under ASAN for detailed error classification
  3. Run GDB exploitable plugin for exploitability rating
  4. Minimize with afl-tmin
  5. LLM root cause analysis — maps to exploitability scale
  6. Update engagement state

Exploitability scale:
  WEAPONIZABLE   — Full control (controlled write, RIP overwrite)
  PROMISING      — Partial control (heap corruption, type confusion)
  INTERESTING    — Crash confirmed but control unclear
  LOW_VALUE      — NULL deref, stack exhaustion, assertion (DoS only)
  FALSE_POSITIVE — Not a real bug
"""

import hashlib
import json
import os
import re
import subprocess

import claude_client
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_FAST
from research_engagement import ResearchEngagement


# --- ASAN error type → exploitability mapping ---

_ASAN_EXPLOITABILITY = {
    "heap-buffer-overflow": "promising",
    "heap-use-after-free": "promising",
    "stack-buffer-overflow": "promising",
    "global-buffer-overflow": "promising",
    "heap-double-free": "promising",
    "stack-use-after-return": "promising",
    "stack-use-after-scope": "interesting",
    "use-after-poison": "interesting",
    "container-overflow": "interesting",
    "alloc-dealloc-mismatch": "low_value",
    "null-dereference": "low_value",
    "SEGV on unknown address": "interesting",
    "signal 11": "interesting",
    "signal 6": "low_value",  # SIGABRT — usually assertion
    "out-of-memory": "low_value",
    "stack-overflow": "low_value",
    "undefined-behavior": "interesting",
}

# Write vs read — writes are more exploitable
_WRITE_INDICATORS = ["WRITE", "write of size", "store to", "memcpy-param-overlap"]
_READ_INDICATORS = ["READ", "read of size", "load from"]


def _get_asan_binary(target_binary: str) -> str | None:
    """Find or build an ASAN-instrumented version of the target."""
    # Check if the binary itself was built with ASAN
    try:
        result = subprocess.run(
            ["nm", "-D", target_binary], capture_output=True, text=True, timeout=10,
        )
        if "__asan" in result.stdout:
            return target_binary
    except Exception:
        pass

    # Look for an _asan variant next to the binary
    base = Path(target_binary)
    asan_path = base.parent / f"{base.stem}_asan{base.suffix}"
    if asan_path.exists():
        return str(asan_path)

    return target_binary  # use as-is, hope for the best


def run_crash_asan(binary: str, crash_input: str, timeout: int = 10) -> dict:
    """Run a crash input under ASAN and parse the output.

    Returns {crash_type, access_type, address, stack_trace, asan_output}.
    """
    result_info = {
        "crash_type": "unknown",
        "access_type": "",
        "address": "",
        "stack_trace": "",
        "asan_output": "",
        "frames": [],
    }

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"

    try:
        result = subprocess.run(
            [binary, crash_input],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        stderr = result.stderr
        result_info["asan_output"] = stderr[:3000]

        # Parse ASAN error type
        # e.g., "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
        error_match = re.search(
            r"AddressSanitizer:\s+([\w-]+)\s+on\s+address\s+(0x[0-9a-f]+)", stderr
        )
        if error_match:
            result_info["crash_type"] = error_match.group(1)
            result_info["address"] = error_match.group(2)

        # Fallback: look for signal
        if result_info["crash_type"] == "unknown":
            sig_match = re.search(r"signal (\d+)", stderr)
            if sig_match:
                result_info["crash_type"] = f"signal {sig_match.group(1)}"

        # Write or read?
        for indicator in _WRITE_INDICATORS:
            if indicator in stderr:
                result_info["access_type"] = "write"
                break
        if not result_info["access_type"]:
            for indicator in _READ_INDICATORS:
                if indicator in stderr:
                    result_info["access_type"] = "read"
                    break

        # Extract stack frames
        frames = []
        for m in re.finditer(r"#(\d+)\s+(0x[0-9a-f]+)\s+in\s+(\S+)\s+(\S+)?", stderr):
            frames.append({
                "frame": int(m.group(1)),
                "address": m.group(2),
                "function": m.group(3),
                "location": (m.group(4) or "").strip(),
            })
        result_info["frames"] = frames[:20]
        result_info["stack_trace"] = "\n".join(
            f"#{f['frame']} {f['function']} ({f['location']})" for f in frames[:10]
        )

    except subprocess.TimeoutExpired:
        result_info["crash_type"] = "timeout"
    except Exception as e:
        result_info["crash_type"] = f"error: {str(e)[:100]}"

    return result_info


def run_gdb_exploitable(binary: str, crash_input: str, timeout: int = 15) -> dict:
    """Run crash under GDB with exploitable plugin.

    Returns {classification, description, instruction, access_type}.
    GDB exploitable classifications: EXPLOITABLE, PROBABLY_EXPLOITABLE,
    PROBABLY_NOT_EXPLOITABLE, NOT_EXPLOITABLE, UNKNOWN.
    """
    result_info = {
        "classification": "UNKNOWN",
        "description": "",
    }

    # Check if exploitable plugin is available
    exploitable_paths = [
        "/usr/share/gdb-exploitable/exploitable.py",
        "/usr/lib/python3/dist-packages/exploitable/exploitable.py",
        os.path.expanduser("~/.gdb/exploitable/exploitable.py"),
    ]
    exploitable_path = None
    for p in exploitable_paths:
        if os.path.exists(p):
            exploitable_path = p
            break

    if not exploitable_path:
        return result_info

    gdb_commands = f"""
set pagination off
set logging enabled off
file {binary}
run {crash_input}
source {exploitable_path}
exploitable
quit
"""

    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", "/dev/stdin"],
            input=gdb_commands, capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout + result.stderr

        # Parse exploitable output
        class_match = re.search(
            r"(EXPLOITABLE|PROBABLY_EXPLOITABLE|PROBABLY_NOT_EXPLOITABLE|NOT_EXPLOITABLE)",
            output,
        )
        if class_match:
            result_info["classification"] = class_match.group(1)

        desc_match = re.search(r"Description:\s*(.+)", output)
        if desc_match:
            result_info["description"] = desc_match.group(1).strip()

    except Exception:
        pass

    return result_info


def minimize_crash(binary: str, crash_input: str, output_path: str,
                   timeout: int = 60) -> bool:
    """Minimize crash input with afl-tmin. Returns True on success."""
    try:
        result = subprocess.run(
            ["afl-tmin", "-i", crash_input, "-o", output_path, "--", binary, "@@"],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "AFL_SKIP_CPUFREQ": "1"},
        )
        return result.returncode == 0 and os.path.exists(output_path)
    except Exception:
        return False


def compute_stack_hash(asan_output: str) -> str:
    """Compute dedup hash from ASAN stack trace."""
    # Extract function names from stack frames for a stable hash
    frames = re.findall(r"in\s+(\S+)", asan_output)
    key = "|".join(frames[:5])  # top 5 frames
    if not key:
        key = asan_output[:500]  # fallback
    return hashlib.md5(key.encode()).hexdigest()[:16]


def llm_root_cause(crash_info: dict, asan_result: dict,
                   source_context: str = "", on_status=None) -> dict:
    """Use LLM to analyze crash root cause and assess exploitability.

    Returns {root_cause, exploitability, what, why, impact, weaponization_path}.
    """
    prompt = f"""Analyze this program crash for vulnerability research.

## Crash Info
Type: {asan_result.get('crash_type', 'unknown')}
Access: {asan_result.get('access_type', 'unknown')} at {asan_result.get('address', '?')}
Stack trace:
{asan_result.get('stack_trace', 'unavailable')}

## ASAN Output (excerpt)
{asan_result.get('asan_output', '')[:2000]}

{f'## Source Context{chr(10)}{source_context[:2000]}' if source_context else ''}

Respond in JSON:
{{
  "root_cause": "one sentence explaining what's broken",
  "exploitability": "weaponizable|promising|interesting|low_value|false_positive",
  "what": "plain language: what is the bug",
  "why": "plain language: why does it happen",
  "impact": "what an attacker can achieve",
  "weaponization_path": "how to turn this into a working exploit (or why it's hard)",
  "controlled_bytes": "which input bytes influence the crash (if determinable)"
}}

Exploitability guide:
- weaponizable: attacker controls WRITE address/value, or controls instruction pointer
- promising: heap corruption/type confusion with partial control, needs more analysis
- interesting: real crash but control path is unclear
- low_value: NULL deref, assertion, stack exhaustion — usually DoS only
- false_positive: not a real bug"""

    try:
        result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            json_match = re.search(r"\{[\s\S]*\}", result.stdout)
            if json_match:
                return json.loads(json_match.group())
    except Exception:
        pass

    # Fallback: use ASAN type mapping
    crash_type = asan_result.get("crash_type", "unknown")
    base_expl = _ASAN_EXPLOITABILITY.get(crash_type, "interesting")

    # Upgrade if it's a write
    if asan_result.get("access_type") == "write" and base_expl == "promising":
        base_expl = "weaponizable"

    return {
        "root_cause": f"{crash_type} ({asan_result.get('access_type', '?')})",
        "exploitability": base_expl,
        "what": f"{crash_type} detected by ASAN",
        "why": "See ASAN output for details",
        "impact": "Crash / potential code execution" if base_expl in ("weaponizable", "promising") else "Denial of service",
        "weaponization_path": "",
        "controlled_bytes": "",
    }


# --- Main triage pipeline ---

def triage_crashes(engagement: ResearchEngagement, target_binary: str = "",
                   max_crashes: int = 20, on_status=None) -> dict:
    """Run full triage pipeline on all untriaged crashes.

    1. Find ASAN binary
    2. For each untriaged crash: ASAN → GDB exploitable → minimize → LLM root cause
    3. Update engagement state
    4. Runs crashes in parallel (3 threads)

    Returns summary dict.
    """
    untriaged = [c for c in engagement.crash_corpus if not c.get("triaged")]
    if not untriaged:
        if on_status:
            on_status("[crash_triager] No untriaged crashes")
        return {"triaged": 0, "results": {}}

    # Cap to prevent excessive analysis
    untriaged = untriaged[:max_crashes]

    if on_status:
        on_status(f"[crash_triager] Triaging {len(untriaged)} crashes...")

    # Find the target binary
    if not target_binary:
        # Look for harness in engagement
        harness = engagement.fuzz_dir / "harness" / "harness_fuzz"
        if harness.exists():
            target_binary = str(harness)
        else:
            harness_sh = engagement.fuzz_dir / "harness" / "harness.sh"
            if harness_sh.exists():
                target_binary = str(harness_sh)

    if not target_binary:
        if on_status:
            on_status("[crash_triager] No target binary found — cannot triage")
        return {"triaged": 0, "error": "no target binary"}

    asan_binary = _get_asan_binary(target_binary)
    summary = {"triaged": 0, "by_exploitability": {}, "results": []}

    def _triage_one(crash: dict) -> dict:
        """Triage a single crash. Returns enriched crash dict."""
        crash_file = crash.get("input_file", "")
        if not crash_file or not os.path.exists(crash_file):
            return crash

        # Step 1: ASAN
        asan = run_crash_asan(asan_binary, crash_file)
        crash["crash_type"] = asan.get("crash_type", "unknown")
        crash["access_type"] = asan.get("access_type", "")
        crash["stack_trace"] = asan.get("stack_trace", "")

        # Compute stable stack hash for dedup
        crash["stack_hash"] = compute_stack_hash(asan.get("asan_output", ""))

        # Step 2: GDB exploitable
        gdb = run_gdb_exploitable(asan_binary, crash_file)
        crash["gdb_classification"] = gdb.get("classification", "UNKNOWN")

        # Step 3: Minimize
        minimized_path = str(Path(crash_file).parent / f"min_{Path(crash_file).name}")
        if minimize_crash(asan_binary, crash_file, minimized_path):
            crash["minimized"] = True
            crash["minimized_path"] = minimized_path

        # Step 4: LLM root cause
        llm = llm_root_cause(crash, asan)
        crash["root_cause"] = llm.get("root_cause", "")
        crash["exploitability"] = llm.get("exploitability", "interesting")
        crash["what"] = llm.get("what", "")
        crash["why"] = llm.get("why", "")
        crash["impact"] = llm.get("impact", "")
        crash["weaponization_path"] = llm.get("weaponization_path", "")
        crash["triaged"] = True

        return crash

    # Parallel triage (3 threads — ASAN and GDB are CPU-bound)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_triage_one, c): c for c in untriaged}
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
                summary["triaged"] += 1
                expl = result.get("exploitability", "unknown")
                summary["by_exploitability"][expl] = summary["by_exploitability"].get(expl, 0) + 1
                summary["results"].append({
                    "id": result.get("id"),
                    "crash_type": result.get("crash_type"),
                    "exploitability": expl,
                    "root_cause": result.get("root_cause", "")[:100],
                })
                if on_status:
                    on_status(f"[crash_triager] {i+1}/{len(untriaged)}: "
                              f"{result.get('crash_type', '?')} → {expl}")
            except Exception:
                pass

    # Promote weaponizable/promising crashes to confirmed bugs
    for crash in engagement.crash_corpus:
        if crash.get("exploitability") in ("weaponizable", "promising") and crash.get("triaged"):
            # Check if already a bug candidate
            existing = [b for b in engagement.bug_candidates
                        if b.get("evidence", "").startswith(f"crash:{crash.get('id', '')}")]
            if not existing:
                engagement.add_bug_candidate(
                    type=crash.get("crash_type", "unknown"),
                    cwe=_crash_to_cwe(crash.get("crash_type", "")),
                    title=f"{crash.get('crash_type', 'Crash')}: {crash.get('root_cause', '')[:80]}",
                    location=crash.get("stack_trace", "").split("\n")[0] if crash.get("stack_trace") else "unknown",
                    what=crash.get("what", ""),
                    why=crash.get("why", ""),
                    impact=crash.get("impact", ""),
                    exploitability=crash.get("exploitability", ""),
                    evidence=f"crash:{crash.get('id', '')}",
                    confidence="high" if crash.get("exploitability") == "weaponizable" else "medium",
                )

    engagement.current_phase = "triage"
    if "triage" not in engagement.completed_phases:
        engagement.completed_phases.append("triage")
    engagement.save()

    if on_status:
        on_status(f"[crash_triager] Done: {summary['triaged']} triaged — "
                  f"{json.dumps(summary['by_exploitability'])}")
    return summary


def _crash_to_cwe(crash_type: str) -> str:
    return {
        "heap-buffer-overflow": "CWE-787",
        "stack-buffer-overflow": "CWE-121",
        "global-buffer-overflow": "CWE-787",
        "heap-use-after-free": "CWE-416",
        "heap-double-free": "CWE-415",
        "stack-use-after-return": "CWE-562",
        "null-dereference": "CWE-476",
        "undefined-behavior": "CWE-758",
    }.get(crash_type, "CWE-119")
