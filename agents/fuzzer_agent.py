"""Fuzzer agent — harness building, seed management, and fuzzer orchestration.

Builds fuzzing harnesses from entry points identified by static_auditor or
re_agent. Launches AFL++ in background, monitors for crashes. Stop condition:
5 unique crashes (prototype threshold).

Architecture:
  1. LLM builds a harness targeting identified entry points
  2. Harness is compiled with ASAN instrumentation
  3. Seeds are gathered or generated
  4. AFL++ launched in background
  5. Agent periodically checks crash count
  6. When threshold hit, crashes are collected for triage
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST
from research_engagement import ResearchEngagement


# --- Configuration ---

CRASH_THRESHOLD = 5         # stop after this many unique crashes
FUZZ_CHECK_INTERVAL = 30    # seconds between crash checks
FUZZ_MAX_DURATION = 3600    # max fuzzing time (1 hour default)
AFL_FUZZ = "afl-fuzz"
AFL_CC = "afl-clang-fast"
AFL_CXX = "afl-clang-fast++"
AFL_TMIN = "afl-tmin"


def _has_tool(name: str) -> bool:
    try:
        return subprocess.run(["which", name], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


_HAS_AFL = _has_tool("afl-fuzz")


# --- Harness generation ---

def generate_harness(engagement: ResearchEngagement, entry_points: list[str] = None,
                     sinks: list[dict] = None, on_status=None) -> Path | None:
    """Use LLM to generate a fuzzing harness for the target.

    Takes entry points and dangerous sinks, generates a C harness that
    reads from a file (AFL @@ mode) and calls the target function.

    Returns path to generated harness, or None on failure.
    """
    profile = engagement.profile
    language = profile.language
    target_path = engagement.target_path

    if language not in ("c", "cpp"):
        if on_status:
            on_status(f"[fuzzer] Harness generation for {language} — using generic stdin approach")
        return _generate_generic_harness(engagement, on_status)

    # Gather context for the LLM
    context_parts = []

    # Entry points
    points = entry_points or profile.entry_points
    if points:
        context_parts.append(f"Entry points to target: {', '.join(points[:10])}")

    # Sinks (from static audit)
    if sinks:
        context_parts.append("Dangerous sinks found:")
        for s in sinks[:10]:
            context_parts.append(f"  - {s.get('file', '?')}:{s.get('line', '?')} "
                                f"[{s.get('sink_type', '?')}] {s.get('data_flow', '')}")

    # Read header files or key source files to understand API
    headers = []
    p = Path(target_path)
    if p.is_dir():
        for h in sorted(p.glob("**/*.h"))[:5]:
            try:
                content = h.read_text(errors="ignore")[:3000]
                headers.append(f"// {h.name}\n{content}")
            except Exception:
                pass

    # Build system detection for compile instructions
    build_info = ""
    if profile.build_system == "cmake":
        build_info = "Build: cmake (compile harness separately, link against target library)"
    elif profile.build_system == "make":
        build_info = "Build: make (add harness to Makefile or compile with target objects)"

    prompt = f"""Generate an AFL++ fuzzing harness for this C/C++ target.

Target: {engagement.target_name}
Language: {language}
{build_info}

{chr(10).join(context_parts)}

Header files:
{chr(10).join(headers[:3]) if headers else '(no headers available)'}

Requirements:
1. Read input from file (argv[1]) for AFL @@ mode
2. Call the target's parsing/processing function with the fuzzed input
3. Include size limits to prevent OOM (max 1MB input)
4. Handle errors gracefully (don't crash on setup failures)
5. Include appropriate #include directives
6. Add ASAN-compatible (no custom signal handlers)

Respond with ONLY the harness code in a C code block. No explanation."""

    if on_status:
        on_status("[fuzzer] Generating fuzzing harness with LLM...")

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text",
             "--max-turns", "1", "--model", MODEL],
            input=prompt, capture_output=True, text=True, timeout=90,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Extract C code block
            code_match = re.search(r"```(?:c|cpp)?\n([\s\S]*?)```", result.stdout)
            if code_match:
                harness_code = code_match.group(1)
            else:
                harness_code = result.stdout.strip()

            harness_path = engagement.fuzz_dir / "harness" / "harness.c"
            harness_path.write_text(harness_code)
            if on_status:
                on_status(f"[fuzzer] Harness written to {harness_path}")
            return harness_path
    except Exception:
        pass

    return None


def _generate_generic_harness(engagement: ResearchEngagement,
                              on_status=None) -> Path | None:
    """Generate a generic stdin-based harness for non-C targets.

    For Python/PHP/Node: creates a wrapper that pipes stdin to the target.
    """
    profile = engagement.profile
    lang = profile.language
    target_path = engagement.target_path

    if lang == "python":
        harness = f"""#!/bin/bash
# Generic Python fuzzing harness
# Pipes file input to the target script
cat "$1" | timeout 5 python3 {target_path} 2>/dev/null
exit 0
"""
    elif lang == "php":
        harness = f"""#!/bin/bash
cat "$1" | timeout 5 php {target_path} 2>/dev/null
exit 0
"""
    else:
        harness = f"""#!/bin/bash
# Generic harness — pipes file to target stdin
cat "$1" | timeout 5 {target_path} 2>/dev/null
exit 0
"""

    harness_path = engagement.fuzz_dir / "harness" / "harness.sh"
    harness_path.write_text(harness)
    harness_path.chmod(0o755)
    if on_status:
        on_status(f"[fuzzer] Generic harness written to {harness_path}")
    return harness_path


# --- Compilation ---

def compile_harness(harness_path: Path, engagement: ResearchEngagement,
                    extra_flags: list[str] = None, on_status=None) -> Path | None:
    """Compile a C harness with AFL instrumentation and ASAN.

    Returns path to compiled binary, or None on failure.
    """
    if harness_path.suffix == ".sh":
        return harness_path  # shell harness, no compilation needed

    output = engagement.fuzz_dir / "harness" / "harness_fuzz"

    compiler = AFL_CXX if engagement.profile.language == "cpp" else AFL_CC
    if not _has_tool(compiler):
        # Fallback to regular compiler with ASAN
        compiler = "g++" if engagement.profile.language == "cpp" else "gcc"

    cmd = [
        compiler,
        "-fsanitize=address,undefined",
        "-g", "-O1",
        str(harness_path),
        "-o", str(output),
    ]
    if extra_flags:
        cmd.extend(extra_flags)

    if on_status:
        on_status(f"[fuzzer] Compiling harness: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            if on_status:
                on_status(f"[fuzzer] Harness compiled: {output}")
            return output
        else:
            if on_status:
                on_status(f"[fuzzer] Compilation failed: {result.stderr[:200]}")
            return None
    except Exception as e:
        if on_status:
            on_status(f"[fuzzer] Compilation error: {e}")
        return None


# --- Seed management ---

def gather_seeds(engagement: ResearchEngagement, on_status=None) -> Path:
    """Gather or generate seed inputs for fuzzing.

    Looks for sample files in the target directory, generates minimal
    seeds if none found.

    Returns path to seeds directory.
    """
    seeds_dir = engagement.fuzz_dir / "seeds"
    seeds_dir.mkdir(exist_ok=True)

    # Check if seeds already exist
    existing = list(seeds_dir.glob("*"))
    if existing:
        if on_status:
            on_status(f"[fuzzer] Using {len(existing)} existing seeds")
        return seeds_dir

    # Look for sample/test files in target directory
    target = Path(engagement.target_path)
    if target.is_dir():
        test_dirs = ["test", "tests", "testdata", "samples", "examples",
                     "fixtures", "test_data", "testcases"]
        for td in test_dirs:
            test_path = target / td
            if test_path.exists():
                files = list(test_path.rglob("*"))[:20]
                for f in files:
                    if f.is_file() and f.stat().st_size < 100_000:
                        try:
                            shutil.copy2(f, seeds_dir / f.name)
                        except Exception:
                            pass

    # If still no seeds, generate minimal ones
    existing = list(seeds_dir.glob("*"))
    if not existing:
        if on_status:
            on_status("[fuzzer] No sample files found — generating minimal seeds")
        # Create basic seed inputs
        (seeds_dir / "empty").write_bytes(b"")
        (seeds_dir / "null").write_bytes(b"\x00")
        (seeds_dir / "small").write_bytes(b"AAAA")
        (seeds_dir / "medium").write_bytes(b"A" * 256)
        (seeds_dir / "newlines").write_bytes(b"\n\n\n\n")
        if engagement.profile.language in ("c", "cpp"):
            (seeds_dir / "format").write_bytes(b"%s%s%s%s%s")
            (seeds_dir / "longstr").write_bytes(b"A" * 4096)

    final_count = len(list(seeds_dir.glob("*")))
    if on_status:
        on_status(f"[fuzzer] Seeds ready: {final_count} files in {seeds_dir}")
    return seeds_dir


# --- AFL++ launch and monitoring ---

def launch_afl(harness_path: Path, engagement: ResearchEngagement,
               on_status=None) -> int | None:
    """Launch AFL++ fuzzer in background.

    Returns PID of the AFL process, or None on failure.
    """
    if not _HAS_AFL:
        if on_status:
            on_status("[fuzzer] AFL++ not installed — cannot fuzz")
        return None

    seeds_dir = engagement.fuzz_dir / "seeds"
    output_dir = engagement.fuzz_dir / "findings_afl"

    # Clean previous run if exists
    if output_dir.exists():
        shutil.rmtree(output_dir)

    cmd = [
        AFL_FUZZ,
        "-i", str(seeds_dir),
        "-o", str(output_dir),
        "-m", "none",  # no memory limit (ASAN needs a lot)
        "-t", "5000",  # 5 second timeout per test case
    ]

    if harness_path.suffix == ".sh":
        cmd.extend(["--", "bash", str(harness_path), "@@"])
    else:
        cmd.extend(["--", str(harness_path), "@@"])

    if on_status:
        on_status(f"[fuzzer] Launching: {' '.join(cmd)}")

    try:
        # Set AFL env vars
        env = os.environ.copy()
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_NO_UI"] = "1"

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(engagement.fuzz_dir),
        )

        if on_status:
            on_status(f"[fuzzer] AFL++ launched (PID {proc.pid})")

        return proc.pid
    except Exception as e:
        if on_status:
            on_status(f"[fuzzer] Failed to launch AFL++: {e}")
        return None


def check_crashes(engagement: ResearchEngagement) -> list[dict]:
    """Check for new crashes from the AFL output directory.

    Returns list of new crash info dicts.
    """
    crashes_dir = engagement.fuzz_dir / "findings_afl" / "default" / "crashes"
    if not crashes_dir.exists():
        # Try alternative AFL output structure
        crashes_dir = engagement.fuzz_dir / "findings_afl" / "crashes"
    if not crashes_dir.exists():
        return []

    new_crashes = []
    known_hashes = {c.get("stack_hash", "") for c in engagement.crash_corpus}

    for crash_file in sorted(crashes_dir.glob("id:*")):
        # Hash the crash input for dedup
        crash_hash = hashlib.md5(crash_file.read_bytes()).hexdigest()
        if crash_hash in known_hashes:
            continue

        # Copy to engagement crashes directory
        dest = engagement.fuzz_dir / "crashes" / crash_file.name
        shutil.copy2(crash_file, dest)

        new_crashes.append({
            "input_file": str(dest),
            "stack_hash": crash_hash,
            "crash_type": "unknown",  # triage will classify
            "size": crash_file.stat().st_size,
        })

    return new_crashes


def get_afl_stats(engagement: ResearchEngagement) -> dict:
    """Read AFL++ fuzzer_stats file for progress info."""
    stats_file = engagement.fuzz_dir / "findings_afl" / "default" / "fuzzer_stats"
    if not stats_file.exists():
        stats_file = engagement.fuzz_dir / "findings_afl" / "fuzzer_stats"
    if not stats_file.exists():
        return {}

    stats = {}
    try:
        for line in stats_file.read_text().split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                stats[key.strip()] = val.strip()
    except Exception:
        pass
    return stats


# --- Monitoring loop ---

def monitor_fuzzing(engagement: ResearchEngagement, afl_pid: int,
                    on_status=None) -> dict:
    """Monitor AFL++ until crash threshold is hit or timeout.

    Checks for new crashes every FUZZ_CHECK_INTERVAL seconds.
    Stops when CRASH_THRESHOLD unique crashes found or FUZZ_MAX_DURATION elapsed.

    Returns summary dict.
    """
    start_time = time.monotonic()
    total_unique = 0

    while True:
        elapsed = time.monotonic() - start_time
        if elapsed > FUZZ_MAX_DURATION:
            if on_status:
                on_status(f"[fuzzer] Timeout ({FUZZ_MAX_DURATION}s) — stopping")
            break

        # Check if AFL is still running
        try:
            os.kill(afl_pid, 0)  # signal 0 = check if alive
        except ProcessLookupError:
            if on_status:
                on_status("[fuzzer] AFL++ process ended")
            break

        # Check for new crashes
        new_crashes = check_crashes(engagement)
        for crash in new_crashes:
            engagement.add_crash(**crash)
            total_unique += 1
            if on_status:
                on_status(f"[fuzzer] CRASH #{total_unique}: {os.path.basename(crash['input_file'])} "
                          f"({crash['size']}b)")

        if total_unique >= CRASH_THRESHOLD:
            if on_status:
                on_status(f"[fuzzer] Crash threshold ({CRASH_THRESHOLD}) reached — stopping")
            break

        # Show progress
        stats = get_afl_stats(engagement)
        execs = stats.get("execs_done", "?")
        speed = stats.get("execs_per_sec", "?")
        paths = stats.get("paths_total", "?")
        if on_status:
            on_status(f"[fuzzer] {int(elapsed)}s | execs:{execs} | speed:{speed}/s | "
                      f"paths:{paths} | crashes:{total_unique}/{CRASH_THRESHOLD}")

        time.sleep(FUZZ_CHECK_INTERVAL)

    # Kill AFL
    try:
        os.kill(afl_pid, 9)
    except Exception:
        pass

    # Final crash collection
    final_crashes = check_crashes(engagement)
    for crash in final_crashes:
        engagement.add_crash(**crash)
        total_unique += 1

    engagement.current_phase = "fuzzing"
    if "fuzzing" not in engagement.completed_phases:
        engagement.completed_phases.append("fuzzing")
    engagement.save()

    return {
        "duration": time.monotonic() - start_time,
        "total_crashes": total_unique,
        "unique_crashes": engagement.unique_crashes(),
        "stats": get_afl_stats(engagement),
    }


# --- Full pipeline ---

def run_fuzzing(engagement: ResearchEngagement, entry_points: list[str] = None,
                sinks: list[dict] = None, compile_flags: list[str] = None,
                on_status=None) -> dict:
    """Run full fuzzing pipeline: harness → compile → seeds → fuzz → collect.

    Returns summary dict.
    """
    if not _HAS_AFL:
        if on_status:
            on_status("[fuzzer] AFL++ not available — install with: sudo apt install afl++")
        return {"error": "AFL++ not installed"}

    # Step 1: Generate harness
    harness = generate_harness(engagement, entry_points, sinks, on_status)
    if not harness:
        return {"error": "Failed to generate harness"}

    # Step 2: Compile (if C/C++)
    binary = compile_harness(harness, engagement, compile_flags, on_status)
    if not binary:
        return {"error": "Failed to compile harness"}

    # Step 3: Gather seeds
    gather_seeds(engagement, on_status)

    # Step 4: Launch AFL++
    pid = launch_afl(binary, engagement, on_status)
    if not pid:
        return {"error": "Failed to launch AFL++"}

    # Step 5: Monitor until threshold
    summary = monitor_fuzzing(engagement, pid, on_status)

    if on_status:
        on_status(f"[fuzzer] Complete: {summary['total_crashes']} crashes in "
                  f"{summary['duration']:.0f}s")

    return summary
