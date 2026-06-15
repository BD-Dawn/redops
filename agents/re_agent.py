"""Reverse engineering agent — binary analysis for vulnerability research.

Uses radare2 (primary, always available on Kali) and Ghidra headless
(optional, for decompilation) to analyze binaries. Identifies dangerous
functions, traces cross-references, maps attack surface.

For firmware: extracts with binwalk first, then analyzes individual binaries
prioritized by dangerous function count and input handling.
"""

import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST, CHAIN_MAX_TURNS
from research_engagement import ResearchEngagement
from agents.re_backbone import analyze as backbone_analyze

_REBIN_MCP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "rebin_mcp.py")


# --- Tool detection ---

def _has_tool(name: str) -> bool:
    try:
        return subprocess.run(["which", name], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False

_HAS_R2 = _has_tool("r2") or _has_tool("radare2")
_HAS_GHIDRA = any(
    Path(p).exists()
    for p in ["/opt/ghidra/support/analyzeHeadless",
              "/usr/share/ghidra/support/analyzeHeadless",
              "/opt/ghidra_11.3_PUBLIC/support/analyzeHeadless"]
)
_HAS_BINWALK = _has_tool("binwalk")

_GHIDRA_HEADLESS = None
if _HAS_GHIDRA:
    for p in ["/opt/ghidra/support/analyzeHeadless",
              "/usr/share/ghidra/support/analyzeHeadless",
              "/opt/ghidra_11.3_PUBLIC/support/analyzeHeadless"]:
        if Path(p).exists():
            _GHIDRA_HEADLESS = p
            break

# Dangerous C functions to look for in binaries
_DANGEROUS_IMPORTS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "memcpy", "memmove", "strncpy", "strncat", "snprintf",
    "system", "popen", "execve", "execvp", "exec",
    "dlopen", "dlsym",
    "malloc", "free", "realloc", "calloc",
    "recv", "recvfrom", "read", "fread",
    "fopen", "open", "fwrite", "write",
}


# --- radare2 analysis ---

def r2_analyze(binary_path: str, on_status=None) -> dict:
    """Analyze a binary with radare2. Returns structured analysis.

    Output: {functions, imports, dangerous_functions, strings_of_interest, xrefs, sections}
    """
    results = {
        "functions": [],
        "imports": [],
        "dangerous_functions": [],
        "dangerous_xrefs": {},  # dangerous_func → [callers]
        "strings_of_interest": [],
        "sections": [],
        "entry_point": "",
        "binary_info": {},
    }

    if not _HAS_R2:
        return results

    r2_cmd = "radare2" if _has_tool("radare2") else "r2"

    def _r2(cmds: str) -> str:
        """Run r2 commands in batch mode."""
        try:
            result = subprocess.run(
                [r2_cmd, "-q", "-c", cmds, binary_path],
                capture_output=True, text=True, timeout=60,
            )
            return result.stdout
        except Exception:
            return ""

    if on_status:
        on_status(f"[re_agent] Analyzing {os.path.basename(binary_path)} with radare2...")

    # Basic info
    info = _r2("iIj")
    try:
        results["binary_info"] = json.loads(info)
    except Exception:
        pass

    # Entry point
    entry = _r2("iej")
    try:
        entries = json.loads(entry)
        if entries:
            results["entry_point"] = hex(entries[0].get("vaddr", 0))
    except Exception:
        pass

    # Imports
    imports_out = _r2("iij")
    try:
        imports = json.loads(imports_out)
        for imp in imports:
            name = imp.get("name", "")
            results["imports"].append(name)
            if name in _DANGEROUS_IMPORTS:
                results["dangerous_functions"].append({
                    "name": name,
                    "address": hex(imp.get("plt", imp.get("vaddr", 0))),
                    "type": "import",
                })
    except Exception:
        pass

    # Functions (with analysis)
    if on_status:
        on_status("[re_agent] Analyzing functions...")
    funcs_out = _r2("aaa; aflj")
    try:
        funcs = json.loads(funcs_out)
        results["functions"] = [
            {
                "name": f.get("name", ""),
                "address": hex(f.get("offset", 0)),
                "size": f.get("size", 0),
                "n_calls": f.get("callrefs", 0) if isinstance(f.get("callrefs"), int) else len(f.get("callrefs", [])),
            }
            for f in funcs[:500]  # cap to prevent massive output
        ]
    except Exception:
        pass

    # Cross-references to dangerous functions
    if on_status:
        on_status("[re_agent] Tracing dangerous function cross-references...")
    for df in results["dangerous_functions"]:
        xrefs_out = _r2(f"aaa; axtj {df['address']}")
        try:
            xrefs = json.loads(xrefs_out)
            callers = [
                {
                    "from": hex(x.get("from", 0)),
                    "from_name": x.get("fcn_name", ""),
                    "type": x.get("type", ""),
                }
                for x in xrefs
            ]
            if callers:
                results["dangerous_xrefs"][df["name"]] = callers
        except Exception:
            pass

    # Interesting strings (passwords, keys, URLs, paths)
    strings_out = _r2("izj")
    try:
        strings = json.loads(strings_out)
        for s in strings:
            val = s.get("string", "")
            if len(val) < 4:
                continue
            # Filter for interesting strings
            lower = val.lower()
            if any(kw in lower for kw in (
                "password", "passwd", "secret", "key", "token",
                "admin", "root", "debug", "test", "backdoor",
                "http://", "https://", "ftp://",
                "/etc/", "/tmp/", "/bin/", "/dev/",
                "select ", "insert ", "update ", "delete ",
                "%s", "%d", "%x", "%n",  # format strings
            )):
                results["strings_of_interest"].append({
                    "value": val[:200],
                    "address": hex(s.get("vaddr", 0)),
                    "section": s.get("section", ""),
                })
    except Exception:
        pass

    # Sections
    sections_out = _r2("iSj")
    try:
        sections = json.loads(sections_out)
        results["sections"] = [
            {
                "name": s.get("name", ""),
                "size": s.get("size", 0),
                "perm": s.get("perm", ""),
            }
            for s in sections
        ]
    except Exception:
        pass

    return results


# --- Ghidra headless decompilation (optional) ---

def ghidra_decompile(binary_path: str, functions: list[str] = None,
                     output_dir: str = "/tmp/ghidra_out", on_status=None) -> dict[str, str]:
    """Decompile specific functions using Ghidra headless.

    Returns {function_name: decompiled_C_code}.
    Runs async — large binaries can take minutes.
    """
    if not _GHIDRA_HEADLESS:
        return {}

    if on_status:
        on_status("[re_agent] Running Ghidra headless decompilation...")

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    project_dir = out_path / "ghidra_project"
    project_dir.mkdir(exist_ok=True)

    # Ghidra script that decompiles specified functions
    script_content = """
import ghidra.app.decompiler.DecompInterface as DecompInterface

decomp = DecompInterface()
decomp.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)

for func in functions:
    results = decomp.decompileFunction(func, 30, monitor)
    if results and results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        if code:
            print("===FUNC:" + func.getName() + "===")
            print(code)
            print("===END===")
"""
    script_path = out_path / "decompile_all.py"
    script_path.write_text(script_content)

    try:
        result = subprocess.run(
            [
                _GHIDRA_HEADLESS,
                str(project_dir), "analysis",
                "-import", binary_path,
                "-postScript", str(script_path),
                "-deleteProject",
                "-noanalysis",  # we'll do our own
            ],
            capture_output=True, text=True,
            timeout=600,  # 10 minute timeout for large binaries
        )

        # Parse output: ===FUNC:name=== ... ===END===
        decompiled = {}
        current_func = None
        current_code = []
        for line in result.stdout.split("\n"):
            if line.startswith("===FUNC:"):
                if current_func and current_code:
                    decompiled[current_func] = "\n".join(current_code)
                current_func = line[8:].rstrip("=")
                current_code = []
            elif line == "===END===":
                if current_func and current_code:
                    decompiled[current_func] = "\n".join(current_code)
                current_func = None
                current_code = []
            elif current_func:
                current_code.append(line)

        return decompiled
    except subprocess.TimeoutExpired:
        if on_status:
            on_status("[re_agent] Ghidra timed out — binary too large for 10min budget")
        return {}
    except Exception:
        return {}


# --- Firmware extraction ---

def extract_firmware(firmware_path: str, output_dir: str = None,
                     on_status=None) -> list[dict]:
    """Extract firmware image with binwalk. Returns list of extracted binaries.

    Each: {path, size, dangerous_count, format, arch}
    Sorted by dangerous_count descending (highest priority first).
    """
    if not _HAS_BINWALK:
        return []

    if not output_dir:
        output_dir = str(Path(firmware_path).parent / "extracted")

    if on_status:
        on_status("[re_agent] Extracting firmware with binwalk...")

    try:
        subprocess.run(
            ["binwalk", "-e", "-C", output_dir, firmware_path],
            capture_output=True, text=True, timeout=120,
        )
    except Exception:
        return []

    # Find all ELF binaries in extracted filesystem
    binaries = []
    extracted = Path(output_dir)
    if not extracted.exists():
        return []

    try:
        result = subprocess.run(
            ["find", str(extracted), "-type", "f", "-executable"],
            capture_output=True, text=True, timeout=30,
        )
        for fpath in result.stdout.strip().split("\n"):
            if not fpath:
                continue
            # Check if it's actually an ELF
            file_result = subprocess.run(
                ["file", fpath], capture_output=True, text=True, timeout=5,
            )
            if "ELF" not in file_result.stdout:
                continue

            # Count dangerous functions
            strings_result = subprocess.run(
                ["strings", fpath], capture_output=True, text=True, timeout=10,
            )
            dangerous = set()
            for line in strings_result.stdout.split("\n"):
                if line.strip() in _DANGEROUS_IMPORTS:
                    dangerous.add(line.strip())

            binaries.append({
                "path": fpath,
                "size": os.path.getsize(fpath),
                "dangerous_count": len(dangerous),
                "dangerous_functions": sorted(dangerous),
            })
    except Exception:
        pass

    # Sort by dangerous function count (priority for fuzzing)
    binaries.sort(key=lambda b: -b["dangerous_count"])
    return binaries


# --- LLM analysis of decompiled / disassembled code ---

def analyze_binary_llm(r2_results: dict, decompiled: dict = None,
                       on_status=None) -> list[dict]:
    """Use LLM to analyze binary RE results for vulnerabilities.

    Takes r2 analysis output and optionally Ghidra decompiled code.
    Returns list of findings (potential vulnerabilities).
    """
    findings = []

    # Build analysis context
    context_parts = []

    # Dangerous function xrefs
    if r2_results.get("dangerous_xrefs"):
        context_parts.append("## Dangerous Function Call Sites")
        for func, callers in r2_results["dangerous_xrefs"].items():
            for c in callers[:10]:
                context_parts.append(f"- {func}() called from {c['from_name']} at {c['from']}")

    # Interesting strings
    if r2_results.get("strings_of_interest"):
        context_parts.append("\n## Interesting Strings")
        for s in r2_results["strings_of_interest"][:30]:
            context_parts.append(f"- [{s['address']}] {s['value']}")

    # Decompiled functions (if available)
    if decompiled:
        context_parts.append("\n## Decompiled Functions")
        for name, code in list(decompiled.items())[:10]:
            context_parts.append(f"\n### {name}\n```c\n{code[:2000]}\n```")

    if not context_parts:
        return findings

    context = "\n".join(context_parts)

    prompt = f"""Analyze this binary reverse engineering output for vulnerabilities.

{context[:8000]}

For each potential vulnerability found, respond in JSON array:
[
  {{
    "function": "function name where the bug is",
    "type": "vulnerability type (buffer_overflow, command_injection, format_string, etc.)",
    "cwe": "CWE-XXX",
    "description": "what the bug is in plain language",
    "confidence": "high/medium/low",
    "exploitability": "weaponizable/promising/interesting/low_value",
    "evidence": "the specific code/pattern that shows the vulnerability"
  }}
]

Rules:
- Only report findings with clear evidence — not speculative
- A dangerous function being CALLED is not a bug — trace whether untrusted input reaches it
- Format strings (%s in printf family) are only bugs if the format is user-controlled
- Focus on: input handling functions, parsers, network-facing code
- Return empty array [] if no vulnerabilities found"""

    if on_status:
        on_status("[re_agent] LLM analyzing binary for vulnerabilities...")

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text",
             "--max-turns", "1", "--model", MODEL_FAST],
            input=prompt, capture_output=True, text=True, timeout=90,
        )
        if result.returncode == 0 and result.stdout.strip():
            json_match = re.search(r"\[[\s\S]*\]", result.stdout)
            if json_match:
                findings = json.loads(json_match.group())
    except Exception:
        pass

    return findings


# --- Layer 3: grounded agentic RE loop (Opus over the rebin MCP) ---

def _backbone_brief(report: dict, max_paths: int = 18) -> str:
    """Compact the backbone report into a prompt-sized investigation brief."""
    lines = []
    lines.append(f"binary: {report.get('binary')}")
    lines.append(f"format={report.get('binary_format')} arch={report.get('arch')} "
                 f"is_driver={report.get('is_driver')} functions={report.get('functions_count')}")
    if report.get("dispatch_handler"):
        lines.append(f"IOCTL dispatch handler: {report['dispatch_handler']}")
    if report.get("ioctl_map"):
        lines.append("IOCTLs:")
        for e in report["ioctl_map"]:
            lines.append(f"  {e['code_hex']} devtype={hex(e['device_type'])} "
                         f"func={hex(e['function'])} method={e['method']} access={e['access']}")
    if report.get("dangerous_sinks"):
        lines.append("dangerous sinks present: "
                     + ", ".join(f"{s['name']}@{s['addr']}" for s in report["dangerous_sinks"]))
    paths = report.get("reachability_paths", [])[:max_paths]
    if paths:
        lines.append(f"ranked source->sink reachability paths ({len(paths)} shown):")
        for p in paths:
            chain = " -> ".join(p.get("path", []))
            lines.append(f"  [{p.get('severity')}] {chain}  ==> {p.get('sink')}@{p.get('sink_addr')}")
    if report.get("double_fetch_candidates"):
        lines.append("double-fetch candidates:")
        for d in report["double_fetch_candidates"]:
            lines.append(f"  {d.get('location')} {d.get('expression')} x{d.get('read_count')}")
    if report.get("notes"):
        lines.append("notes: " + " | ".join(report["notes"]))
    return "\n".join(lines)


def _mcp_config_file() -> str:
    """Write a temp MCP config exposing the rebin server to the agent subprocess."""
    import tempfile
    cfg = {"mcpServers": {"rebin": {"command": "python3", "args": [_REBIN_MCP]}}}
    fd, path = tempfile.mkstemp(prefix="rebin_mcp_cfg_", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    return path


_REBIN_TOOLS = [
    "open_binary", "backbone_report", "list_functions", "disasm", "decompile",
    "xrefs_to", "xrefs_from", "callgraph_path", "ioctl_map", "decode_ioctl_code",
    "imports", "strings_in", "hexdump",
]


def run_agentic_re(target_path: str, report: dict, on_status=None,
                   on_progress=None, max_turns: int = None,
                   transcript_path: str = None) -> list[dict]:
    """Drive an Opus agent over the rebin MCP to confirm/kill bug candidates.

    The deterministic backbone has already mapped the attack surface and ranked
    source->sink paths. The agent's job is to walk those paths with real tools
    (disasm/decompile/xrefs) and decide which are genuinely exploitable —
    grounding every claim in code it actually pulled.
    """
    max_turns = max_turns or CHAIN_MAX_TURNS
    brief = _backbone_brief(report)

    prompt = f"""You are a kernel/binary vulnerability researcher hunting for a real, \
exploitable zero-day in a single binary. A deterministic analysis backbone has \
already mapped the attack surface. Your job: investigate the ranked paths below \
with the `rebin` MCP tools and confirm or kill each candidate with EVIDENCE.

## Backbone map (ground truth — addresses/names are real)
{brief}

## How to work
1. Call mcp__rebin__open_binary("{target_path}") first to load the full map.
2. For each ranked path, walk it: mcp__rebin__decompile the handler and the \
functions on the path, follow mcp__rebin__xrefs_to/xrefs_from, inspect IOCTL \
handling. Use mcp__rebin__callgraph_path to confirm reachability between funcs.
3. Decide, for each candidate, whether ATTACKER-CONTROLLED input (IOCTL input \
buffer / network / file data) actually reaches a dangerous operation WITHOUT \
adequate validation (missing bounds check, unchecked length, sign confusion, \
unvalidated user pointer with METHOD_NEITHER, integer overflow before alloc/copy).

## Rules (this is what separates a finding from a false positive)
- A dangerous sink merely being called is NOT a bug. You must show the data flow \
from an input source to the sink and the MISSING/INADEQUATE check.
- Quote the actual decompiled C (or disasm) that proves it. No quoted code = no finding.
- If you cannot prove exploitability, say so. An empty findings list is a valid, \
honest result. Do NOT invent vulnerabilities to fill the report.
- Verify every address/function name against tool output before citing it.

## Output
When done investigating, output ONLY a JSON array (no prose around it) as your \
final message:
[
  {{
    "function": "function name or address where the bug is",
    "address": "0x... entry of that function",
    "type": "buffer_overflow|oob_write|oob_read|integer_overflow|double_fetch|\
unvalidated_user_pointer|type_confusion|...",
    "cwe": "CWE-XXX",
    "description": "what the bug is and why it is exploitable",
    "data_flow": "source -> intermediate -> sink (concrete function chain)",
    "evidence": "the decompiled C / disasm lines that prove it (REQUIRED)",
    "reachable": true,
    "confidence": "high|medium|low",
    "exploitability": "weaponizable|promising|interesting|low_value",
    "ioctl": "0x... if reached via a specific IOCTL, else empty"
  }}
]
Return [] if nothing is provably exploitable."""

    cfg_path = _mcp_config_file()
    allowed = ",".join(f"mcp__rebin__{t}" for t in _REBIN_TOOLS)
    cmd = [
        "claude", "-p",
        "--output-format", "stream-json", "--verbose",
        "--model", MODEL,
        "--max-turns", str(max_turns),
        "--mcp-config", cfg_path,
        "--allowedTools", allowed,
        "--dangerously-skip-permissions",
    ]

    if on_status:
        on_status(f"[re_agent] Launching Opus RE loop ({max_turns} turns) over rebin MCP...")

    final_text = ""
    # Open the transcript up front and flush each event as it arrives, so a run
    # that is killed or times out (the thrash case) still leaves a full trace to
    # diagnose — the old end-of-run write captured nothing on a kill.
    tf = None
    if transcript_path:
        try:
            tf = open(transcript_path, "w")
        except Exception:
            tf = None
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        proc.stdin.write(prompt)
        proc.stdin.close()
        # Claude Code stream-json schema: tool calls are tool_use blocks inside
        # `assistant` messages; tool outputs are tool_result blocks inside `user`
        # messages; the final answer is the `result` event.
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if tf is not None:
                try:
                    tf.write(line + "\n")
                    tf.flush()
                except Exception:
                    pass
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = event.get("type", "")
            if etype == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        tname = block.get("name", "")
                        tinput = block.get("input", {}) or {}
                        if tname == "ToolSearch":
                            continue  # internal deferred-tool resolution
                        short = (tinput.get("target") or tinput.get("path") or
                                 tinput.get("source") or tinput.get("sink") or "")
                        if on_status:
                            on_status(f"[re_agent] {tname.replace('mcp__rebin__','')} "
                                      f"{str(short)[:50]}")
                        if on_progress:
                            on_progress({"type": "tool_use", "agent": "re_agent",
                                         "tool": tname,
                                         "input": {k: str(v)[:200]
                                                   for k, v in tinput.items()}})
                    elif block.get("type") == "text":
                        txt = block.get("text", "")
                        if txt.strip():
                            final_text = txt  # last assistant text = conclusion
            elif etype == "result":
                if event.get("result"):
                    final_text = str(event["result"])
        proc.wait(timeout=10)
    except Exception as e:
        if on_status:
            on_status(f"[re_agent] RE loop error: {e}")
    finally:
        if tf is not None:
            try:
                tf.close()
            except Exception:
                pass
        try:
            os.unlink(cfg_path)
        except Exception:
            pass

    return _parse_and_ground_findings(final_text, report, on_status)


def _extract_json_array(text: str):
    """Find the JSON findings array in an LLM reply that may wrap it in prose.

    A naive 'first [ to last ]' regex breaks when the prose contains stray
    brackets (disassembly notes, citations). We scan every '[' as a candidate
    start, bracket-balance to its matching ']' (ignoring brackets inside JSON
    strings), and return the LAST span that parses to a list of dicts — the
    agent's conclusion comes last.
    """
    if not text:
        return None
    # Prefer a fenced ```json block if present.
    fence = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text)
    candidates = []
    if fence:
        candidates.append(fence.group(1))
    for i, ch in enumerate(text):
        if ch != "[":
            continue
        depth = 0
        in_str = False
        esc = False
        for j in range(i, len(text)):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    candidates.append(text[i:j + 1])
                    break
    best = None
    for cand in candidates:
        try:
            val = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(val, list) and (not val or isinstance(val[0], dict)):
            best = val  # keep the last well-formed list-of-dicts
    return best


def _parse_and_ground_findings(text: str, report: dict, on_status=None) -> list[dict]:
    """Extract the JSON findings array and keep only grounded candidates.

    Grounded = the agent quoted real evidence AND claims reachability. Findings
    whose location also lies on a backbone-computed reachability path are marked
    backbone_confirmed; the rest are kept but flagged as agent-asserted only.
    """
    raw = _extract_json_array(text)
    if not isinstance(raw, list):
        if on_status and text:
            on_status("[re_agent] could not parse a findings array from agent output")
        return []

    # function names/addresses that appear on any backbone reachability path
    on_path = set()
    for p in report.get("reachability_paths", []):
        for node in p.get("path", []):
            on_path.add(node)
        on_path.add(p.get("sink", ""))

    grounded = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        evidence = (f.get("evidence") or "").strip()
        reachable = bool(f.get("reachable", False))
        # Grounding gate: must cite real evidence and assert reachability.
        if len(evidence) < 30 or not reachable:
            if on_status:
                on_status(f"[re_agent] dropped ungrounded candidate: "
                          f"{f.get('function','?')} ({f.get('type','?')})")
            continue
        loc = f.get("function", "") or f.get("address", "")
        f["backbone_confirmed"] = any(loc and loc in n for n in on_path) or \
            (f.get("address", "") in on_path)
        grounded.append(f)
    return grounded


# --- Main analysis pipeline ---

def run_re_analysis(engagement: ResearchEngagement, on_status=None) -> dict:
    """Run full RE analysis pipeline on binary target(s).

    For single binaries: r2 analysis + optional Ghidra decompile + LLM analysis.
    For firmware: extract → prioritize by dangerous functions → analyze top binaries.

    Returns analysis summary dict.
    """
    profile = engagement.profile
    target_path = engagement.target_path
    summary = {"binaries_analyzed": 0, "findings": [], "dangerous_total": 0}

    if profile.target_type == "firmware":
        # Extract firmware and analyze top binaries
        binaries = extract_firmware(target_path, str(engagement.dir / "extracted"), on_status)
        if on_status:
            on_status(f"[re_agent] Extracted {len(binaries)} binaries from firmware")

        # Analyze top 5 by dangerous function count (parallel)
        top_binaries = binaries[:5]

        def _analyze_one(b):
            return r2_analyze(b["path"], on_status)

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(_analyze_one, b): b for b in top_binaries}
            for future in as_completed(futures):
                binary = futures[future]
                try:
                    r2_result = future.result()
                    llm_findings = analyze_binary_llm(r2_result, on_status=on_status)
                    summary["binaries_analyzed"] += 1
                    summary["dangerous_total"] += len(r2_result.get("dangerous_functions", []))
                    summary["findings"].extend(llm_findings)
                except Exception:
                    pass

    elif profile.target_type == "binary":
        # Single binary: 3-layer architecture.
        # Layer 1 — deterministic backbone maps the attack surface + ranks paths.
        if on_status:
            on_status("[re_agent] Layer 1: deterministic backbone analysis...")
        report = backbone_analyze(target_path, on_status=on_status)
        report_dict = report.to_dict()
        summary["binaries_analyzed"] = 1
        summary["dangerous_total"] = len(report_dict.get("dangerous_sinks", []))
        summary["backbone"] = report_dict
        # Persist the ground-truth map for the record.
        try:
            (engagement.dir / "backbone_report.json").write_text(
                json.dumps(report_dict, indent=2))
        except Exception:
            pass

        # Layer 2+3 — agentic loop over the rebin MCP, grounded confirmation.
        if on_status:
            on_status("[re_agent] Layer 2/3: agentic investigation + grounding...")
        summary["findings"] = run_agentic_re(
            target_path, report_dict, on_status=on_status,
            transcript_path=str(engagement.dir / "re_transcript.jsonl"))

    # Update engagement state
    for f in summary["findings"]:
        engagement.add_bug_candidate(
            type=f.get("type", "unknown"),
            cwe=f.get("cwe", ""),
            title=f.get("description", "")[:100],
            location=f.get("function", "") or f.get("address", "unknown"),
            what=f.get("description", ""),
            confidence=f.get("confidence", "low"),
            exploitability=f.get("exploitability", ""),
            evidence=f.get("evidence", ""),
            data_flow=f.get("data_flow", ""),
            ioctl=f.get("ioctl", ""),
            reachable=f.get("reachable", False),
            backbone_confirmed=f.get("backbone_confirmed", False),
        )

    engagement.current_phase = "re_analysis"
    if "re_analysis" not in engagement.completed_phases:
        engagement.completed_phases.append("re_analysis")
    engagement.save()

    if on_status:
        on_status(f"[re_agent] Analysis complete: {summary['binaries_analyzed']} binaries, "
                  f"{len(summary['findings'])} potential vulnerabilities")

    return summary
