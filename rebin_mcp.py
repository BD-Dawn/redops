"""REBIN MCP Server (Layer 2) — interactive binary RE tools for the agentic loop.

This is the toolbox the Opus reverse-engineering agent drives. Every tool is
backed by ground truth from the binary (r2pipe for structure/disasm, Ghidra
headless for C decompilation), so the agent reasons over real data instead of
guessing. Layer 1 (re_backbone) hands the agent a ranked map of source->sink
paths; these tools let it pull the actual code at each hop and confirm or kill
a candidate.

Design:
  - One persistent r2pipe session per binary (analyzed once with `aaa`), shared
    across all structure/disasm/xref calls — instant after the first open.
  - Ghidra headless with a *persistent project*: import+analyze once, then every
    `decompile` is a fast `-process -noanalysis -postScript` run (no re-analysis).
  - Backbone report cached per binary.

Register in ~/.claude/settings.json:
    {
        "mcpServers": {
            "rebin": {
                "command": "python3",
                "args": ["/home/kali/OffensiveAI/redops/rebin_mcp.py"]
            }
        }
    }
"""

import sys
import os
import json
import subprocess
import tempfile
import hashlib
import re
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

from agents.re_backbone import _R2, analyze as backbone_analyze, decode_ioctl

# ---------------------------------------------------------------------------
# Ghidra discovery (mirror re_agent.py)
# ---------------------------------------------------------------------------

_GHIDRA_HEADLESS = None
for _p in ("/opt/ghidra/support/analyzeHeadless",
           "/usr/share/ghidra/support/analyzeHeadless",
           "/opt/ghidra_11.3_PUBLIC/support/analyzeHeadless"):
    if Path(_p).exists():
        _GHIDRA_HEADLESS = _p
        break

_GHIDRA_SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "ghidra_scripts")
_GHIDRA_PROJ_ROOT = os.path.join(tempfile.gettempdir(), "redops_ghidra")

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "rebin",
    instructions=(
        "REBIN — static binary reverse-engineering toolbox for zero-day "
        "discovery. Open a binary with open_binary to get a structural map "
        "(IOCTL dispatch, dangerous sinks, ranked source->sink reachability "
        "paths). Then walk the ranked paths: disasm/decompile each function, "
        "follow xrefs, and confirm whether attacker-controlled input reaches a "
        "sink without validation. Every fact comes from the binary — never "
        "invent addresses, function names, or code you have not pulled."
    ),
)


# ---------------------------------------------------------------------------
# Per-binary session cache
# ---------------------------------------------------------------------------

class _Target:
    """Holds the persistent r2 session, backbone report, and Ghidra project."""

    def __init__(self, path: str):
        self.path = path
        self.r2 = _R2(path)
        self.r2.cmd("aaa")
        self.report = None          # BackboneReport, lazily computed
        self._ghidra_ready = False  # project imported+analyzed?
        # Cache of full decompiled C bodies keyed by canonical function address,
        # so Ghidra runs at most ONCE per function. Paging windows slice this
        # cached body instead of re-spawning analyzeHeadless per call — the fix
        # for the RE-loop thrash (60+ Ghidra subprocesses → 600s timeout).
        self._decomp_cache: dict[str, str] = {}

    def report_dict(self) -> dict:
        if self.report is None:
            # reuse the already-analyzed session
            self.report = backbone_analyze(self.path, r2=self.r2)
        return self.report.to_dict()

    def close(self):
        try:
            self.r2.close()
        except Exception:
            pass


_targets: dict[str, _Target] = {}


def _get(path: str) -> _Target:
    rp = os.path.realpath(path)
    if rp not in _targets:
        if not os.path.exists(rp):
            raise FileNotFoundError(rp)
        _targets[rp] = _Target(rp)
    return _targets[rp]


def _proj_name(path: str) -> str:
    h = hashlib.sha1(os.path.realpath(path).encode()).hexdigest()[:12]
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(path))
    return f"{base}_{h}"


# ---------------------------------------------------------------------------
# Ghidra headless decompile (persistent project)
# ---------------------------------------------------------------------------

def _ghidra_import(path: str, on_log=None) -> tuple[bool, str]:
    """Import + analyze the binary into a persistent Ghidra project (once)."""
    if not _GHIDRA_HEADLESS:
        return False, "Ghidra headless not installed"
    os.makedirs(_GHIDRA_PROJ_ROOT, exist_ok=True)
    name = _proj_name(path)
    cmd = [
        _GHIDRA_HEADLESS, _GHIDRA_PROJ_ROOT, name,
        "-import", path,
        "-scriptPath", _GHIDRA_SCRIPT_DIR,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return False, "Ghidra import/analysis timed out (>15min)"
    except Exception as e:
        return False, f"Ghidra import failed: {e}"
    ok = "Import succeeded" in res.stdout or "Analysis succeeded" in res.stdout \
        or res.returncode == 0
    return (ok, res.stdout[-2000:] if not ok else "imported")


def _ghidra_decompile(path: str, target: str) -> str:
    """Decompile one function from the already-imported project."""
    if not _GHIDRA_HEADLESS:
        return "ERROR: Ghidra headless not installed on this system."
    name = _proj_name(path)
    proj_file = os.path.join(_GHIDRA_PROJ_ROOT, name + ".gpr")

    tgt = _get(path)
    if not tgt._ghidra_ready or not os.path.exists(proj_file):
        ok, msg = _ghidra_import(path)
        if not ok:
            return f"ERROR: Ghidra import failed:\n{msg}"
        tgt._ghidra_ready = True

    # decompiled C is written to a file (Ghidra's logger prefixes stdout lines)
    out_fd, out_path = tempfile.mkstemp(prefix="redops_dec_", suffix=".c")
    os.close(out_fd)
    # -process against the imported file, skip analysis, run our decompile script
    cmd = [
        _GHIDRA_HEADLESS, _GHIDRA_PROJ_ROOT, name,
        "-process", os.path.basename(path),
        "-noanalysis",
        "-scriptPath", _GHIDRA_SCRIPT_DIR,
        "-postScript", "RedopsDecompile.java", target, out_path,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        os.unlink(out_path)
        return "ERROR: Ghidra decompile timed out."
    except Exception as e:
        os.unlink(out_path)
        return f"ERROR: Ghidra decompile failed: {e}"

    try:
        body = Path(out_path).read_text()
    except Exception:
        body = ""
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass

    if body.startswith("REDOPS_ERR:"):
        return "ERROR: " + body[len("REDOPS_ERR:"):].strip()
    if body.strip():
        return body
    return ("ERROR: no decompiler output. Tail of Ghidra log:\n" + res.stdout[-800:])


# ---------------------------------------------------------------------------
# Helpers for resolving a target (addr or name) to an address
# ---------------------------------------------------------------------------

def _resolve_addr(tgt: _Target, target: str) -> str:
    """Return an r2-usable address string for a function addr-or-name."""
    target = target.strip()
    if target.startswith("0x"):
        return target
    # try symbol/function name → r2 understands sym/fcn names in most commands,
    # but normalize to an address via `?v` to be safe.
    v = tgt.r2.cmd(f"?v {target}").strip()
    if v and v not in ("0x0", "0"):
        return v
    return target  # let r2 try the name directly


# ===========================================================================
# Tools
# ===========================================================================

@mcp.tool()
def open_binary(path: str) -> str:
    """Open a binary and return its structural map (the starting point for RE).

    Runs the deterministic backbone: binary metadata, IOCTL dispatch map (for
    Windows kernel drivers), dangerous sinks present, and the RANKED list of
    source->sink reachability paths. Walk these paths to find the bug.

    Args:
        path: Absolute path to the binary (e.g. a .sys driver or ELF/PE).
    """
    try:
        tgt = _get(path)
    except FileNotFoundError:
        return f"ERROR: file not found: {path}"
    return json.dumps(tgt.report_dict(), indent=2)


@mcp.tool()
def backbone_report(path: str) -> str:
    """Return the cached deterministic backbone report (same as open_binary).

    Args:
        path: Absolute path to the binary.
    """
    return open_binary(path)


@mcp.tool()
def list_functions(path: str, filter: str = "") -> str:
    """List analyzed functions (address, size, name), optionally name-filtered.

    Args:
        path: Absolute path to the binary.
        filter: Optional substring to filter function names (case-insensitive).
    """
    tgt = _get(path)
    funcs = tgt.r2.cmdj("aflj") or []
    flt = filter.lower()
    lines = []
    for f in funcs:
        nm = f.get("name", "")
        if flt and flt not in nm.lower():
            continue
        lines.append(f"{hex(f.get('offset', 0))}\t{f.get('size', 0):>6}\t{nm}")
    if not lines:
        return "No functions match." if flt else "No functions."
    return f"{len(lines)} functions:\n" + "\n".join(lines[:500])


def _window(body: str, start_line: int, max_lines: int,
            max_chars: int = 18000) -> str:
    """Return a line-numbered window of `body`, bounded so the result never
    exceeds Claude Code's per-tool-output token cap.

    Large functions (e.g. a 1200-line IOCTL dispatcher) otherwise overflow and
    get spilled to a file, forcing the agent to waste turns reading it back.
    """
    lines = body.splitlines()
    total = len(lines)
    if start_line < 1:
        start_line = 1
    begin = start_line - 1
    if begin >= total:
        return f"// only {total} lines; start_line={start_line} is past the end."

    out, chars, last = [], 0, begin
    for i in range(begin, min(total, begin + max_lines)):
        ln = f"{i + 1}\t{lines[i]}"
        if chars + len(ln) + 1 > max_chars:
            break
        out.append(ln)
        chars += len(ln) + 1
        last = i + 1

    shown = "\n".join(out)
    if last < total:
        more = (f"\n// ... truncated. Showing lines {start_line}-{last} of "
                f"{total}. Call again with start_line={last + 1} for more.")
        return shown + more
    if start_line > 1:
        return shown + f"\n// end of function (lines {start_line}-{total} of {total})."
    return shown


@mcp.tool()
def disasm(path: str, target: str, instructions: int = 0,
           start_line: int = 1, max_lines: int = 600) -> str:
    """Disassemble a function (instant — from the r2 session).

    Args:
        path: Absolute path to the binary.
        target: Function address (0x140014e60) or name.
        instructions: If >0, disassemble only this many instructions from the
            address (pd N); otherwise the whole function (pdf).
        start_line: 1-based line to start the returned window at (for paging
            through large functions).
        max_lines: Max lines to return in this window.
    """
    tgt = _get(path)
    addr = _resolve_addr(tgt, target)
    tgt.r2.cmd(f"af @ {addr}")  # ensure analyzed
    if instructions and instructions > 0:
        out = tgt.r2.cmd(f"pd {instructions} @ {addr}")
    else:
        out = tgt.r2.cmd(f"pdf @ {addr}")
    out = out.strip()
    if not out:
        return f"No disassembly at {target}."
    return _window(out, start_line, max_lines)


@mcp.tool()
def decompile(path: str, target: str,
              start_line: int = 1, max_lines: int = 600) -> str:
    """Decompile a function to C using Ghidra (the heavy, authoritative view).

    First call per binary imports+analyzes the project (slow, ~1-2 min); later
    calls are fast. Use this to confirm data flow you suspect from disasm.

    Output is line-numbered and windowed so large functions never overflow. For
    a big function (e.g. an IOCTL dispatcher), read the first window, then call
    again with start_line set to the next line to page through it.

    Args:
        path: Absolute path to the binary.
        target: Function address (0x140014e60) or name.
        start_line: 1-based line to start the returned window at.
        max_lines: Max lines to return in this window.
    """
    tgt = _get(path)
    # Canonicalize the cache key so "decompile 0x140007208" and a later call by
    # name resolve to the same cached body. Ghidra runs only on a cache miss.
    key = _resolve_addr(tgt, target)
    body = tgt._decomp_cache.get(key)
    if body is None:
        body = _ghidra_decompile(tgt.path, target)
        if body.startswith("ERROR:"):
            return body  # don't cache failures — a re-analyze may succeed
        tgt._decomp_cache[key] = body
    return _window(body, start_line, max_lines)


@mcp.tool()
def xrefs_to(path: str, target: str) -> str:
    """Who calls / references this address (callers — walk UP toward input).

    Args:
        path: Absolute path to the binary.
        target: Address or name to find references TO.
    """
    tgt = _get(path)
    addr = _resolve_addr(tgt, target)
    xrefs = tgt.r2.cmdj(f"axtj @ {addr}") or []
    if not xrefs:
        return f"No references to {target}."
    lines = []
    for x in xrefs:
        fa = x.get("fcn_addr")
        fn = x.get("fcn_name", "")
        lines.append(f"{hex(x.get('from', 0))}\t{x.get('type','')}\tin {fn or hex(fa) if fa else '?'}")
    return f"{len(lines)} refs to {target}:\n" + "\n".join(lines)


@mcp.tool()
def xrefs_from(path: str, target: str) -> str:
    """What this function calls / references (callees — walk DOWN toward sinks).

    Args:
        path: Absolute path to the binary.
        target: Function address or name.
    """
    tgt = _get(path)
    addr = _resolve_addr(tgt, target)
    tgt.r2.cmd(f"af @ {addr}")
    xrefs = tgt.r2.cmdj(f"axffj @ {addr}") or tgt.r2.cmdj(f"axfj @ {addr}") or []
    if not xrefs:
        return f"No outbound references from {target}."
    lines = []
    for x in xrefs:
        ref = x.get("ref") or x.get("to") or x.get("at") or 0
        nm = x.get("name", "")
        lines.append(f"{x.get('type','')}\t{hex(ref) if isinstance(ref,int) else ref}\t{nm}")
    return f"refs from {target}:\n" + "\n".join(lines)


@mcp.tool()
def callgraph_path(path: str, source: str, sink: str, max_depth: int = 12) -> str:
    """Find a concrete call path from source function to sink function (BFS).

    Proves reachability: if a path exists, attacker input *can* flow from the
    source toward the sink. Returns the function-name chain or 'no path'.

    Args:
        path: Absolute path to the binary.
        source: Starting function address or name (e.g. the IOCTL dispatcher).
        sink: Target function address or name (e.g. memcpy / ExAllocatePoolWithTag).
        max_depth: Maximum path length to search (default 12).
    """
    from collections import deque
    tgt = _get(path)
    # Force-analyze the source: the IOCTL dispatch handler is reached only via a
    # function-pointer store, so `aaa` may not have made it a function with edges.
    src_addr0 = _resolve_addr(tgt, source)
    tgt.r2.cmd(f"af @ {src_addr0}")
    funcs = tgt.r2.cmdj("aflj") or []
    name_to_addr, addr_to_name, cg = {}, {}, {}
    for f in funcs:
        off = f.get("offset", 0)
        nm = f.get("name", "")
        addr_to_name[off] = nm
        name_to_addr[nm] = off
        outs = set()
        for c in (f.get("callrefs") or []):
            if c.get("type") in ("CALL", "call") and "addr" in c:
                outs.add(c["addr"])
        cg[off] = outs

    # import name -> thunk address (imports aren't always in the aflj name map
    # under their bare name; r2 calls them sym.imp.X)
    import_addr = {}
    for imp in (tgt.r2.cmdj("iij") or []):
        nm = imp.get("name", "")
        a = imp.get("plt") or imp.get("vaddr") or 0
        if a:
            import_addr[nm] = a
            import_addr[nm.split("_")[-1]] = a

    def _addr(t: str):
        a = _resolve_addr(tgt, t)
        try:
            return int(a, 16)
        except Exception:
            pass
        if t in name_to_addr:
            return name_to_addr[t]
        if t in import_addr:
            return import_addr[t]
        if f"sym.imp.{t}" in name_to_addr:
            return name_to_addr[f"sym.imp.{t}"]
        return None

    s, d = _addr(source), _addr(sink)
    if s is None:
        return f"source not found: {source}"
    if d is None:
        return f"sink not found: {sink}"

    q = deque([(s, [s])])
    seen = {s}
    while q:
        node, trail = q.popleft()
        if len(trail) > max_depth:
            continue
        if node == d:
            chain = " -> ".join(addr_to_name.get(a, hex(a)) for a in trail)
            return f"PATH ({len(trail)} hops): {chain}"
        for callee in cg.get(node, ()):
            if callee not in seen:
                seen.add(callee)
                q.append((callee, trail + [callee]))
    return f"No path from {source} to {sink} within depth {max_depth}."


@mcp.tool()
def ioctl_map(path: str) -> str:
    """IOCTL dispatch map for a Windows kernel driver (codes + decoded fields).

    Args:
        path: Absolute path to the .sys driver.
    """
    tgt = _get(path)
    rep = tgt.report_dict()
    if not rep.get("ioctl_map"):
        return ("No IOCTL codes resolved. dispatch_handler="
                f"{rep.get('dispatch_handler') or 'unresolved'}. "
                "Driver may use a jump table or compute codes dynamically — "
                "disasm the dispatch handler to inspect.")
    return json.dumps({
        "dispatch_handler": rep.get("dispatch_handler"),
        "ioctls": rep.get("ioctl_map"),
    }, indent=2)


@mcp.tool()
def decode_ioctl_code(code: str) -> str:
    """Decode a single Windows CTL_CODE into device_type/function/method/access.

    Args:
        code: The control code, hex (0x222200) or decimal.
    """
    try:
        c = int(code, 16) if code.lower().startswith("0x") else int(code)
    except ValueError:
        return f"Not a number: {code}"
    return json.dumps(decode_ioctl(c).to_dict(), indent=2)


@mcp.tool()
def imports(path: str, filter: str = "") -> str:
    """List imported functions (the API surface), optionally name-filtered.

    Args:
        path: Absolute path to the binary.
        filter: Optional case-insensitive substring filter.
    """
    tgt = _get(path)
    imps = tgt.r2.cmdj("iij") or []
    flt = filter.lower()
    lines = []
    for i in imps:
        nm = i.get("name", "")
        if flt and flt not in nm.lower():
            continue
        lines.append(f"{hex(i.get('plt') or i.get('vaddr') or 0)}\t{nm}")
    if not lines:
        return "No imports match." if flt else "No imports."
    return f"{len(lines)} imports:\n" + "\n".join(lines[:400])


@mcp.tool()
def strings_in(path: str, target: str = "") -> str:
    """List strings; if target given, only strings referenced by that function.

    Args:
        path: Absolute path to the binary.
        target: Optional function address/name to scope strings to.
    """
    tgt = _get(path)
    if not target:
        out = tgt.r2.cmd("izzq~...")  # quiet, capped
        s = tgt.r2.cmd("iz")
        return s.strip()[:6000] or "No strings."
    addr = _resolve_addr(tgt, target)
    tgt.r2.cmd(f"af @ {addr}")
    # data refs from the function, resolve those pointing into string section
    refs = tgt.r2.cmdj(f"axffj @ {addr}") or []
    found = []
    for r in refs:
        if r.get("type") in ("DATA", "data", "STRING", "string"):
            ref = r.get("ref") or r.get("to")
            if isinstance(ref, int):
                sv = tgt.r2.cmd(f"psz @ {ref}").strip()
                if sv:
                    found.append(f"{hex(ref)}: {sv}")
    return "\n".join(found) if found else f"No string refs in {target}."


@mcp.tool()
def hexdump(path: str, target: str, length: int = 128) -> str:
    """Hexdump bytes at an address (inspect raw data/structures).

    Args:
        path: Absolute path to the binary.
        target: Address or name.
        length: Number of bytes (default 128).
    """
    tgt = _get(path)
    addr = _resolve_addr(tgt, target)
    return tgt.r2.cmd(f"px {length} @ {addr}").strip() or f"No data at {target}."


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run()
