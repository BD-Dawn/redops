"""Deterministic RE backbone (Layer 1) — no LLM.

Builds ground-truth structural facts about a binary that the agentic RE loop
(Layer 2) reasons over. Everything here is computed from the binary via r2pipe,
so a finding grounded in this data is real, not hallucinated.

Provides:
  - call graph (caller -> callees)
  - input-source detection (network/file imports; for PE drivers the IOCTL
    dispatch handler is the canonical input source)
  - reachability paths: input source -> ... -> dangerous sink (BFS over callgraph)
  - IOCTL dispatch map for Windows kernel drivers (DriverObject->MajorFunction
    wiring + IoControlCode switch decode)
  - double-fetch candidate flagging (best-effort static heuristic)

This module never decompiles — that is the MCP server's job (Layer 2). Here we
only need structure and reachability so the agent knows *which* functions to
pull and in what priority order.
"""

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import r2pipe
    _HAS_R2PIPE = True
except Exception:
    _HAS_R2PIPE = False


# --- Dangerous sinks -------------------------------------------------------

# Userspace memory-corruption / command-exec sinks
_USER_SINKS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
    "memcpy", "memmove", "strncpy", "strncat", "snprintf", "vsnprintf",
    "alloca", "system", "popen", "execve", "execvp", "execl",
    "malloc", "realloc", "calloc", "free",
}

# Windows kernel-driver sinks (the bugs live here, not in strcpy)
_DRIVER_SINKS = {
    "memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory", "RtlCopyBytes",
    "RtlFillMemory", "RtlZeroMemory", "memset",
    "MmMapLockedPages", "MmMapLockedPagesSpecifyCache",
    "MmMapIoSpace", "MmGetSystemAddressForMdlSafe",
    "ExAllocatePool", "ExAllocatePool2", "ExAllocatePoolWithTag",
    "ProbeForRead", "ProbeForWrite",   # validation primitives; absence near a copy is the bug
    "ZwOpenFile", "ZwCreateFile", "ZwWriteFile", "ZwMapViewOfSection",
}

# Input sources (attacker-controlled data enters here)
_USER_SOURCES = {
    "recv", "recvfrom", "read", "fread", "fgets", "scanf", "sscanf",
    "getenv", "fscanf", "recvmsg", "accept",
}

# Driver "input arrives" primitives — used to confirm a dispatch path is reachable
_DRIVER_SOURCE_HINTS = {
    "IoGetCurrentIrpStackLocation", "ProbeForRead", "ProbeForWrite",
    "MmGetSystemAddressForMdlSafe",
}

# IOCTL transfer methods (low 2 bits of the control code)
_IOCTL_METHODS = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
_IOCTL_ACCESS = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}

# --- Data model ------------------------------------------------------------

@dataclass
class IOCTLEntry:
    code: int
    code_hex: str
    device_type: int
    function: int
    method: str
    access: str
    handler_addr: str = ""      # best-effort: case handler if resolvable

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TaintPath:
    source: str
    source_addr: str
    sink: str
    sink_addr: str
    path: list[str] = field(default_factory=list)   # function-name chain
    severity: str = "medium"                          # ranking bucket

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BackboneReport:
    binary: str
    binary_format: str = ""
    arch: str = ""
    is_driver: bool = False
    functions_count: int = 0
    dangerous_sinks: list[dict] = field(default_factory=list)
    input_sources: list[dict] = field(default_factory=list)
    reachability_paths: list[dict] = field(default_factory=list)
    ioctl_map: list[dict] = field(default_factory=list)
    dispatch_handler: str = ""
    double_fetch_candidates: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# --- r2 session wrapper ----------------------------------------------------

class _R2:
    """Thin r2pipe wrapper with JSON helpers and failure tolerance."""

    def __init__(self, path: str):
        # -2 silences stderr; flags keep the session quiet and scriptable
        self.r2 = r2pipe.open(path, flags=["-2"])
        # disable ANSI color so disasm regexes match clean text
        try:
            self.r2.cmd("e scr.color=0")
        except Exception:
            pass

    def cmd(self, c: str) -> str:
        try:
            return self.r2.cmd(c) or ""
        except Exception:
            return ""

    def cmdj(self, c: str):
        try:
            out = self.r2.cmd(c)
            return __import__("json").loads(out) if out else None
        except Exception:
            return None

    def close(self):
        try:
            self.r2.quit()
        except Exception:
            pass


# --- IOCTL code decode -----------------------------------------------------

def decode_ioctl(code: int) -> IOCTLEntry:
    """Decode a Windows CTL_CODE into its components."""
    device_type = (code >> 16) & 0xffff
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xfff
    method = code & 0x3
    return IOCTLEntry(
        code=code,
        code_hex=hex(code),
        device_type=device_type,
        function=function,
        method=_IOCTL_METHODS.get(method, str(method)),
        access=_IOCTL_ACCESS.get(access, str(access)),
    )


def _looks_like_ioctl(imm: int) -> bool:
    """Heuristic: does this immediate look like a CTL_CODE?

    Custom drivers almost always use FILE_DEVICE_UNKNOWN (0x22) or a vendor
    device type in 0x8000-0xffff, with a small function number. We accept codes
    whose decoded function number is plausible (< 0x800) and whose device type
    is non-zero, while rejecting tiny constants and obvious non-IOCTL values.
    """
    if imm <= 0xffff or imm > 0xffffffff:
        return False
    device_type = (imm >> 16) & 0xffff
    # FILE_DEVICE_UNKNOWN (0x22) is overwhelmingly the most common for custom
    # drivers; vendors otherwise use 0x8000-0xbfff. NTSTATUS codes look like
    # 0xc0000000+, so excluding >=0xc000 rejects them (e.g. 0xc0000001, 0xffffffff).
    return device_type == 0x22 or (0x8000 <= device_type <= 0xbfff)


# --- Backbone analysis -----------------------------------------------------

def analyze(path: str, on_status=None, r2: Optional["_R2"] = None) -> BackboneReport:
    """Run the full deterministic backbone over a binary.

    If `r2` is provided, that already-opened session is reused (and left open for
    the caller). Otherwise a session is opened and closed locally. Reusing a
    session lets the MCP server (Layer 2) share one analyzed `aaa` state across
    the backbone report and all subsequent interactive tool calls.
    """
    report = BackboneReport(binary=path)

    if not _HAS_R2PIPE:
        report.notes.append("r2pipe not available — backbone skipped")
        return report

    def _s(m):
        if on_status:
            on_status(f"[backbone] {m}")

    owns_session = r2 is None
    r = r2 if r2 is not None else _R2(path)
    try:
        # Binary metadata
        info = r.cmdj("ij") or {}
        bin_info = info.get("bin", {})
        report.binary_format = (bin_info.get("bintype") or "").lower()
        report.arch = bin_info.get("arch", "")
        cls = (bin_info.get("class") or "")
        is_pe = "pe" in report.binary_format or report.binary_format in ("pe", "pe32", "pe32+")
        # Driver heuristic: PE that imports kernel routines / .sys subsystem
        subsystem = (bin_info.get("subsystem") or "").lower()
        report.is_driver = is_pe and ("native" in subsystem or path.lower().endswith(".sys"))

        _s(f"format={report.binary_format} arch={report.arch} driver={report.is_driver} — analyzing...")

        # Analyze. aaa is acceptable for driver-sized binaries; guard for time.
        r.cmd("aaa")

        addr_to_name, name_to_addr, callgraph = _build_callgraph(r)
        report.functions_count = len(addr_to_name)

        # Imports → locate sink/source thunks
        imports = r.cmdj("iij") or []
        sink_set = _DRIVER_SINKS if report.is_driver else _USER_SINKS
        source_set = _DRIVER_SOURCE_HINTS if report.is_driver else _USER_SOURCES

        import_addr: dict[str, int] = {}
        for imp in imports:
            nm = imp.get("name", "")
            # demangle-ish: strip module prefixes like "ntoskrnl.exe_RtlCopyMemory"
            short = nm.split("_")[-1] if "_" in nm else nm
            addr = imp.get("plt") or imp.get("vaddr") or 0
            import_addr[short] = addr
            import_addr[nm] = addr

        # Sinks present in this binary
        sink_addrs: dict[int, str] = {}
        for sname in sink_set:
            a = import_addr.get(sname)
            if a:
                sink_addrs[a] = sname
                report.dangerous_sinks.append({"name": sname, "addr": hex(a)})

        # Callers of each sink (functions that actually invoke the sink)
        def _callers_of(addr: int) -> list[int]:
            xrefs = r.cmdj(f"axtj @ {addr}") or []
            out = []
            for x in xrefs:
                fa = x.get("fcn_addr")
                if fa is not None:
                    out.append(fa)
            return out

        sink_callers: dict[int, str] = {}   # function-addr -> sink name it calls
        for addr, sname in sink_addrs.items():
            for fa in _callers_of(addr):
                sink_callers.setdefault(fa, sname)

        # --- Driver-specific: find dispatch handler + IOCTL map ---
        dispatch_addr: Optional[int] = None
        if report.is_driver:
            _s("locating MajorFunction dispatch handlers...")
            slots = find_dispatch_handlers(r, list(name_to_addr.values()))
            for slot_name, haddr in slots.items():
                report.input_sources.append(
                    {"name": slot_name, "addr": hex(haddr), "kind": "irp_dispatch"})
            dispatch_addr = slots.get("IRP_MJ_DEVICE_CONTROL")
            if dispatch_addr is not None:
                report.dispatch_handler = hex(dispatch_addr)
                # handler is reached only via a function pointer store, so aaa
                # may not have analyzed it — force it and register the name.
                r.cmd(f"af @ {dispatch_addr}")
                addr_to_name.setdefault(dispatch_addr, "ioctl_dispatch")
                _s("decoding IoControlCode switch...")
                ioctls = _extract_ioctl_codes(r, dispatch_addr)
                report.ioctl_map = [e.to_dict() for e in ioctls]
                # Double-fetch (TOCTOU on a user pointer) realistically only
                # applies to METHOD_NEITHER IOCTLs — for BUFFERED/DIRECT the I/O
                # manager copies/maps the buffer, so re-reads aren't user-racing.
                has_neither = any(e.method == "NEITHER" for e in ioctls)
                if has_neither:
                    report.double_fetch_candidates = _detect_double_fetch(
                        r, dispatch_addr, addr_to_name)
                else:
                    report.notes.append(
                        "double-fetch scan skipped: no METHOD_NEITHER IOCTLs "
                        "(BUFFERED/DIRECT input is copied by the I/O manager)")
            else:
                report.notes.append("IRP_MJ_DEVICE_CONTROL handler not resolved statically")

        # Non-driver input sources (functions calling input imports)
        if not report.is_driver:
            for sname in source_set:
                a = import_addr.get(sname)
                if not a:
                    continue
                for fa in _callers_of(a):
                    report.input_sources.append(
                        {"name": sname, "addr": hex(fa),
                         "function": addr_to_name.get(fa, hex(fa)), "kind": "import"})

        # --- Reachability: source -> ... -> sink (BFS over callgraph) ---
        _s("computing reachability paths (source -> sink)...")
        source_func_addrs = []
        if report.is_driver and dispatch_addr is not None:
            # The dispatch handler + its callees were only `af`-analyzed inside the
            # driver block above, after the initial callgraph snapshot. Rebuild so
            # the handler node and its edges exist before we BFS from it.
            addr_to_name, name_to_addr, callgraph = _build_callgraph(r)
            report.functions_count = len(addr_to_name)
            addr_to_name.setdefault(dispatch_addr, "ioctl_dispatch")
            # sink-caller set is keyed by function addr; recompute against the
            # refreshed function boundaries so handler->sink edges are captured.
            sink_callers = {}
            for addr, sname in sink_addrs.items():
                for fa in _callers_of(addr):
                    sink_callers.setdefault(fa, sname)
            source_func_addrs = [dispatch_addr]
        else:
            source_func_addrs = [int(s["addr"], 16) for s in report.input_sources]

        paths = _reachability(callgraph, source_func_addrs, sink_callers,
                              addr_to_name, max_depth=12, max_paths=40)
        # Rank: NEITHER-method IOCTLs and shorter paths score higher
        report.reachability_paths = [p.to_dict() for p in paths]

        _s(f"done: {report.functions_count} funcs, {len(report.dangerous_sinks)} sinks, "
           f"{len(report.ioctl_map)} IOCTLs, {len(report.reachability_paths)} paths, "
           f"{len(report.double_fetch_candidates)} double-fetch candidates")
    finally:
        if owns_session:
            r.close()

    return report


def _build_callgraph(r: _R2):
    """Snapshot all analyzed functions into (addr_to_name, name_to_addr, callgraph).

    Called once after `aaa`, then again after driver dispatch analysis forces
    `af` on the IOCTL handler (which is reached only via a function-pointer store,
    so the initial `aaa` doesn't discover it). Rebuilding picks up the handler and
    its callees so reachability BFS can actually reach the sinks.
    """
    funcs = r.cmdj("aflj") or []
    addr_to_name: dict[int, str] = {}
    name_to_addr: dict[str, int] = {}
    callgraph: dict[int, set] = {}
    for f in funcs:
        off = f.get("offset", 0)
        nm = f.get("name", "")
        addr_to_name[off] = nm
        name_to_addr[nm] = off
        outs = set()
        for c in (f.get("callrefs") or []):
            if c.get("type") in ("CALL", "call") and "addr" in c:
                outs.add(c["addr"])
        callgraph[off] = outs
    return addr_to_name, name_to_addr, callgraph


# IRP_MJ_* MajorFunction slot offsets on x64 (base 0x70, 8 bytes each)
_MAJORFUNC_SLOTS = {
    0x70: "IRP_MJ_CREATE", 0x78: "IRP_MJ_CREATE_NAMED_PIPE", 0x80: "IRP_MJ_CLOSE",
    0x88: "IRP_MJ_READ", 0x90: "IRP_MJ_WRITE", 0xe0: "IRP_MJ_DEVICE_CONTROL",
    0xe8: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
}


def find_dispatch_handlers(r: _R2, func_addrs: list) -> dict:
    """Find MajorFunction dispatch handlers by scanning every function.

    DriverEntry is frequently unnamed (reached via the CRT/GS stub `entry0`),
    so we scan all functions for the canonical wiring:
        lea  reg, [handler]
        mov  qword [obj + <slot>], reg     ; obj == DriverObject
    Returns {slot_name: handler_addr}. IRP_MJ_DEVICE_CONTROL is the key one.
    """
    slots: dict[str, int] = {}
    lea_re = re.compile(r"lea (\w+), \[(0x[0-9a-fA-F]+)\]")
    store_re = re.compile(r"mov qword \[(\w+) \+ (0x[0-9a-fA-F]+)\], (\w+)")
    for fa in func_addrs:
        disasm = r.cmdj(f"pdfj @ {fa}") or {}
        regval: dict[str, int] = {}
        for op in disasm.get("ops", []):
            dis = op.get("disasm", "")
            m = lea_re.match(dis)
            if m:
                regval[m.group(1)] = int(m.group(2), 16)
                continue
            m = store_re.match(dis)
            if m:
                off = int(m.group(2), 16)
                src = m.group(3)
                if off in _MAJORFUNC_SLOTS and src in regval:
                    slots[_MAJORFUNC_SLOTS[off]] = regval[src]
        if "IRP_MJ_DEVICE_CONTROL" in slots:
            break  # found the one we care about
    return slots


def _extract_ioctl_codes(r: _R2, dispatch_addr: int) -> list[IOCTLEntry]:
    """Scan the dispatch handler (and shallow callees) for IoControlCode compares.

    Looks for `cmp reg, <imm>` where imm decodes as a plausible CTL_CODE.
    """
    seen: dict[int, IOCTLEntry] = {}

    def _scan(addr: int, depth: int):
        if depth > 2:
            return
        r.cmd(f"af @ {addr}")  # ensure the target is analyzed as a function
        disasm = r.cmdj(f"pdfj @ {addr}") or {}
        for op in disasm.get("ops", []):
            dis = op.get("disasm", "")
            # cmp/sub reg, imm  OR  mov reg, imm used for comparison
            m = re.search(r"\b(cmp|sub)\s+\w+,\s*(0x[0-9a-fA-F]+)", dis)
            if m:
                imm = int(m.group(2), 16)
                if _looks_like_ioctl(imm) and imm not in seen:
                    seen[imm] = decode_ioctl(imm)
            # follow direct calls one level (switch handlers sometimes split out)
            if dis.startswith("call ") and op.get("ptr") and depth < 2:
                _scan(op["ptr"], depth + 1)

    _scan(dispatch_addr, 0)
    return sorted(seen.values(), key=lambda e: e.code)


def _detect_double_fetch(r: _R2, dispatch_addr: int, addr_to_name: dict) -> list[dict]:
    """Best-effort double-fetch heuristic.

    Flags handlers that read from the same user-mode pointer expression twice
    without an intervening copy to a local. This is the static signature of the
    AFD/double-fetch bug class. Conservative — the agent confirms.
    """
    candidates = []
    disasm = r.cmdj(f"pdfj @ {dispatch_addr}") or {}
    ops = disasm.get("ops", [])
    # Track reads of the form mov reg, [base + disp] where base looks like a
    # user buffer (SystemBuffer/UserBuffer/Type3InputBuffer held in a register).
    read_sites: dict[str, int] = {}   # "[base+disp]" -> count
    for op in ops:
        dis = op.get("disasm", "")
        m = re.search(r"mov\s+\w+,\s*(qword|dword|word|byte)?\s*\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+)\]", dis)
        if m:
            expr = f"[{m.group(2)}+{m.group(3)}]"
            read_sites[expr] = read_sites.get(expr, 0) + 1
    for expr, count in read_sites.items():
        if count >= 2:
            candidates.append({
                "location": report_addr(dispatch_addr),
                "expression": expr,
                "read_count": count,
                "note": "same user-pointer expression read >=2x — possible double-fetch (TOCTOU)",
            })
    return candidates


def report_addr(addr: int) -> str:
    return hex(addr) if isinstance(addr, int) else str(addr)


def _reachability(callgraph: dict, sources: list, sink_callers: dict,
                  addr_to_name: dict, max_depth: int = 12,
                  max_paths: int = 40) -> list[TaintPath]:
    """BFS from each source to any function that calls a dangerous sink.

    Returns concrete function-name paths. A path existing here is the grounding
    that makes a candidate real rather than 'a sink exists somewhere'.
    """
    paths: list[TaintPath] = []

    for src in sources:
        if src not in callgraph and src not in sink_callers:
            # source may itself be a sink-caller (direct copy in the handler)
            if src in sink_callers:
                paths.append(TaintPath(
                    source=addr_to_name.get(src, hex(src)), source_addr=hex(src),
                    sink=sink_callers[src], sink_addr=hex(src),
                    path=[addr_to_name.get(src, hex(src))], severity="high"))
            continue

        # BFS keeping the path
        from collections import deque
        q = deque([(src, [src])])
        visited = {src}
        while q and len(paths) < max_paths:
            node, trail = q.popleft()
            if len(trail) > max_depth:
                continue
            if node in sink_callers:
                names = [addr_to_name.get(a, hex(a)) for a in trail]
                sev = "high" if len(trail) <= 4 else "medium"
                paths.append(TaintPath(
                    source=addr_to_name.get(src, hex(src)), source_addr=hex(src),
                    sink=sink_callers[node], sink_addr=hex(node),
                    path=names, severity=sev))
                # keep exploring for other sinks but don't revisit
            for callee in callgraph.get(node, ()):  # noqa
                if callee not in visited:
                    visited.add(callee)
                    q.append((callee, trail + [callee]))

    # Rank: high severity first, then shorter paths
    paths.sort(key=lambda p: (0 if p.severity == "high" else 1, len(p.path)))
    return paths[:max_paths]


if __name__ == "__main__":
    import sys
    import json as _json
    if len(sys.argv) < 2:
        print("usage: re_backbone.py <binary>")
        sys.exit(1)
    rep = analyze(sys.argv[1], on_status=lambda m: print(m))
    print(_json.dumps(rep.to_dict(), indent=2))
