"""Research engagement state model for vulnerability research / 0-day hunting.

Separate from the pentest Engagement (CTF/LE/RT). Different state model:
tracks audit coverage, sinks, bug candidates, crash corpus, PoCs, and variants
instead of hosts, credentials, and lateral movement.

Stored at: data/engagements/research/<target_name>/state.json
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from config import ENGAGEMENTS_DIR


# --- Target Profile ---

@dataclass
class TargetProfile:
    """Classification output from the TargetClassifier agent."""
    path: str = ""
    target_type: str = ""           # "source", "binary", "firmware", "protocol", "library"
    language: str = ""              # "c", "php", "python", "java", "node", "go", "rust", "unknown"
    arch: str = ""                  # "x86_64", "arm", "mips", "n/a"
    build_system: str = ""          # "cmake", "make", "npm", "pip", "cargo", "n/a"
    binary_format: str = ""         # "elf", "pe", "macho", "n/a"
    is_driver: bool = False         # Windows kernel-mode driver (.sys / native PE)
    has_symbols: bool = False
    file_count: int = 0
    estimated_loc: int = 0
    entry_points: list[str] = field(default_factory=list)
    recommended_pipeline: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "TargetProfile":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def summary_line(self) -> str:
        """One-line summary for display."""
        lang = self.language.upper() if self.language else "?"
        loc = f"{self.estimated_loc // 1000}K" if self.estimated_loc >= 1000 else str(self.estimated_loc)
        return f"{lang}, {self.arch or '?'}, {loc} LOC, {self.file_count} files"


# --- Exploitability scale ---

EXPLOITABILITY = {
    "weaponizable": "Full control of crash (controlled write, RIP overwrite). PoC likely.",
    "promising": "Partial control (heap corruption, type confusion). Needs analysis.",
    "interesting": "Crash confirmed but control unclear. Worth investigating.",
    "low_value": "NULL deref, stack exhaustion, assertion. Usually DoS only.",
    "false_positive": "Not a real bug (expected behavior, test artifact).",
}

POC_MATURITY = {
    "none": "No PoC yet.",
    "crash": "Triggers the bug, causes crash/DoS.",
    "controlled": "Demonstrates memory corruption with controlled values.",
    "weaponized": "Full exploit: code execution, auth bypass, or data exfil.",
}


# --- Bug display (user-friendly) ---

def format_bug(bug: dict) -> str:
    """Format a bug for plain-language display."""
    lines = []
    bug_id = bug.get("id", "?")
    cwe = bug.get("cwe", "")
    title = bug.get("title", bug.get("type", "Unknown"))
    cwe_str = f" ({cwe})" if cwe else ""
    lines.append(f"BUG-{bug_id}: {title}{cwe_str}")

    if bug.get("what"):
        lines.append(f"  WHAT:   {bug['what']}")
    if bug.get("location"):
        lines.append(f"  WHERE:  {bug['location']}")
    if bug.get("why"):
        lines.append(f"  WHY:    {bug['why']}")
    if bug.get("impact"):
        lines.append(f"  IMPACT: {bug['impact']}")

    status = bug.get("status", "candidate")
    expl = bug.get("exploitability", "")
    poc = bug.get("poc_status", "none")
    lines.append(f"  STATUS: {status.upper()}"
                 + (f" — {expl}" if expl else "")
                 + (f" | PoC: {poc}" if poc != "none" else ""))

    return "\n".join(lines)


# --- Research Engagement ---

class ResearchEngagement:
    """State model for a vulnerability research engagement."""

    def __init__(self, target_name: str = "", target_path: str = ""):
        self.target_name = target_name
        self.target_path = target_path
        self.engagement_mode = "research"
        self.profile = TargetProfile(path=target_path)

        # Audit coverage: {file_path: {total_functions, audited, sinks_found}}
        self.audit_coverage: dict[str, dict] = {}

        # Dangerous sinks identified by auditor
        # Each: {id, file, line, function, sink_type, confidence, data_flow}
        self.sinks: list[dict] = []

        # Bug candidates (pre-confirmation)
        # Each: {id, type, cwe, title, location, evidence, confidence,
        #        status (candidate/confirmed/false_positive), what, where, why, impact,
        #        data_flow, exploitability, poc_status}
        self.bug_candidates: list[dict] = []

        # Confirmed bugs (promoted from candidates)
        self.confirmed_bugs: list[dict] = []

        # Crash corpus from fuzzing
        # Each: {id, input_file, crash_type, stack_hash, stack_trace,
        #        exploitability, minimized, triaged, root_cause}
        self.crash_corpus: list[dict] = []

        # Variant candidates
        # Each: {id, original_bug_id, location, status (candidate/confirmed/fp), pattern}
        self.variants: list[dict] = []

        # PoC scripts
        # Each: {bug_id, script_path, maturity (none/crash/controlled/weaponized),
        #        tested, notes, mitigations_bypassed}
        self.pocs: list[dict] = []

        # Metrics
        self.total_cost: float = 0.0
        self.total_time_secs: float = 0.0

        # Pipeline state
        self.current_phase: str = "classify"
        self.pipeline: list[str] = []
        self.completed_phases: list[str] = []

        # Notes / operator observations
        self.notes: list[str] = []

        # Paths
        self._safe_name = (
            target_name.replace("/", "_").replace(".", "_")
            .replace(" ", "_").replace(":", "_")
        ) or "_blank"
        self.dir = ENGAGEMENTS_DIR / "research" / self._safe_name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / "state.json"

        # Subdirectories
        self.audit_dir = self.dir / "audit"
        self.fuzz_dir = self.dir / "fuzzing"
        self.triage_dir = self.dir / "triage"
        self.poc_dir = self.dir / "pocs"
        self.variant_dir = self.dir / "variants"
        for d in (self.audit_dir, self.fuzz_dir, self.triage_dir,
                  self.poc_dir, self.variant_dir):
            d.mkdir(exist_ok=True)

        # Fuzzing subdirs
        (self.fuzz_dir / "harness").mkdir(exist_ok=True)
        (self.fuzz_dir / "seeds").mkdir(exist_ok=True)
        (self.fuzz_dir / "corpus").mkdir(exist_ok=True)
        (self.fuzz_dir / "crashes").mkdir(exist_ok=True)

    # --- Bug management ---

    _bug_counter: int = 0

    def _next_bug_id(self) -> int:
        self._bug_counter += 1
        return self._bug_counter

    def add_bug_candidate(self, **kwargs) -> int:
        """Add a new bug candidate. Returns bug ID."""
        bug_id = self._next_bug_id()
        bug = {
            "id": bug_id,
            "status": "candidate",
            "exploitability": "",
            "poc_status": "none",
            "confidence": "medium",
            "discovered_at": datetime.now().isoformat(),
            **kwargs,
        }
        self.bug_candidates.append(bug)
        return bug_id

    def confirm_bug(self, bug_id: int, **updates) -> bool:
        """Promote a candidate to confirmed. Returns True if found."""
        for bug in self.bug_candidates:
            if bug["id"] == bug_id:
                bug["status"] = "confirmed"
                bug.update(updates)
                self.confirmed_bugs.append(bug)
                return True
        return False

    def mark_false_positive(self, bug_id: int, reason: str = "") -> bool:
        """Mark a candidate as false positive."""
        for bug in self.bug_candidates:
            if bug["id"] == bug_id:
                bug["status"] = "false_positive"
                if reason:
                    bug["fp_reason"] = reason
                return True
        return False

    def add_crash(self, **kwargs) -> int:
        """Add a crash to the corpus. Returns crash ID."""
        crash_id = len(self.crash_corpus) + 1
        crash = {
            "id": crash_id,
            "triaged": False,
            "minimized": False,
            "exploitability": "",
            "discovered_at": datetime.now().isoformat(),
            **kwargs,
        }
        self.crash_corpus.append(crash)
        return crash_id

    def add_poc(self, bug_id: int, script_path: str, maturity: str = "crash", **kwargs) -> None:
        """Register a PoC script for a confirmed bug."""
        self.pocs.append({
            "bug_id": bug_id,
            "script_path": script_path,
            "maturity": maturity,
            "tested": False,
            "created_at": datetime.now().isoformat(),
            **kwargs,
        })

    # --- Coverage tracking ---

    def update_coverage(self, file_path: str, total_functions: int,
                        audited: int, sinks_found: int) -> None:
        """Update audit coverage for a file."""
        self.audit_coverage[file_path] = {
            "total_functions": total_functions,
            "audited": audited,
            "sinks_found": sinks_found,
        }

    def coverage_pct(self) -> float:
        """Overall audit coverage percentage."""
        total = sum(c["total_functions"] for c in self.audit_coverage.values())
        audited = sum(c["audited"] for c in self.audit_coverage.values())
        if total == 0:
            return 0.0
        return (audited / total) * 100

    # --- Stats ---

    def unique_crashes(self) -> int:
        """Count of deduplicated crashes."""
        hashes = {c.get("stack_hash", c["id"]) for c in self.crash_corpus}
        return len(hashes)

    def crashes_by_exploitability(self) -> dict[str, int]:
        """Count crashes by exploitability rating."""
        counts: dict[str, int] = {}
        for c in self.crash_corpus:
            e = c.get("exploitability", "untriaged")
            counts[e] = counts.get(e, 0) + 1
        return counts

    def pocs_by_maturity(self) -> dict[str, int]:
        """Count PoCs by maturity level."""
        counts: dict[str, int] = {}
        for p in self.pocs:
            m = p.get("maturity", "none")
            counts[m] = counts.get(m, 0) + 1
        return counts

    # --- Dashboard ---

    def dashboard(self) -> dict:
        """Structured summary for display."""
        time_secs = self.total_time_secs
        mins, secs = divmod(int(time_secs), 60)
        time_str = f"{mins}m{secs:02d}s" if mins < 60 else f"{mins // 60}h{mins % 60:02d}m"

        candidates = len([b for b in self.bug_candidates if b["status"] == "candidate"])
        confirmed = len(self.confirmed_bugs)
        fps = len([b for b in self.bug_candidates if b["status"] == "false_positive"])

        crash_expl = self.crashes_by_exploitability()
        poc_mat = self.pocs_by_maturity()

        return {
            "target_name": self.target_name,
            "target_path": self.target_path,
            "profile": self.profile.summary_line() if self.profile.language else "Not classified",
            "phase": self.current_phase,
            "coverage": f"{self.coverage_pct():.0f}%",
            "coverage_detail": f"{sum(c['audited'] for c in self.audit_coverage.values())}"
                               f"/{sum(c['total_functions'] for c in self.audit_coverage.values())} functions",
            "sinks": len(self.sinks),
            "bugs_candidate": candidates,
            "bugs_confirmed": confirmed,
            "bugs_fp": fps,
            "crashes_total": len(self.crash_corpus),
            "crashes_unique": self.unique_crashes(),
            "crashes_weaponizable": crash_expl.get("weaponizable", 0),
            "crashes_promising": crash_expl.get("promising", 0),
            "variants": len(self.variants),
            "pocs_crash": poc_mat.get("crash", 0),
            "pocs_controlled": poc_mat.get("controlled", 0),
            "pocs_weaponized": poc_mat.get("weaponized", 0),
            "cost": f"${self.total_cost:.2f}",
            "time": time_str,
            "notes": len(self.notes),
        }

    def dashboard_display(self) -> str:
        """Formatted dashboard string for terminal output."""
        d = self.dashboard()
        lines = [
            f"TARGET:  {d['target_name']} ({d['profile']})",
            f"PATH:    {self.target_path}",
            f"PHASE:   {d['phase'].upper()}",
            "",
            f"COVERAGE:  {d['coverage']} ({d['coverage_detail']})",
            f"SINKS:     {d['sinks']} dangerous sinks identified",
            f"BUGS:      {d['bugs_candidate']} candidates / {d['bugs_confirmed']} confirmed / {d['bugs_fp']} false positives",
            f"CRASHES:   {d['crashes_total']} total / {d['crashes_unique']} unique / {d['crashes_weaponizable']} weaponizable / {d['crashes_promising']} promising",
            f"VARIANTS:  {d['variants']} candidates from confirmed bugs",
            f"POCs:      {d['pocs_crash']} crash / {d['pocs_controlled']} controlled / {d['pocs_weaponized']} weaponized",
            "",
            f"COST: {d['cost']} | TIME: {d['time']}",
        ]

        # Show confirmed bugs in plain language
        if self.confirmed_bugs:
            lines.append("")
            lines.append("--- CONFIRMED BUGS ---")
            for bug in self.confirmed_bugs:
                lines.append("")
                lines.append(format_bug(bug))

        return "\n".join(lines)

    # --- Serialization ---

    def _to_dict(self) -> dict:
        return {
            "target_name": self.target_name,
            "target_path": self.target_path,
            "engagement_mode": "research",
            "profile": self.profile.to_dict(),
            "audit_coverage": self.audit_coverage,
            "sinks": self.sinks,
            "bug_candidates": self.bug_candidates,
            "confirmed_bugs": self.confirmed_bugs,
            "crash_corpus": self.crash_corpus,
            "variants": self.variants,
            "pocs": self.pocs,
            "total_cost": self.total_cost,
            "total_time_secs": self.total_time_secs,
            "current_phase": self.current_phase,
            "pipeline": self.pipeline,
            "completed_phases": self.completed_phases,
            "notes": self.notes,
            "bug_counter": self._bug_counter,
            "saved_at": datetime.now().isoformat(),
        }

    def _from_dict(self, data: dict):
        self.target_name = data.get("target_name", "")
        self.target_path = data.get("target_path", "")
        self.profile = TargetProfile.from_dict(data.get("profile", {}))
        self.audit_coverage = data.get("audit_coverage", {})
        self.sinks = data.get("sinks", [])
        self.bug_candidates = data.get("bug_candidates", [])
        self.confirmed_bugs = data.get("confirmed_bugs", [])
        self.crash_corpus = data.get("crash_corpus", [])
        self.variants = data.get("variants", [])
        self.pocs = data.get("pocs", [])
        self.total_cost = data.get("total_cost", 0.0)
        self.total_time_secs = data.get("total_time_secs", 0.0)
        self.current_phase = data.get("current_phase", "classify")
        self.pipeline = data.get("pipeline", [])
        self.completed_phases = data.get("completed_phases", [])
        self.notes = data.get("notes", [])
        self._bug_counter = data.get("bug_counter", 0)

    def save(self):
        """Save state to disk."""
        self.state_path.write_text(json.dumps(self._to_dict(), indent=2))

    def load(self) -> bool:
        """Load state from disk. Returns True if loaded."""
        if not self.state_path.exists():
            return False
        data = json.loads(self.state_path.read_text())
        self._from_dict(data)
        return True
