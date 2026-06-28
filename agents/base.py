"""Base autonomous agent — shared execution logic for all specialist agents."""

import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST, MODEL_PLANNER, MAX_TURNS, TIMEOUT, EVIDENCE_DIR, ENGAGEMENTS_DIR, SUBTASK_MAX_TURNS, AGENT_MAX_TURNS, SOFT_TURN_LIMIT
from config import CTF_SYSTEM_PROMPT, CTF_AUTHORIZATION_HEADER
import config as _config
from retriever import KnowledgeBase
from opsec import score_command, LEVEL_HIGH
from findings_db import FindingsDB, Finding
from impact_evaluator import IMPACT_RUBRIC
from engagement_logger import EngagementLogger
from secret_vault import SecretVault


# --- Stuck detection ---

# AGENT_MAX_TURNS and SOFT_TURN_LIMIT imported from config.py


class StuckDetector:
    """Detects when an agent is grinding on the same approach without progress.

    Tracks command history and identifies patterns:
    - Repeated similar commands (same base command with minor variations)
    - Error→retry loops (same command after failure)
    - Escalating complexity without progress (commands getting longer/more escaped)
    - Strategic loops: too many turns on one attack category without findings
    - Incomplete enumeration: jumping to exploitation without finishing recon
    """

    # Attack category classifiers — order matters (first match wins).
    # Each entry: (category_name, list_of_compiled_regex_patterns)
    _ATTACK_CATEGORIES_RAW: list[tuple[str, list[str]]] = [
        ("sqli", [
            r"\bsqlmap\b", r"\bsql\s*injection\b", r"union\s+select",
            r"'\s*or\s+['\d]", r"'\s*and\s+['\d]", r"sleep\s*\(\s*\d",
            r"waitfor\s+delay", r"benchmark\s*\(", r"extractvalue\s*\(",
            r"updatexml\s*\(", r"order\s+by\s+\d+",
            r"-['\"].*--", r"' *;",  # trailing injection markers
        ]),
        ("brute_force", [
            r"\b(hydra|medusa|patator|spray)\b",
            r"\bcrackmapexec\b.*(-p|-u|--pass|--user)",
            r"\bnetexec\b.*(-p|-u|--pass|--user)",
            r"\bevil-winrm\b", r"\bwmiexec\b", r"\bpsexec\b",
            r"\bsmbclient\b.*-U", r"\brpcclient\b.*-U",
            r"\bcurl\b.*-d\b.*\b(password|passwd|pass|pwd)\b",  # login form brute force
        ]),
        # subdomain_enum MUST be before web_enum — ffuf with Host: header is subdomain enum
        # NOTE: patterns are matched against cmd.lower(), so use lowercase
        ("subdomain_enum", [
            r"\bffuf\b.*host:\s*fuzz", r"\bwfuzz\b.*host:",
            r"\bsubfinder\b", r"\bamass\b", r"\bgobuster\s+dns\b",
            r"\bgobuster\s+vhost\b", r"\bdnsrecon\b", r"\bfierce\b",
        ]),
        # param_tamper MUST be before web_enum — ffuf with ?FUZZ= is param fuzzing, not dir enum
        ("param_tamper", [
            # IDOR probing — changing IDs, comparing responses
            r"\bcurl\b.*[?&]id=\d", r"\bcurl\b.*[?&]user_id=",
            r"\bcurl\b.*[?&]account=", r"\bcurl\b.*[?&]uid=",
            # Parameter fuzzing with ffuf/wfuzz on query params
            r"\bffuf\b.*fuzz=", r"\bffuf\b.*\?fuzz",
            r"\bwfuzz\b.*fuzz=", r"\bwfuzz\b.*\?fuzz",
            # Arjun / param discovery tools
            r"\barjun\b", r"\bparam-miner\b",
            # Manual parameter probing (curl with query params that aren't SQLi)
            r"\bcurl\b.*[?&](token|key|api_key|session)=",
            r"\bcurl\b.*[?&](file|path|filename|document)=",
            r"\bcurl\b.*[?&](redirect|url|next|goto|dest)=",
        ]),
        ("web_enum", [
            r"\b(gobuster|feroxbuster|dirb|dirsearch)\b",
            r"\bffuf\b", r"\bwfuzz\b",
            r"\bnuclei\b", r"\bnikto\b",
            r"\bcurl\b.*-[sI]\b.*/(robots|sitemap|\.env|\.git|wp-)",
        ]),
        ("port_scan", [
            r"\bnmap\b", r"\bmasscan\b", r"\brusscan\b",
            r"\bnc\b.*-z", r"\bnetcat\b",
        ]),
        ("xss", [
            r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
            r"alert\s*\(", r"document\.cookie", r"<img\s+src\s*=",
        ]),
        ("lfi_rfi", [
            r"\.\./\.\./", r"etc/passwd", r"etc/shadow",
            r"php://filter", r"php://input", r"data://",
            r"file://", r"expect://",
        ]),
        ("ssti", [
            r"\{\{.*\}\}", r"\{%.*%\}", r"\$\{.*\}",
            r"__class__", r"__mro__", r"__subclasses__",
        ]),
        ("cve_exploit", [
            r"\bsearchsploit\b", r"\bmetasploit\b", r"\bmsfconsole\b",
            r"\bpoc\b", r"\bexploit[-/]", r"CVE-\d{4}-\d+",
        ]),
        # cloud_escape MUST be before cloud_exploit — escape-specific patterns
        # are more specific than general AWS CLI commands
        ("cloud_escape", [
            # Container escape vectors
            r"docker\.sock", r"/var/run/docker", r"\bnsenter\b",
            r"mount.*cgroup", r"release_agent", r"notify_on_release",
            r"/proc/sys/kernel/modprobe", r"/proc/sys/kernel/core_pattern",
            r"\bupperdir\b", r"\boverlay\b.*mount",
            # Cloud-to-host escape
            r"hot-reload", r"hot\.reload", r"lambda.*layer",
            r"volume.*mount", r"mountpoints", r"privilegedmode",
            # Namespace escape
            r"/proc/1/root", r"/proc/\d+/ns/", r"\bunshare\b", r"\bsetns\b",
        ]),
        ("cloud_exploit", [
            r"\baws\b\s+(sqs|s3|sts|iam|secretsmanager|ssm|lambda|ec2)",
            r"\bboto3\b", r"\blocalstack\b",
            r"169\.254\.169\.254", r"metadata.*iam",
            r"\baws\b.*send-message", r"\baws\b.*get-object",
            r"\baws\b.*put-object", r"\baws\b.*receive-message",
        ]),
        ("post_exploit", [
            r"\bpython3?\b\s+-c\b", r"\bperl\b\s+-e\b",
            r"\bruby\b\s+-e\b", r"\bnode\b\s+-e\b",
            r"\bbase64\s+-d\b.*\|\s*(bash|sh|python)",
            r"\brev(erse)?\s*shell\b", r"\bnc\b.*-e\b",
            r"\bmkfifo\b", r"\b/dev/tcp/",
            r"import\s+socket.*connect", r"import\s+subprocess",
            r"\bcurl\b.*\|\s*(bash|sh|python)",
            r"\bwget\b.*-O\s*-\s*\|\s*(bash|sh)",
        ]),
        ("ssrf", [
            r"\bcurl\b.*\burl=", r"gopher://",
            r"dict://", r"\bssrf\b",
            r"\bcurl\b.*localhost:\d+",
            r"\bcurl\b.*127\.0\.0\.1",
            r"\bcurl\b.*\bfetch\b.*url",
        ]),
        ("recon_general", [
            r"\bcurl\b.*-[sIvk]", r"\bwget\b",
            r"\bwhatweb\b", r"\bwappalyzer\b",
        ]),
    ]

    # Pre-compiled attack category patterns (compiled once at class load)
    _ATTACK_CATEGORIES: list[tuple[str, list[re.Pattern]]] = [
        (cat, [re.compile(p) for p in patterns])
        for cat, patterns in _ATTACK_CATEGORIES_RAW
    ]

    # Per-category turn limits — complex exploit categories get more room before pivot.
    _CATEGORY_TURN_LIMITS: dict[str, int] = {
        "port_scan": 3,
        "recon_general": 4,
        "web_enum": 4,
        "subdomain_enum": 4,
        "param_tamper": 5,
        "xss": 5,
        "lfi_rfi": 6,
        "brute_force": 5,
        "cve_exploit": 6,
        "sqli": 8,
        "ssti": 6,
        "cloud_escape": 5,
        "cloud_exploit": 6,
        "post_exploit": 7,
        "ssrf": 5,
    }
    # Fallback for categories not listed above
    CATEGORY_TURN_LIMIT = int(os.getenv("REDOPS_CATEGORY_TURNS", "5"))

    # Minimum recon categories that should be attempted before heavy exploitation.
    # param_tamper is recon-tier: you should probe parameters BEFORE trying injection.
    _RECON_CATEGORIES = {"port_scan", "web_enum", "subdomain_enum", "param_tamper"}
    _EXPLOIT_CATEGORIES = {"sqli", "brute_force", "xss", "lfi_rfi", "ssti", "cve_exploit",
                           "cloud_escape", "cloud_exploit", "post_exploit", "ssrf"}

    def __init__(self, agent_name: str, engagement_dir: Path | None = None):
        self.agent_name = agent_name
        self._engagement_dir = engagement_dir  # per-engagement isolation
        self.commands: list[str] = []
        self.error_count: int = 0
        self.last_error: str = ""
        self.pivot_warnings_sent: int = 0
        self._similar_streak: int = 0
        # Strategic tracking: category → list of turn numbers
        self.category_turns: dict[str, list[int]] = {}
        # Categories that have been explicitly pivoted away from
        self.exhausted_categories: set[str] = set()
        # Whether we've warned about incomplete recon
        self._recon_warning_sent: bool = False
        # Milestone counter — reset per dispatch, tracks progress to gate Pattern 6
        self._milestones_at_check: int = 0

    def to_dict(self) -> dict:
        """Serialize detector state for persistence across dispatches."""
        return {
            "category_turns": {k: v for k, v in self.category_turns.items()},
            "exhausted_categories": sorted(self.exhausted_categories),
            "pivot_warnings_sent": self.pivot_warnings_sent,
            "error_count": self.error_count,
            "total_commands": len(self.commands),
            "recon_warning_sent": self._recon_warning_sent,
        }

    @classmethod
    def from_dict(cls, agent_name: str, data: dict, engagement_dir: Path | None = None) -> "StuckDetector":
        """Restore detector state from persisted data."""
        sd = cls(agent_name, engagement_dir)
        sd.category_turns = {k: v for k, v in data.get("category_turns", {}).items()}
        sd.exhausted_categories = set(data.get("exhausted_categories", []))
        sd.pivot_warnings_sent = data.get("pivot_warnings_sent", 0)
        sd.error_count = data.get("error_count", 0)
        sd._recon_warning_sent = data.get("recon_warning_sent", False)
        return sd

    def _persist_path(self) -> Path:
        """Path to persisted detector state.

        If engagement_dir is set, stores per-engagement (isolated).
        Otherwise falls back to global ENGAGEMENTS_DIR (legacy).
        """
        base = self._engagement_dir or ENGAGEMENTS_DIR
        return base / f"_stuck_{self.agent_name}.json"

    def save(self) -> None:
        """Persist current state to disk."""
        try:
            self._persist_path().parent.mkdir(parents=True, exist_ok=True)
            self._persist_path().write_text(json.dumps(self.to_dict(), indent=2))
        except Exception:
            pass

    @classmethod
    def load(cls, agent_name: str, engagement_dir: Path | None = None) -> "StuckDetector":
        """Load persisted state, or return a fresh detector if none exists.

        Args:
            agent_name: Agent identifier (e.g., "interactive", "recon")
            engagement_dir: Per-engagement directory for isolated state.
                           If None, uses global ENGAGEMENTS_DIR (legacy).
        """
        base = engagement_dir or ENGAGEMENTS_DIR
        path = base / f"_stuck_{agent_name}.json"
        try:
            if path.exists():
                data = json.loads(path.read_text())
                return cls.from_dict(agent_name, data, engagement_dir)
        except Exception:
            pass
        return cls(agent_name, engagement_dir)

    @staticmethod
    def _normalize_cmd(cmd: str) -> str:
        """Normalize a command to detect similarity (strip IPs, quotes, payloads)."""
        # Strip leading whitespace, collapse spaces
        c = re.sub(r"\s+", " ", cmd.strip())
        # Normalize IPs/ports to placeholders
        c = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP", c)
        c = re.sub(r":\d{2,5}", ":PORT", c)
        # Normalize ALL quoted/escaped content — this is what varies in stuck loops
        # Replace entire quoted strings and their content
        c = re.sub(r""""[^"]*" """, "QSTR", c)
        c = re.sub(r"""'[^']*'""", "QSTR", c)
        # Collapse remaining escape chars
        c = re.sub(r"""[\\'"`;]+""", "Q", c)
        # Normalize -d/--data payloads (common in web exploit loops)
        c = re.sub(r"(-d|--data|--data-raw|--data-binary)\s*\S+", r"\1 PAYLOAD", c)
        # Take first 60 chars as the "signature" — shorter to catch base command pattern
        return c[:60].lower()

    def _classify_command(self, cmd: str) -> str | None:
        """Classify a command into an attack category. Returns None if unclassifiable."""
        cmd_lower = cmd.lower()
        for category, compiled_patterns in self._ATTACK_CATEGORIES:
            for pat in compiled_patterns:
                if pat.search(cmd_lower):
                    return category
        return None

    def record_command(self, cmd: str) -> None:
        """Record a command execution and classify it."""
        self.commands.append(cmd)
        turn = len(self.commands)
        category = self._classify_command(cmd)
        if category:
            self.category_turns.setdefault(category, []).append(turn)

    def record_error(self, error_text: str) -> None:
        """Record a tool error/failure."""
        self.error_count += 1
        self.last_error = error_text[:200]

    def check(self, turn: int) -> str | None:
        """Check for stuck patterns. Returns a pivot message if stuck, None if OK.

        Called after each tool_result. Returns a message that should be shown
        to the operator (in verbose mode) and can inform the on_progress callback.
        """
        if len(self.commands) < 3:
            return None

        # --- Pattern 1: Similar command repetition ---
        # Look at the last 8 commands and check if 5+ share the same normalized form.
        # Exception: short commands (<60 chars) are likely filter probing (intentional),
        # not stuck grinding. Stuck grinding produces long, complex commands.
        recent = self.commands[-8:]
        normalized = [self._normalize_cmd(c) for c in recent]
        from collections import Counter
        cmd_counts = Counter(normalized)
        most_common_cmd, most_common_count = cmd_counts.most_common(1)[0]

        if most_common_count >= 5:
            # Check if these are short probing commands vs long stuck payloads
            matching_cmds = [c for c, n in zip(recent, normalized) if n == most_common_cmd]
            avg_len = sum(len(c) for c in matching_cmds) / len(matching_cmds)

            if avg_len > 80:
                # Long commands = stuck grinding, not probing
                self.pivot_warnings_sent += 1
                return (
                    f"STUCK DETECTED: {most_common_count} similar commands in last {len(recent)} attempts "
                    f"(avg length: {avg_len:.0f} chars). "
                    f"The agent is repeating variations of the same complex payload. "
                    f"Pattern: '{most_common_cmd[:50]}...'"
                )
            elif most_common_count >= 7:
                # Even short commands — if 7+ are identical, something is wrong
                self.pivot_warnings_sent += 1
                return (
                    f"STUCK DETECTED: {most_common_count} near-identical short commands. "
                    f"If probing a filter, you should have mapped it by now. "
                    f"Pattern: '{most_common_cmd[:50]}...'"
                )

        # --- Pattern 2: Quoting/escaping rabbit hole ---
        # Catches two cases:
        # a) Strictly escalating escape complexity (each command more escaped than the last)
        # b) Sustained high escape count (4+ commands all heavily escaped = grinding on encoding)
        if len(self.commands) >= 4:
            recent_cmds = self.commands[-4:]
            escape_counts = [len(re.findall(r"""[\\'"`;]""", c)) for c in recent_cmds]

            # Case a: strictly escalating
            if (all(escape_counts[i] < escape_counts[i + 1] for i in range(len(escape_counts) - 1))
                    and escape_counts[-1] > 8):
                self.pivot_warnings_sent += 1
                return (
                    f"STUCK DETECTED: Escalating escape complexity across {len(recent_cmds)} commands "
                    f"(escape chars: {escape_counts}). This is a quoting rabbit hole — "
                    f"each fix at one layer is breaking another."
                )

            # Case b: sustained high escaping — all 4+ commands have >8 escape chars
            if all(c > 8 for c in escape_counts):
                self.pivot_warnings_sent += 1
                return (
                    f"STUCK DETECTED: {len(recent_cmds)} consecutive heavily-escaped commands "
                    f"(escape chars: {escape_counts}). You are stuck in an encoding loop. "
                    f"Map the filter with simple probes, or write a script to avoid escaping."
                )

        # --- Pattern 3: High error rate ---
        if turn >= 8 and self.error_count >= turn * 0.5:
            self.pivot_warnings_sent += 1
            return (
                f"STUCK DETECTED: {self.error_count} errors in {turn} turns ({self.error_count*100//turn}% failure rate). "
                f"Last error: {self.last_error[:100]}"
            )

        # --- Pattern 4: Strategic loop (same attack category too long) ---
        # This catches the case where every command is syntactically different
        # but strategically repetitive (e.g., SQLi on 5 different endpoints).
        # Per-category limits: complex categories (sqli, cve_exploit) get more room.
        for category, turns_list in self.category_turns.items():
            if category in self.exhausted_categories:
                continue
            cat_limit = self._CATEGORY_TURN_LIMITS.get(category, self.CATEGORY_TURN_LIMIT)
            if len(turns_list) >= cat_limit:
                self.exhausted_categories.add(category)
                self.pivot_warnings_sent += 1

                # Build a summary of what other categories have been tried
                other_tried = [
                    f"{cat}({len(t)})"
                    for cat, t in self.category_turns.items()
                    if cat != category and t
                ]
                tried_str = ", ".join(other_tried) if other_tried else "none"

                # Suggest untried categories
                all_categories = {cat for cat, _ in self._ATTACK_CATEGORIES}
                tried_categories = set(self.category_turns.keys())
                untried = all_categories - tried_categories
                suggest_str = ", ".join(sorted(untried)[:4]) if untried else "all categories attempted"

                if category == "cloud_escape":
                    return (
                        f"CONTAINER/CLOUD ESCAPE EXHAUSTED: {len(turns_list)} turns spent on "
                        f"container/cloud escape vectors without breakthrough. STOP.\n"
                        f"  Before trying more escape vectors:\n"
                        f"  (1) Check if the objective (flag/target file) exists in your CURRENT "
                        f"container: `find / -name root.txt -o -name user.txt 2>/dev/null`. "
                        f"Permission denied = file IS HERE, escalate locally.\n"
                        f"  (2) Check if you can create a PRIVILEGED container via cloud APIs "
                        f"(CodeBuild privilegedMode, ECS with capabilities). A new privileged "
                        f"container is often the intended path, not escaping the current "
                        f"unprivileged one.\n"
                        f"  Other categories tried: {tried_str}\n"
                        f"  MANDATORY: Your next command must NOT be in the '{category}' category."
                    )

                return (
                    f"STRATEGIC LOOP DETECTED: {len(turns_list)} turns spent on '{category}' "
                    f"without breakthrough. This attack class is exhausted — STOP trying "
                    f"variations and pivot to a fundamentally different approach.\n"
                    f"  Other categories tried: {tried_str}\n"
                    f"  Untried categories to consider: {suggest_str}\n"
                    f"  MANDATORY: Your next command must NOT be in the '{category}' category."
                )

        # --- Pattern 5: Incomplete recon before exploitation ---
        # Detect when the agent is grinding on exploit categories without having
        # done basic enumeration (subdomain enum, directory brute-force, etc.)
        if not self._recon_warning_sent and turn >= 6:
            exploit_turns = sum(
                len(t) for cat, t in self.category_turns.items()
                if cat in self._EXPLOIT_CATEGORIES
            )
            recon_done = {
                cat for cat in self._RECON_CATEGORIES
                if cat in self.category_turns and len(self.category_turns[cat]) >= 1
            }
            recon_missing = self._RECON_CATEGORIES - recon_done

            # If >4 exploit turns but missing recon categories, warn
            if exploit_turns > 4 and recon_missing:
                self._recon_warning_sent = True
                missing_str = ", ".join(sorted(recon_missing))
                return (
                    f"RECON INCOMPLETE: You've spent {exploit_turns} turns on exploitation "
                    f"but haven't completed basic enumeration. Missing: {missing_str}. "
                    f"Exploitation without thorough enumeration is a common reason for "
                    f"getting stuck — you may be missing the actual attack surface. "
                    f"Complete enumeration before continuing exploitation attempts."
                )

        # --- Pattern 6: Cross-category grinding without milestones ---
        # Catches the case where the agent cycles through multiple categories
        # (e.g., cloud_exploit → post_exploit → ssrf → cloud_exploit) without
        # any engagement milestone (new creds, new host, flag). Each category
        # stays under its limit, but total turns burned is excessive.
        total_classified = sum(len(t) for t in self.category_turns.values())
        if turn >= 10 and total_classified >= 8:
            active_cats = [cat for cat, t in self.category_turns.items()
                           if len(t) >= 2 and cat not in self.exhausted_categories]
            if len(active_cats) >= 2:
                milestones = self._milestones_at_check
                if milestones == 0:
                    cats_str = ", ".join(f"{c}({len(self.category_turns[c])})" for c in active_cats)
                    self.pivot_warnings_sent += 1
                    return (
                        f"STRATEGIC LOOP DETECTED: {total_classified} classified turns across "
                        f"{len(active_cats)} categories ({cats_str}) with no engagement milestone "
                        f"(no new credentials, compromised hosts, or flags). "
                        f"The agent is cycling between approaches that all fail. "
                        f"MANDATORY: Write a standalone script to automate the current exploit chain, "
                        f"or pivot to a completely different attack vector."
                    )

        return None

    def record_milestone(self) -> None:
        """Record that a meaningful engagement milestone occurred (cred found, host compromised, etc.)."""
        self._milestones_at_check += 1

    def approach_summary(self) -> str:
        """Return a structured summary of approaches tried, for injection into prompts."""
        if not self.category_turns:
            return ""
        lines = ["## Approaches Tried (auto-tracked)"]
        for category, turns_list in sorted(self.category_turns.items(), key=lambda x: -len(x[1])):
            exhausted = " [EXHAUSTED — pivot away]" if category in self.exhausted_categories else ""
            lines.append(f"- {category}: {len(turns_list)} turns{exhausted}")
        if self.exhausted_categories:
            lines.append(f"\nDO NOT retry: {', '.join(sorted(self.exhausted_categories))}")
        return "\n".join(lines)

_kb = None


def _get_kb():
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb


class BaseAgent:
    """Base class for autonomous specialist agents.

    Subclasses must set:
        AGENT_NAME: str       — short identifier (e.g. "recon")
        SYSTEM_PROMPT: str    — full system prompt for this specialist
        ALLOWED_TOOLS: str    — comma-separated Claude CLI tools
        RAG_QUERIES: list[str] — default knowledge base queries for context
    """

    AGENT_NAME: str = "base"
    SYSTEM_PROMPT: str = ""
    ALLOWED_TOOLS: str = "Bash,Read,Glob,Grep"
    RAG_QUERIES: list[str] = []
    USE_FAST_MODEL: bool = False  # Set True for parsing/analysis agents (uses MODEL_FAST)
    USE_PLANNER_MODEL: bool = False  # Set True for triage/planning agents (uses MODEL_PLANNER / sonnet)
    SUBTASK_MAX_TURNS: int = SUBTASK_MAX_TURNS  # Turn limit when running as a subtask

    def __init__(self, engagement_state, autonomous: bool = True):
        self.state = engagement_state
        self.autonomous = autonomous
        self._session_id: str = ""
        self.results: list[dict] = []  # Structured findings from this agent
        self.opsec_log: list[dict] = []
        self._last_cost: float = 0
        self._last_turns: int = 0
        self.findings_db = FindingsDB()
        # Per-engagement logger
        _eng_dir = getattr(engagement_state, "dir", _config.ENGAGEMENTS_DIR / "_blank")
        _eng_mode = getattr(engagement_state, "engagement_mode", "ctf")
        self._log = EngagementLogger(_eng_dir, _eng_mode)
        # Secret vault — shared with interactive agent via same engagement dir
        _vault_enabled = _eng_mode in ("le", "redteam")
        self._vault = SecretVault(_eng_dir, enabled=_vault_enabled)
        # Try to restore session from last run
        self._load_session()

    def add_finding(self, **kwargs) -> int:
        """Convenience method to add a finding with agent name auto-set."""
        kwargs.setdefault("agent", self.AGENT_NAME)
        return self.findings_db.add(Finding(**kwargs))

    def _session_path(self) -> Path:
        """Path to this agent's persisted session file."""
        return ENGAGEMENTS_DIR / f"_agent_{self.AGENT_NAME}.json"

    def _save_session(self):
        """Persist session ID and last results summary to disk.

        Only saves if the session produced at least 1 turn — stale/dead
        sessions cause silent failures on resume (0 turns, no output).
        """
        if self._last_turns < 1 or not self._session_id:
            # Don't persist dead sessions — they'll cause --resume to fail silently
            try:
                path = self._session_path()
                if path.exists():
                    path.unlink()
            except Exception:
                pass
            return
        try:
            data = {
                "session_id": self._session_id,
                "last_cost": self._last_cost,
                "last_turns": self._last_turns,
                "results_count": len(self.results),
                "last_response_preview": (
                    self.results[-1]["response"][:500] if self.results else ""
                ),
                "time": datetime.now().isoformat(),
            }
            self._session_path().write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _load_session(self):
        """Restore session ID from disk if available.

        Skips sessions that had 0 turns (dead/stale) to prevent silent
        --resume failures.
        """
        try:
            path = self._session_path()
            if path.exists():
                data = json.loads(path.read_text())
                turns = data.get("last_turns", 0)
                if turns < 1:
                    # Stale session — remove it
                    path.unlink(missing_ok=True)
                    return
                self._session_id = data.get("session_id", "")
        except Exception:
            pass

    @staticmethod
    def _sanitize(text: str) -> str:
        text = text.replace("\x00", "")
        return "".join(
            ch for ch in text
            if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127)
        )

    def _retrieve_context(self, extra_queries: list[str] | None = None,
                           task_text: str = "") -> str:
        """Pull relevant KB material for this agent's specialty.

        Uses batch_search to send all queries to ChromaDB in a single call,
        avoiding per-query embedding overhead.  When *task_text* is provided,
        decomposes it into keyword sub-queries (via the retriever's term
        extraction) so task-specific content is retrieved alongside the
        agent's static RAG_QUERIES.
        """
        try:
            kb = _get_kb()
            from retriever import decompose_query
            queries = list(extra_queries or []) + self.RAG_QUERIES
            # Also search the task text itself so task-specific topics
            # (e.g. BYOVD, AI attacks) get retrieved even when the agent's
            # static RAG_QUERIES don't mention them.
            if task_text:
                queries.extend(decompose_query(task_text))
            if not queries:
                return ""
            # Single batched call instead of N sequential multi_search calls
            scope = getattr(self.state, "engagement_id", None)
            mode = getattr(self.state, "engagement_mode", None)
            hits = kb.batch_search(queries, n_results=6, scope=scope, mode=mode)
            if hits:
                return self._sanitize(kb.format_context(hits[:6]))
        except Exception:
            pass
        return ""

    # Injected into every agent's prompt — anti-stuck and strategy-pivot guidance
    _ANTI_STUCK_PROMPT = """
## MICRO-AGENT MODE — 3 TURNS MAX
Execute the specific task, report results, stop. 1-2 commands max.

**Execution discipline:**
- If a command fails, DIAGNOSE the error before moving on. Common fixable causes:
  - Clock skew → `sudo ntpdate TARGET_IP` then retry
  - Permission denied on Kali → add `sudo`
  - Connection refused → check if listener/service is running
  - Wrong format/encoding → fix the input, don't switch tools
- Do NOT abandon a technique because of a fixable error. Fix the error, retry ONCE.
- Only abandon if the error is fundamental (access denied by target policy, not misconfiguration).

**Efficiency:**
- If you have indirect execution (DLL hijack, scheduled task, cron), batch ALL checks
  into ONE payload. Don't deploy → wait → check one thing → redeploy → wait → check another.
- Validate your setup BEFORE triggering a slow execution chain (test SMB/HTTP listeners
  locally, verify file permissions before uploading).
- You have full sudo on Kali. Use it without hesitation.
- **NEVER run blocking/listener commands inline.** These will HANG FOREVER:
  `responder`, `nc -l`, `python3 -m http.server`, `impacket-ntlmrelayx`,
  `impacket-smbserver`, `socat LISTEN`, any command that waits for inbound connections.
  ALWAYS background them: `sudo responder -I tun0 &`, `nc -lvnp 4444 &`
  Then check results with: `cat /tmp/responder.log`, `jobs`, `ss -tlnp`
  If you need to wait for a callback: `command & sleep 30 && check_result`
- **Tool keeps crashing (3+ restarts)?** Check stderr/logs for WHY. If unfixable in 1 turn,
  ABANDON the tool and use a different approach. Do not restart in a loop.
- **ERROR_BAD_NETPATH from coercion** = target cannot reach your IP via SMB. Outbound SMB
  is firewalled. Stop retrying coercion via SMB. Try HTTP or abandon relay entirely.
- **Outbound blocked from target?** If you confirmed the target cannot reach your IP
  (ERROR_BAD_NETPATH, connection timeout, no callback), then ALL of these are dead:
  NTLM relay, coerced auth, reverse shells, download cradles, SMB server hash capture,
  Responder, HTTP callbacks. Do NOT retry any of them. Use only:
  file upload via WinRM/SMB, DLL hijack with file-based output, on-target tools only.
"""

    # === ENGAGEMENT MODE PROMPTS (mutually exclusive) ===

    _CTF_MODE_PROMPT = """
## CTF LAB CHALLENGE MODE
This is an authorized lab challenge on intentionally vulnerable infrastructure.
A valid solution path exists — persistence and creative technique chaining will find it.

### Login Simulation Protection (NON-NEGOTIABLE)
Login simulations trigger logon scripts and credential capture. Breaking them requires a box reset.

**Do NOT:**
- Set scriptPath to a UNC path on the attack machine (SMB timeout kills simulation)
- Use logon scripts that make outbound network connections or take >5 seconds
- Deploy complex payloads before testing a minimal one

**Do:**
- Use NETLOGON-relative paths only (e.g., `logon.bat`)
- Write output to SYSVOL scripts directory or LDAP attributes
- First attempt: `whoami > output.txt` only. Verify simulation still runs before expanding.
- Check lastLogon timestamp after every script change. If it stops advancing, revert immediately.

### Integrity Rules — ENFORCED (violation kills your session)
Anti-cheat is active. Commands matching blocked patterns terminate the session immediately.
- Do NOT access writeups, walkthroughs, or solution guides for any CTF/HTB target
- Do NOT access AI chatbots (ChatGPT, Gemini, Claude, Perplexity, Phind, You.com)
- Do NOT search Google/Bing/DuckDuckGo for box solutions, walkthroughs, or hints
- Do NOT access HTB forums, 0xdf, IppSec, InfoSecWriteups, Reddit solution threads, or writeup blogs
- Allowed: tool documentation, man pages, exploit-db, CVE databases, HackTricks, GTFOBins, PayloadsAllTheThings, tool repos

### Flag Location Pre-Check (do BEFORE choosing attack strategy)
When you have code execution in any context (container, Lambda, CodeBuild, VM):
```
find / -name root.txt -o -name user.txt -o -name flag.txt 2>/dev/null
ls -la /root/ /home/ 2>/dev/null
```
"Permission denied" = the file IS HERE. Escalate locally, do NOT escape to host/another
container. Only pursue container escape if the flag does NOT exist in your current context.

### Methodology
- Every service/configuration exists for a reason — unusual configs are likely the path
- If obvious paths are exhausted, chain techniques (synthesis agent exists for this)
- Execute commands and analyze output. Minimize planning monologues — bias toward action.
- Describe findings in technical terms: file permissions, binary capabilities, service configs.

### Objectives — STOP WHEN DONE
- Capture flags: user.txt and root.txt. Once BOTH are captured, STOP.
- Do NOT establish persistence, enumerate further, or create unnecessary artifacts after flags.
- Every action after capturing flags wastes turns and budget.
"""

    _LE_MODE_PROMPT = """
## LIVE ENVIRONMENT MODE — Bug Bounty / Penetration Test
This is a REAL target. Vulnerabilities may or may NOT exist.

**Rules of engagement:**
- Operate within defined scope STRICTLY — do not test out-of-scope assets
- Document ALL findings using the standard finding template (see CLAUDE.md)
- Report vulnerabilities with proper severity ratings (CVSS 3.1)
- Provide actionable remediation guidance
- Collect evidence (screenshots, request/response pairs, PoC commands)
- Test for impact but do NOT cause damage or disruption

**PoC requirements (MANDATORY for all findings):**
Every finding MUST include a reproducible proof-of-concept. A finding without a PoC is
not a finding — it's a guess.
- For each vulnerability discovered, immediately attempt to create a working PoC
- PoC format: a single curl command, script, or step-by-step request sequence that
  an operator can replay to reproduce the issue
- If you CAN reproduce it: include the exact command and its output as evidence
- If you CANNOT reproduce it: clearly state this in the finding. Label it as
  UNCONFIRMED and describe exactly what the operator needs to do to verify it
  (tools, auth state, timing, browser requirements)
- Never claim a vulnerability is confirmed without running a PoC yourself
- Save PoC scripts to the evidence directory as executable .sh files

**Assumptions:**
- The target MAY be fully patched and secure — "no findings" is a valid result
- Not every service is exploitable — prioritize based on real risk, not CTF logic
- False positives are worse than missed findings in bug bounty context
- Time-box techniques — if a vector isn't yielding after thorough testing, move on

**Objectives:**
- Identify and document all exploitable vulnerabilities within scope
- Provide reproducible PoC for every finding (or explicit manual PoC instructions)
- Write findings to /findings/ using the standard template
- Generate a final report summarizing risk posture
- Do NOT persist access, do NOT exfiltrate real data, do NOT disrupt services
"""

    _REDTEAM_MODE_PROMPT = """
## RED TEAM OPS MODE — Adversary Simulation
This is a red team engagement simulating a real adversary.

**Rules of engagement:**
- Full kill chain: initial access → execution → persistence → privilege escalation →
  defense evasion → credential access → discovery → lateral movement → collection → exfiltration
- OPSEC is CRITICAL — minimize detection, use living-off-the-land where possible
- Establish persistence at EVERY level gained (survive reboots, credential rotations)
- Evade AV/EDR — test payloads, use obfuscation, prefer memory-resident techniques
- Document the full attack chain for purple team debrief

**Assumptions:**
- The target MAY be fully patched — not everything is exploitable
- Blue team MAY be actively monitoring — assume SOC is watching
- Defensive controls (AV, EDR, SIEM) are present and active
- Time is a factor — real adversaries don't have unlimited attempts

**Objectives:**
- Achieve defined objectives (DA, specific data, business email compromise, etc.)
- Maintain persistent access throughout the engagement
- Avoid detection by defensive controls (measure TTD — time to detect)
- Document the full attack narrative for the debrief report
- Test: can the organization detect and respond to this attack chain?
- Golden ticket / DCSync / credential harvesting are EXPECTED post-exploitation activities
"""

    # Legacy compat alias
    _CTF_ANTI_CHEAT_PROMPT = _CTF_MODE_PROMPT

    def _build_full_prompt(self, task: str, context: str = "", include_rubric: bool = True) -> str:
        """Build the complete prompt sent to Claude CLI.

        Follows the "simple memory" principle from Efficient Agents (Zhou et al. 2025):
        minimal context injection outperforms verbose context. Only inject what the
        agent cannot derive from its own actions.

        In CTF mode, uses a lean prompt without opsec/stealth language to avoid
        policy filter accumulation over long exploitation sessions.
        """
        mode = getattr(self.state, "engagement_mode", "ctf")

        if mode == "ctf":
            # CTF mode: authorization header + lean system prompt
            platform = getattr(self.state, "ctf_platform", "")
            platform_clause = f" hosted on {platform}" if platform else ""
            target = self.state.target or "target"
            auth_header = CTF_AUTHORIZATION_HEADER.format(platform_clause=platform_clause, target=target)
            parts = [auth_header, f"## System Context\n{CTF_SYSTEM_PROMPT}"]
        else:
            parts = [f"## System Context\n{self.SYSTEM_PROMPT}"]

        # Inject engagement mode prompt (always — all agents need to know the rules)
        if mode == "ctf":
            parts.append(self._CTF_MODE_PROMPT)
        elif mode == "le":
            parts.append(self._LE_MODE_PROMPT)
        elif mode == "redteam":
            parts.append(self._REDTEAM_MODE_PROMPT)

        # Anti-stuck and impact rubric — skip for analysis-only agents (synthesis, report)
        if self.AGENT_NAME not in ("synthesis", "report"):
            parts.append(self._ANTI_STUCK_PROMPT)

            # Impact rubric — only for execution agents, skip for analysis/subtasks
            if include_rubric and self.AGENT_NAME not in (
                "triage", "noise_filter", "sanity_checker", "param_analyzer"
            ):
                parts.append(IMPACT_RUBRIC)

        # RAG context — per-agent cap based on reasoning depth needed
        if context:
            rag_cap = getattr(self, "RAG_CONTEXT_CAP", 2000)
            parts.append(f"\n\n## Reference Material\n{context[:rag_cap]}")

        # --- Lean engagement context (simple memory) ---
        # Only inject: resume point, target, credentials, exhausted categories
        # Skip: full notes dump, verbose findings DB, detailed approach history
        # NOTE: Synthesis agent skips this — it receives full structured context in the task
        if not getattr(self, "SKIP_LEAN_STATE", False):
            lean_parts = []
            if getattr(self.state, "resume_point", ""):
                lean_parts.append(f"**RESUME:** {self.state.resume_point}")
            lean_parts.append(f"Target: {self.state.target or 'Not set'}")
            if self.state.credentials:
                creds = "; ".join(
                    f"{c['username']}:{c['secret']}[{c['type']}]"
                    for c in self.state.credentials[:5]
                )
                lean_parts.append(f"Creds: {creds}")
            if self.state.compromised_hosts:
                hosts = ", ".join(
                    f"{h['hostname']}[{h['access_level']}]"
                    for h in self.state.compromised_hosts[:5]
                )
                lean_parts.append(f"Compromised: {hosts}")
            if lean_parts:
                parts.append("\n## State\n" + "\n".join(lean_parts))

            # Findings — one-line summary only, not full dump
            total_findings = self.findings_db.count(host=self.state.target)
            if total_findings > 0:
                high_findings = self.findings_db.count(host=self.state.target, min_severity="medium")
                parts.append(f"\nFindings: {total_findings} total, {high_findings} medium+ severity")

        # Discovered defenses — tells agent what NOT to try
        # Skip for synthesis (it gets full defenses in its structured task context)
        if not getattr(self, "SKIP_LEAN_STATE", False):
            defenses = getattr(self.state, "defenses", {})
            if defenses:
                defense_lines = []
                for k, v in defenses.items():
                    defense_lines.append(f"  {k}: {v}")
                parts.append("\n**DEFENSES IN PLACE (do NOT try blocked techniques):**\n" + "\n".join(defense_lines))

        # Exhausted categories — compact, critical for preventing loops
        prior_stuck = StuckDetector.load(self.AGENT_NAME, getattr(self.state, "dir", None))
        if prior_stuck.exhausted_categories:
            blacklist = ", ".join(sorted(prior_stuck.exhausted_categories))
            parts.append(f"\n**BLOCKED:** {blacklist}")
        # Required next steps — compact
        all_known = {cat for cat, _ in StuckDetector._ATTACK_CATEGORIES}
        tried = set(prior_stuck.category_turns.keys())
        required_missing = StuckDetector._RECON_CATEGORIES - tried
        if required_missing:
            parts.append(f"**DO FIRST:** {', '.join(sorted(required_missing))}")

        # Secret vault — instructs agent to use $TOKEN variables
        vault_section = self._vault.prompt_section()
        if vault_section:
            parts.append(vault_section)

        parts.append(f"\nEvidence: {_config.EVIDENCE_DIR}")
        parts.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        parts.append(f"\n\n## Task\n{task}")

        return "\n".join(parts)

    def run(self, task: str, on_status=None, on_progress=None, extra_rag_queries: list[str] | None = None,
            max_turns: int | None = None, skip_rag: bool = False) -> str:
        """Execute a task autonomously.

        Args:
            task: The task description / instruction
            on_status: Callback for spinner status updates — on_status(msg: str)
            on_progress: Callback for verbose progress events — on_progress(event: dict)
                         Event types: "command", "output", "reasoning", "tool_use", "phase", "error"
            extra_rag_queries: Additional KB queries beyond the agent's defaults
            max_turns: Override turn limit (for subtask mode)
            skip_rag: Skip RAG retrieval (for narrow subtasks that don't need KB)

        Returns:
            Agent's response text
        """
        context = ""
        if not skip_rag:
            if on_status:
                on_status(f"[{self.AGENT_NAME}] Retrieving context...")
            context = self._retrieve_context(extra_rag_queries, task_text=task)

        if on_status:
            on_status(f"[{self.AGENT_NAME}] Starting task...")

        # Skip impact rubric for subtasks (narrow tasks, minimal turns)
        include_rubric = not (skip_rag and max_turns and max_turns <= 5)
        prompt = self._sanitize(self._build_full_prompt(task, context, include_rubric=include_rubric))

        agent_model = MODEL_FAST if self.USE_FAST_MODEL else MODEL_PLANNER if self.USE_PLANNER_MODEL else MODEL
        effective_turns = max_turns or getattr(self, "MAX_TURNS_OVERRIDE", None) or AGENT_MAX_TURNS
        is_resume = bool(self._session_id)

        cmd = [
            "claude",
            "-p",
            "--output-format", "stream-json",
            "--verbose",
            "--model", agent_model,
            "--max-turns", str(effective_turns),
            "--permission-mode", "auto",
        ]
        if self.ALLOWED_TOOLS:
            cmd.extend(["--allowedTools", self.ALLOWED_TOOLS])

        if is_resume:
            cmd.extend(["--resume", self._session_id])

        if self.autonomous:
            cmd.append("--dangerously-skip-permissions")

        # On resume, send a short continuation directive instead of the full
        # system prompt — the session already has full context. Re-sending the
        # entire prompt causes the agent to re-analyze from scratch.
        if is_resume:
            # Build a concise resume prompt with only new information
            resume_parts = [
                "CONTINUE from where you left off. Do NOT re-analyze or re-enumerate — "
                "pick up your current attack chain immediately.",
                f"\nTask: {task}",
                f"\nCurrent time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]
            # Include approach tracking so agent knows what's exhausted
            # Load detector state to get current exhausted categories
            _resume_stuck = StuckDetector.load(self.AGENT_NAME, getattr(self.state, "dir", None))
            approach_info = _resume_stuck.approach_summary()
            if approach_info:
                resume_parts.append(f"\n{approach_info}")
            if _resume_stuck.exhausted_categories:
                resume_parts.append(
                    f"\nCRITICAL: Do NOT attempt these exhausted categories: "
                    f"{', '.join(sorted(_resume_stuck.exhausted_categories))}"
                )
            # Include any new credentials/hosts discovered since last run
            state_summary = self.state.summary()
            if self.state.credentials or self.state.compromised_hosts:
                resume_parts.append(f"\n{state_summary}")
            send_prompt = "\n".join(resume_parts)
        else:
            send_prompt = prompt

        env = os.environ.copy()
        env["HOME"] = os.path.expanduser("~")
        env["EVIDENCE_DIR"] = str(_config.EVIDENCE_DIR)

        # Vault deref script for shell variable resolution
        vault_script = self._vault.write_deref_script()
        if vault_script:
            env["VAULT_ENV"] = str(vault_script)

        try:
            import time as _time
            _session_start = _time.monotonic()
            self._log.session_start(
                agent=self.AGENT_NAME, session_id=self._session_id,
                turns=effective_turns, model=agent_model, resumed=is_resume,
            )
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=str(_config.EVIDENCE_DIR),
            )

            # Tokenize secrets before sending to API (LE/RT mode)
            send_prompt = self._vault.tokenize(send_prompt)

            proc.stdin.write(send_prompt)
            proc.stdin.close()

            response_text = ""
            last_result = None
            turn_count = 0
            _session_output = []  # Accumulates tool results + thinking for primitive extractor
            # Load persisted detector state so exhausted categories carry across dispatches
            stuck = StuckDetector.load(self.AGENT_NAME, getattr(self.state, "dir", None))
            killed_for_stuck = False
            last_cmd_str = ""  # Track last Bash command for stuck detector
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                etype = event.get("type", "")

                if etype == "tool_use":
                    tool_name = event.get("tool", {}).get("name", event.get("name", ""))
                    tool_input = event.get("tool", {}).get("input", {})
                    if tool_name == "Bash":
                        last_cmd_str = tool_input.get("command", "")
                        stuck.record_command(last_cmd_str)
                        # OPSEC scoring — skip in CTF mode (no stealth needed,
                        # avoids opsec narrative accumulating in context)
                        _is_ctf = getattr(self.state, "ctf_mode", False)
                        if not _is_ctf:
                            opsec_result = score_command(
                                last_cmd_str,
                                scope_enforcer=getattr(self.state, "scope_enforcer", None),
                                ctf_mode=False,
                            )
                            self.opsec_log.append({
                                "command": last_cmd_str[:200],
                                "score": opsec_result.score,
                                "level": opsec_result.level_name,
                                "reasons": opsec_result.reasons,
                                "agent": self.AGENT_NAME,
                                "time": datetime.now().isoformat(),
                            })
                            if on_status:
                                if opsec_result.score >= LEVEL_HIGH:
                                    on_status(
                                        f"[{self.AGENT_NAME}] [OPSEC: {opsec_result.level_name}] "
                                        f"{last_cmd_str[:60]}"
                                    )
                                else:
                                    on_status(f"[{self.AGENT_NAME}] Running: {last_cmd_str[:70]}")
                            if on_progress:
                                on_progress({
                                    "type": "command",
                                    "agent": self.AGENT_NAME,
                                    "command": last_cmd_str,
                                    "opsec_score": opsec_result.score,
                                    "opsec_level": opsec_result.level_name,
                                    "opsec_reasons": opsec_result.reasons,
                                })
                        else:
                            # CTF mode: anti-cheat only, no stealth scoring
                            opsec_result = score_command(
                                last_cmd_str,
                                scope_enforcer=getattr(self.state, "scope_enforcer", None),
                                ctf_mode=True,
                            )
                            if opsec_result.ctf_blocked:
                                self.opsec_log.append({
                                    "command": last_cmd_str[:200],
                                    "score": opsec_result.score,
                                    "level": opsec_result.level_name,
                                    "reasons": opsec_result.reasons,
                                    "agent": self.AGENT_NAME,
                                    "time": datetime.now().isoformat(),
                                    "action": "killed",
                                })
                                if on_status:
                                    on_status(
                                        f"[{self.AGENT_NAME}] ANTI-CHEAT VIOLATION — "
                                        f"{opsec_result.reasons[0]}"
                                    )
                                if on_progress:
                                    on_progress({
                                        "type": "ctf_anticheat",
                                        "agent": self.AGENT_NAME,
                                        "command": last_cmd_str,
                                        "reasons": opsec_result.reasons,
                                    })
                                proc.kill()
                                response_text += (
                                    f"\n\n*[SESSION KILLED — CTF anti-cheat violation: "
                                    f"{opsec_result.reasons[0]}. "
                                    f"Solve the box using your own methodology.]*"
                                )
                                break
                            if opsec_result.scope_violation or any("CTF ANTI-CHEAT" in r for r in opsec_result.reasons):
                                self.opsec_log.append({
                                    "command": last_cmd_str[:200],
                                    "score": opsec_result.score,
                                    "level": opsec_result.level_name,
                                    "reasons": opsec_result.reasons,
                                    "agent": self.AGENT_NAME,
                                    "time": datetime.now().isoformat(),
                                })
                            if on_status:
                                on_status(f"[{self.AGENT_NAME}] Running: {last_cmd_str[:70]}")
                            if on_progress:
                                on_progress({
                                    "type": "command",
                                    "agent": self.AGENT_NAME,
                                    "command": last_cmd_str,
                                })
                    else:
                        if on_status:
                            on_status(f"[{self.AGENT_NAME}] Using: {tool_name}")
                        if on_progress:
                            on_progress({
                                "type": "tool_use",
                                "agent": self.AGENT_NAME,
                                "tool": tool_name,
                                "input": {k: str(v)[:300] for k, v in tool_input.items()},
                            })

                elif etype == "tool_result":
                    turn_count += 1
                    # Extract tool output for verbose progress
                    result_content = ""
                    if "content" in event:
                        for block in event.get("content", []):
                            if isinstance(block, dict) and block.get("type") == "text":
                                result_content = block.get("text", "")
                            elif isinstance(block, str):
                                result_content = block
                    elif "result" in event:
                        result_content = str(event["result"])

                    # Accumulate for primitive extractor (tokenized in LE/RT)
                    if result_content and len(result_content) > 20:
                        _session_output.append(self._vault.tokenize(result_content[:2000]))

                    # Scan tool output for defense indicators in real-time
                    if result_content:
                        self._detect_defenses(result_content)

                    # Check for milestones in tool output to inform stuck detector
                    if result_content and len(result_content) > 20:
                        _rc_lower = result_content.lower()
                        for _mp, _mpat in self._MILESTONES:
                            if re.search(_mpat, _rc_lower):
                                stuck.record_milestone()
                                break

                    # Feed errors to stuck detector
                    is_error = event.get("is_error", False)
                    if is_error and result_content:
                        stuck.record_error(result_content)
                        self._log.command_error(self.AGENT_NAME, last_cmd_str, result_content[:300])

                    if on_status:
                        on_status(f"[{self.AGENT_NAME}] Turn {turn_count}...")
                    if on_progress and result_content:
                        on_progress({
                            "type": "output",
                            "agent": self.AGENT_NAME,
                            "turn": turn_count,
                            "content": result_content[:2000],
                        })

                    # --- Stuck detection checkpoint ---
                    stuck_msg = stuck.check(turn_count)
                    if stuck_msg:
                        is_strategic = "STRATEGIC LOOP" in stuck_msg or "RECON INCOMPLETE" in stuck_msg

                        if stuck.pivot_warnings_sent >= 2 or is_strategic:
                            # Kill on: second syntactic warning OR first strategic warning.
                            # Strategic loops (Pattern 4/5) kill immediately because the
                            # agent can't see our warnings — continuing is pure waste.
                            if on_status:
                                on_status(f"[{self.AGENT_NAME}] KILLING: {stuck_msg}")
                            if on_progress:
                                on_progress({
                                    "type": "error",
                                    "agent": self.AGENT_NAME,
                                    "text": f"TERMINATED — {stuck_msg}",
                                })
                            proc.kill()
                            killed_for_stuck = True
                            exhausted = ", ".join(sorted(stuck.exhausted_categories)) or "none"
                            self._log.stuck_detected(self.AGENT_NAME, stuck_msg, exhausted)
                            # Auto-learn: record what failed
                            try:
                                from learner import learn_from_stuck_async
                                learn_from_stuck_async(
                                    stuck_msg, stuck.approach_summary(), self.AGENT_NAME,
                                    engagement_id=getattr(self.state, "engagement_id", ""),
                                    mode=getattr(self.state, "engagement_mode", ""))
                            except Exception:
                                pass
                            break
                        else:
                            # First syntactic warning → log it, agent continues but is on notice
                            if on_status:
                                on_status(f"[{self.AGENT_NAME}] WARNING: {stuck_msg}")
                            if on_progress:
                                on_progress({
                                    "type": "error",
                                    "agent": self.AGENT_NAME,
                                    "text": stuck_msg,
                                })

                    # --- Per-turn strategy reassessment (every 3 turns) ---
                    # Paper (Zhou et al. 2025): plan revision every 1 step > infrequent.
                    # We check every 3 turns as a balance between overhead and responsiveness.
                    if turn_count >= 3 and turn_count % 3 == 0:
                        # Build a compact progress report
                        cats_used = {
                            cat: len(t) for cat, t in stuck.category_turns.items() if t
                        }
                        cats_str = ", ".join(f"{c}:{n}" for c, n in cats_used.items()) or "none"
                        budget_pct = int(turn_count / AGENT_MAX_TURNS * 100)

                        progress_msg = (
                            f"Turn {turn_count}/{AGENT_MAX_TURNS} ({budget_pct}% budget used). "
                            f"Categories: {cats_str}. Errors: {stuck.error_count}."
                        )
                        if budget_pct >= 70:
                            progress_msg += " WARNING: budget nearly exhausted — wrap up or pivot."

                        if on_status:
                            on_status(f"[{self.AGENT_NAME}] {progress_msg}")
                        if on_progress:
                            on_progress({
                                "type": "phase",
                                "agent": self.AGENT_NAME,
                                "text": progress_msg,
                            })

                elif etype == "assistant" and "message" in event:
                    for block in event["message"].get("content", []):
                        if block.get("type") == "text":
                            response_text = block["text"]
                            if len(block["text"]) > 50:
                                _session_output.append(block["text"][:1500])
                            if on_progress:
                                on_progress({
                                    "type": "reasoning",
                                    "agent": self.AGENT_NAME,
                                    "text": block["text"][:1500],
                                })

                if etype == "result":
                    last_result = event
                    if event.get("result"):
                        response_text = event["result"]

            proc.wait(timeout=TIMEOUT)

            if last_result:
                self._session_id = last_result.get("session_id", self._session_id)
                self._last_cost = last_result.get("total_cost_usd", 0)
                self._last_turns = last_result.get("num_turns", 1)
                # Accumulate cost + time on engagement state (persisted)
                _elapsed = _time.monotonic() - _session_start
                if self.state.target:
                    if self._last_cost:
                        self.state.total_cost = getattr(self.state, "total_cost", 0.0) + self._last_cost
                    self.state.total_time_secs = getattr(self.state, "total_time_secs", 0.0) + _elapsed
                self._log.session_end(self.AGENT_NAME, self._last_cost, self._last_turns,
                                      _elapsed, self._session_id)

            # If killed for being stuck, append a pivot report to the response
            if killed_for_stuck:
                approach_summary = stuck.approach_summary()
                exhausted_str = (
                    ", ".join(sorted(stuck.exhausted_categories))
                    if stuck.exhausted_categories else "none explicitly"
                )
                # Identify what recon is missing
                recon_done = {
                    cat for cat in stuck._RECON_CATEGORIES
                    if cat in stuck.category_turns
                }
                recon_missing = stuck._RECON_CATEGORIES - recon_done
                recon_note = (
                    f"- MISSING recon categories: {', '.join(sorted(recon_missing))}\n"
                    if recon_missing else ""
                )

                pivot_report = (
                    f"\n\n---\n**[AGENT TERMINATED — STUCK DETECTED]**\n"
                    f"The {self.AGENT_NAME} agent was terminated after {turn_count} turns "
                    f"due to repetitive behavior.\n"
                    f"- Commands attempted: {len(stuck.commands)}\n"
                    f"- Errors encountered: {stuck.error_count}\n"
                    f"- Pivot warnings: {stuck.pivot_warnings_sent}\n"
                    f"- Exhausted attack categories: {exhausted_str}\n"
                    f"{recon_note}\n"
                    f"{approach_summary}\n\n"
                    f"**The current approach is not working.** The orchestrator MUST:\n"
                    f"1. NOT retry any exhausted category listed above\n"
                    f"2. Complete missing recon before retrying exploitation\n"
                    f"3. Try a fundamentally different attack vector\n"
                    f"4. Consider: subdomain enumeration, different service discovery, "
                    f"writing a standalone script, or targeting a different service\n"
                )
                response_text = (response_text or "") + pivot_report

            # Persist detector state so exhausted categories survive across dispatches
            stuck.save()

            if not response_text:
                response_text = "(No response from agent)"

            # Auto-detect defenses from output and record them
            self._detect_defenses(response_text)

            # Auto-extract attack primitives from the full session output.
            # Use accumulated tool results + thinking (not just the final response text,
            # which is often a short summary missing the actual findings).
            # Skip for analysis-only agents — their output is proposed chains, not real findings.
            if self.AGENT_NAME not in ("synthesis", "report", "sanity_checker"):
                try:
                    from primitive_extractor import extract_primitives_async
                    _full_output = "\n\n".join(_session_output[-20:])
                    if len(_full_output) > len(response_text):
                        extract_primitives_async(_full_output, self.state)
                    else:
                        extract_primitives_async(response_text, self.state)
                except Exception:
                    pass

            # Store result
            self.results.append({
                "task": task,
                "response": response_text,
                "cost": self._last_cost,
                "turns": self._last_turns,
                "opsec_events": len(self.opsec_log),
                "stuck_killed": killed_for_stuck,
                "commands_attempted": len(stuck.commands),
                "errors": stuck.error_count,
                "time": datetime.now().isoformat(),
            })

            # Auto-update resume checkpoint based on milestones
            self._update_resume_point(response_text)

            # CTF flag write-back + dead-end memory — same shared engagement logic the
            # interactive agent uses, so orchestrator runs persist flags/hosts too.
            if getattr(self.state, "engagement_mode", "ctf") == "ctf":
                try:
                    recorded = self.state.scan_and_record_flags(
                        response_text, raw_output=response_text)
                    for _label, _value in recorded.items():
                        self._log.flag_captured(_label, _value)
                except Exception:
                    pass
            try:
                self.state.scan_and_record_dead_ends(response_text)
            except Exception:
                pass

            # Parse credentials into typed state — orchestrator sub-agents never did
            # this, so harvested creds (AWS keys, passwords) found during a dispatch
            # were lost. Scan the raw tool output too, where env dumps / callbacks land.
            try:
                self.state.parse_credentials_from_text(response_text, source=self.AGENT_NAME)
                _raw = "\n\n".join(_session_output[-20:]) if _session_output else ""
                if _raw and _raw != response_text:
                    self.state.parse_credentials_from_text(_raw, source="tool_output")
            except Exception:
                pass

            # Persist session so we can --resume after restart
            self._save_session()

            return response_text

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            self._log.error("timeout", agent=self.AGENT_NAME, timeout=TIMEOUT)
            return f"[{self.AGENT_NAME}] Task timed out after {TIMEOUT // 60} minutes."
        except Exception as e:
            import traceback
            self._log.crash(self.AGENT_NAME, str(e), traceback.format_exc()[-500:])
            return f"[{self.AGENT_NAME}] Error: {e}"

    # Milestone patterns for auto-updating resume_point (priority order, highest wins).
    _MILESTONES = [
        (100, r"(root|system|nt authority).*(flag|proof|hash|txt)"),
        (95,  r"(dcsync|secretsdump.*completed|ntds\.dit|krbtgt.*hash)"),
        (90,  r"(domain\s*admin|enterprise\s*admin|da\s+access)"),
        (80,  r"(privilege\s*escalat|privesc|got\s*root|now\s*root|uid=0|nt authority\\\\system)"),
        (70,  r"(lateral\s*mov|pivot|moved\s*to|accessed\s*(another|new)\s*host)"),
        (65,  r"(user\.txt|user\s*flag|user\s*proof)"),
        (60,  r"(reverse\s*shell|callback|shell\s*as\s*\w+|interactive\s*shell"
              r"|winrm.*(connect|shell|access|works)|evil-winrm"
              r"|crackmapexec.*(pwn3d|Pwn3d|\(\+\))|got\s*a?\s*shell)"),
        (55,  r"(webshell|web\s*shell|cmd\.php|shell\.php|system\(\$_GET)"),
        (50,  r"(rce\s*confirm|confirmed\s*rce|code\s*execution\s*confirm|uid=\d+\()"),
        (45,  r"(credentials?\s*(found|discover|crack|dump|obtain|extract)"
              r"|password\s*(hash|crack|found|dump)|gmsa\s*(password|hash)"
              r"|ntlm\s*hash\s*(obtain|extract|read)|tgt\s*(obtain|extract))"),
        (40,  r"(authenticated|logged\s*in|auth\s*bypass|valid\s*(session|token)|login\s*(success|work))"),
        (30,  r"(sqli\s*(confirm|found)|injection\s*(confirm|found)|data\s*(extract|dump)"
              r"|type\s*juggl|idor\s*(confirm|found))"),
    ]

    _MILESTONE_LABELS = {
        100: "ROOT/SYSTEM access achieved",
        95:  "DCSync/NTDS dump completed — domain fully compromised",
        90:  "Domain Admin achieved",
        80:  "Privilege escalation successful",
        70:  "Lateral movement in progress",
        65:  "User flag captured",
        60:  "Shell obtained — enumerate and escalate",
        55:  "Webshell deployed",
        50:  "RCE confirmed — use it, don't refine it",
        45:  "Credentials obtained — try reuse across services",
        40:  "Authenticated access — look for post-auth vulns",
        30:  "Injection/IDOR confirmed — extract data or pivot to RCE",
    }

    def _update_resume_point(self, response_text: str) -> None:
        """Scan response for milestone indicators and update engagement resume checkpoint."""
        if not response_text or not self.state.target:
            return

        text_lower = response_text.lower()
        current_priority = self.state.resume_priority

        for priority, pattern in self._MILESTONES:
            if priority <= current_priority:
                continue
            match = re.search(pattern, text_lower)
            if match:
                # Terminal claims (root/DA/SYSTEM, priority >= 90) must be backed
                # by recorded state (a flag or compromised host) — a narrative-only
                # "I have root" is a hallucination that sets a false objective.
                if not self.state.milestone_corroborated(priority):
                    continue
                label = self._MILESTONE_LABELS.get(priority, "Progress checkpoint")
                # Extract context around the match
                start = max(0, match.start() - 80)
                end = min(len(response_text), match.end() + 120)
                context = response_text[start:end].strip().replace("\n", " ")

                self.state.resume_point = (
                    f"{label} on {self.state.target}.\n"
                    f"Context: {context[:300]}\n"
                    f"Do NOT redo recon, scanning, or earlier exploitation steps."
                )
                self.state.resume_priority = priority
                self._log.milestone(self.AGENT_NAME, priority, label)
                # Corroborate the foothold in typed state so a later root claim passes
                # milestone_corroborated() (see the same logic in agent.py).
                if priority >= 50:
                    try:
                        self.state.add_compromised_host(
                            self.state.target or "target", ip=self.state.target or "",
                            access_level=("root" if priority >= 80 else "user"))
                    except Exception:
                        pass
                # Persist immediately
                try:
                    self.state.save()
                except Exception:
                    pass
                # Auto-learn: ingest successful technique into RAG
                try:
                    from learner import learn_from_milestone_async
                    learn_from_milestone_async(
                        response_text, label, self.state.target,
                        engagement_id=getattr(self.state, "engagement_id", ""),
                        mode=getattr(self.state, "engagement_mode", ""))
                except Exception:
                    pass
                break

    # Defense indicators — patterns that reveal security controls in place.
    # When detected, they're recorded in engagement state to prevent wasting turns.
    _DEFENSE_PATTERNS_RAW = [
        ("smb_signing", [r"signing.*required", r"signing.*enforced", r"SMB.*signing"]),
        ("protected_users", [r"protected\s*users", r"account.restriction", r"STATUS_ACCOUNT_RESTRICTION"]),
        ("lsass_ppl", [r"RunAsPPL.*1", r"lsass.*protected", r"PPL.*enabled"]),
        ("clm", [r"constrained.*language", r"ConstrainedLanguage"]),
        ("applocker", [r"applocker", r"application\s*whitelisting"]),
        ("amsi", [r"AMSI.*block", r"amsi.*detected"]),
        ("cert_mapping_strong", [r"strong.*cert.*map", r"KB5014754", r"szOID_NTDS_CA_SECURITY"]),
        ("server_auth_eku_only", [r"server\s*auth.*only", r"no.*client.*auth.*eku", r"pkinit.*fail.*eku"]),
        ("ntlm_disabled", [r"ntlm.*disabled", r"ntlm.*blocked", r"ETYPE_NOSUPP"]),
        ("defender_active", [r"defender.*enabled", r"windefend.*running", r"real.time.*protection"]),
        ("external_sasl_disabled", [r"external.*sasl.*not.*support", r"external.*not.*support",
                                     r"sasl.*external.*fail"]),
        ("schannel_blocked", [r"schannel.*fail", r"schannel.*denied", r"schannel.*not.*support",
                               r"cert.*mapping.*fail", r"cert.*auth.*blocked"]),
        ("pkinit_not_supported", [r"KDC_ERR_CLIENT_NOT_TRUSTED", r"pkinit.*not.*support",
                                   r"pkinit.*not.*configured", r"no.*kdc.*cert"]),
        ("smb_outbound_firewalled", [r"ERROR_BAD_NETPATH", r"bad_netpath",
                                      r"outbound.*smb.*block", r"can.*t.*reach"]),
        ("outbound_blocked", [r"outbound.*block", r"no.*callback", r"reverse.*shell.*fail.*connect",
                               r"no.*connection.*received", r"listener.*no.*connect"]),
        ("machine_quota_zero", [r"machine.*quota.*0", r"quota.*exceeded",
                                 r"SamrCreateUser2.*STATUS_ACCESS_DENIED"]),
    ]

    # Pre-compiled defense patterns (compiled once at class load)
    _DEFENSE_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
        (name, [re.compile(p, re.IGNORECASE) for p in patterns])
        for name, patterns in _DEFENSE_PATTERNS_RAW
    ]

    def _detect_defenses(self, text: str) -> None:
        """Scan agent output for defense indicators and record them."""
        if not text or not hasattr(self.state, "defenses"):
            return
        changed = False
        for defense_name, compiled_patterns in self._DEFENSE_PATTERNS:
            if defense_name in self.state.defenses:
                continue  # Already known
            for pat in compiled_patterns:
                if pat.search(text):
                    self.state.defenses[defense_name] = True
                    changed = True
                    break
        if changed:
            try:
                self.state.save()
            except Exception:
                pass

    def reset(self):
        """Reset agent session for a fresh start."""
        self._session_id = ""
        self.results = []
        self.opsec_log = []
        # Clear persisted session and stuck detector state
        try:
            self._session_path().unlink(missing_ok=True)
        except Exception:
            pass
        try:
            # Clean up per-engagement stuck state
            eng_dir = getattr(self.state, "dir", None)
            stuck_path = (eng_dir or ENGAGEMENTS_DIR) / f"_stuck_{self.AGENT_NAME}.json"
            stuck_path.unlink(missing_ok=True)
        except Exception:
            pass
