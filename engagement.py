"""Engagement Manager -- isolated, per-target engagement lifecycle.

Each engagement owns:
- Its state (credentials, notes, primitives, defenses)
- Its task ledger (operator objectives and agent tasks)
- Its phase tracker (recon -> exploit -> postex progression)
- Its findings DB (SQLite, per-engagement directory)
- Its evidence directory
- Its attack plan
- Its checkpoint
- Its lifecycle status (active/solved)

Engagements NEVER share state. Switching engagements is a clean cut.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from config import ENGAGEMENTS_DIR, EVIDENCE_BASE
from scope_enforcer import ScopeDefinition, ScopeEnforcer
from target_manager import TargetManager


# ---------------------------------------------------------------------------
# Task Ledger — tracks objectives and agent work items per engagement
# ---------------------------------------------------------------------------

class TaskStatus:
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    SKIPPED = "skipped"

    _TERMINAL = frozenset({"completed", "failed", "skipped"})


@dataclass
class Task:
    id: str
    objective: str
    status: str = TaskStatus.PENDING
    agent: str = ""
    phase: str = ""
    created_at: str = ""
    completed_at: str = ""
    blocked_by: str = ""
    result: str = ""
    parent_id: str = ""

    @property
    def is_done(self) -> bool:
        return self.status in TaskStatus._TERMINAL


class TaskLedger:
    """Ordered list of tasks/objectives within an engagement."""

    def __init__(self):
        self._tasks: list[Task] = []
        self._counter: int = 0

    def add(self, objective: str, agent: str = "", phase: str = "",
            parent_id: str = "") -> Task:
        self._counter += 1
        task = Task(
            id=f"T{self._counter:03d}",
            objective=objective,
            agent=agent,
            phase=phase,
            created_at=datetime.now().isoformat(),
            parent_id=parent_id,
        )
        self._tasks.append(task)
        return task

    def get(self, task_id: str) -> Task | None:
        for t in self._tasks:
            if t.id == task_id:
                return t
        return None

    def update(self, task_id: str, **kwargs) -> Task | None:
        task = self.get(task_id)
        if not task:
            return None
        for k, v in kwargs.items():
            if hasattr(task, k) and k != "id":
                setattr(task, k, v)
        if kwargs.get("status") in TaskStatus._TERMINAL:
            task.completed_at = datetime.now().isoformat()
        return task

    def start(self, task_id: str, agent: str = "") -> Task | None:
        kwargs = {"status": TaskStatus.ACTIVE}
        if agent:
            kwargs["agent"] = agent
        return self.update(task_id, **kwargs)

    def complete(self, task_id: str, result: str = "") -> Task | None:
        return self.update(task_id, status=TaskStatus.COMPLETED, result=result)

    def fail(self, task_id: str, result: str = "") -> Task | None:
        return self.update(task_id, status=TaskStatus.FAILED, result=result)

    def block(self, task_id: str, blocked_by: str = "") -> Task | None:
        return self.update(task_id, status=TaskStatus.BLOCKED, blocked_by=blocked_by)

    @property
    def active(self) -> list[Task]:
        return [t for t in self._tasks if t.status == TaskStatus.ACTIVE]

    @property
    def pending(self) -> list[Task]:
        return [t for t in self._tasks if t.status == TaskStatus.PENDING]

    @property
    def completed(self) -> list[Task]:
        return [t for t in self._tasks if t.status == TaskStatus.COMPLETED]

    @property
    def blocked(self) -> list[Task]:
        return [t for t in self._tasks if t.status == TaskStatus.BLOCKED]

    @property
    def all(self) -> list[Task]:
        return list(self._tasks)

    def by_phase(self, phase: str) -> list[Task]:
        return [t for t in self._tasks if t.phase == phase]

    def by_agent(self, agent: str) -> list[Task]:
        return [t for t in self._tasks if t.agent == agent]

    def children(self, parent_id: str) -> list[Task]:
        return [t for t in self._tasks if t.parent_id == parent_id]

    def to_dict(self) -> list[dict]:
        return [asdict(t) for t in self._tasks]

    def load_from_dict(self, data: list[dict]):
        self._tasks = []
        for d in data:
            self._tasks.append(Task(**{k: v for k, v in d.items() if k in Task.__dataclass_fields__}))
        self._counter = max((int(t.id[1:]) for t in self._tasks), default=0)

    def summary(self, compact: bool = False) -> str:
        if not self._tasks:
            return ""
        lines = [f"## Task Ledger ({len(self._tasks)} tasks)"]
        counts = {}
        for t in self._tasks:
            counts[t.status] = counts.get(t.status, 0) + 1
        status_line = " | ".join(f"{s}: {c}" for s, c in counts.items())
        lines.append(f"  {status_line}")

        if compact:
            # Only show active + pending
            for t in self.active + self.pending[:5]:
                marker = ">" if t.status == TaskStatus.ACTIVE else "-"
                agent_tag = f" [{t.agent}]" if t.agent else ""
                lines.append(f"  {marker} {t.id}: {t.objective}{agent_tag}")
        else:
            for t in self._tasks:
                markers = {
                    TaskStatus.PENDING: "-",
                    TaskStatus.ACTIVE: ">",
                    TaskStatus.COMPLETED: "x",
                    TaskStatus.BLOCKED: "!",
                    TaskStatus.FAILED: "X",
                    TaskStatus.SKIPPED: "~",
                }
                marker = markers.get(t.status, "?")
                agent_tag = f" [{t.agent}]" if t.agent else ""
                phase_tag = f" ({t.phase})" if t.phase else ""
                lines.append(f"  {marker} {t.id}: {t.objective}{agent_tag}{phase_tag}")
                if t.result and t.is_done:
                    lines.append(f"      -> {t.result[:120]}")
                if t.blocked_by:
                    lines.append(f"      blocked by: {t.blocked_by}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Phase Tracker — engagement phase state machine
# ---------------------------------------------------------------------------

class Phase:
    SETUP = "setup"
    RECON = "recon"
    TRIAGE = "triage"
    EXPLOIT = "exploit"
    POSTEX = "postex"
    LATERAL = "lateral"
    REPORTING = "reporting"
    COMPLETED = "completed"

    ORDER = ["setup", "recon", "triage", "exploit", "postex", "lateral", "reporting", "completed"]


class PhaseTracker:
    """Tracks engagement phase progression with timestamps."""

    def __init__(self):
        self.current: str = Phase.SETUP
        self.history: list[dict] = []  # [{phase, entered_at, exited_at}]

    def advance(self, to_phase: str = "") -> str:
        """Move to the next phase (or a specific phase). Returns new phase."""
        if to_phase:
            new_phase = to_phase
        else:
            idx = Phase.ORDER.index(self.current) if self.current in Phase.ORDER else 0
            if idx + 1 < len(Phase.ORDER):
                new_phase = Phase.ORDER[idx + 1]
            else:
                return self.current  # Already at end

        now = datetime.now().isoformat()

        # Close current phase
        if self.history:
            self.history[-1]["exited_at"] = now

        # Open new phase
        self.history.append({
            "phase": new_phase,
            "entered_at": now,
            "exited_at": "",
        })
        self.current = new_phase
        return new_phase

    def time_in_phase(self, phase: str) -> float:
        """Seconds spent in a specific phase (cumulative if re-entered)."""
        total = 0.0
        for entry in self.history:
            if entry["phase"] != phase:
                continue
            entered = datetime.fromisoformat(entry["entered_at"])
            if entry["exited_at"]:
                exited = datetime.fromisoformat(entry["exited_at"])
            else:
                exited = datetime.now()
            total += (exited - entered).total_seconds()
        return total

    @property
    def phase_index(self) -> int:
        return Phase.ORDER.index(self.current) if self.current in Phase.ORDER else 0

    def to_dict(self) -> dict:
        return {"current": self.current, "history": self.history}

    def load_from_dict(self, data: dict):
        self.current = data.get("current", Phase.SETUP)
        self.history = data.get("history", [])

    def summary(self) -> str:
        phases_done = [e["phase"] for e in self.history if e["exited_at"]]
        return f"Phase: {self.current} | Completed: {', '.join(phases_done) or 'none'}"


# ---------------------------------------------------------------------------
# Engagement Status
# ---------------------------------------------------------------------------

class EngagementStatus:
    ACTIVE = "active"
    SOLVED = "solved"


# ---------------------------------------------------------------------------
# Engagement — single source of truth for all per-engagement state
# ---------------------------------------------------------------------------

# Fields that are directly serialized to/from JSON.
# Format: (attr_name, json_key, default_factory_or_value)
# Using tuples so save/load/migrate all iterate one list.
_FIELDS: list[tuple[str, str, Any]] = [
    ("target",              "target",              ""),
    ("targets",             "targets",             list),
    ("scope",               "scope",               ""),
    ("roe",                 "roe",                 ""),
    ("status",              "status",              EngagementStatus.ACTIVE),
    ("compromised_hosts",   "compromised_hosts",   list),
    ("credentials",         "credentials",         list),
    ("discovered_hosts",    "discovered_hosts",    list),
    ("notes",               "notes",               list),
    ("defenses",            "defenses",            dict),
    ("attack_surfaces",     "attack_surfaces",     list),
    ("trust_relationships", "trust_relationships", list),
    ("capabilities",        "capabilities",        list),
    ("service_configs",     "service_configs",     list),
    ("resume_point",        "resume_point",        ""),
    ("resume_priority",     "resume_priority",     0),
    ("autonomous",          "autonomous",          False),
    ("engagement_mode",     "engagement_mode",     "ctf"),
    ("total_cost",           "total_cost",           0.0),
    ("total_time_secs",      "total_time_secs",      0.0),
    ("ctf_platform",        "ctf_platform",        ""),
    ("flags",               "flags",               dict),
]


def _default(spec: Any) -> Any:
    """Return a fresh default value from a _FIELDS spec."""
    if spec is list:
        return []
    if spec is dict:
        return {}
    return spec


class Engagement:
    """A fully isolated penetration testing engagement."""

    def __init__(self, target: str = "", mode: str = "ctf"):
        # Initialize all serializable fields from _FIELDS
        for attr, _, default_spec in _FIELDS:
            setattr(self, attr, _default(default_spec))

        self.target = target
        self.targets = [target] if target else []
        self.engagement_mode = mode

        # Derived state
        self.ctf_mode: bool = (mode == "ctf")

        # Per-engagement directory: data/engagements/<mode>/<safe_target>/
        mode_dir = ENGAGEMENTS_DIR / mode
        self.dir = mode_dir / self._safe_name() if target else ENGAGEMENTS_DIR / "_blank"
        self.dir.mkdir(parents=True, exist_ok=True)

        # Per-engagement paths
        self.evidence_dir = self.dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)
        self.findings_db_path = self.dir / "findings.db"
        self.state_path = self.dir / "state.json"
        self.checkpoint_path = self.dir / "checkpoint.json"
        self.plan_path = self.dir / "plan.json"

        # Subsystems (not in _FIELDS — serialized separately)
        self.scope_enforcer: ScopeEnforcer | None = None
        self.target_manager: TargetManager = TargetManager()
        self.task_ledger: TaskLedger = TaskLedger()
        self.phases: PhaseTracker = PhaseTracker()

    # --- Naming / Paths ---

    def _safe_name(self) -> str:
        if not self.target:
            return "_blank"
        return self.target.replace(".", "_").replace("/", "_").replace(":", "_").replace(" ", "_")

    @property
    def engagement_id(self) -> str:
        """Stable per-engagement identifier (`<mode>/<safe_target>`).

        Matches the on-disk engagement directory key. Used to scope learned
        RAG knowledge so one engagement's distilled techniques never surface
        in a different engagement/target.
        """
        return f"{self.engagement_mode}/{self._safe_name()}"

    def _update_paths(self):
        """Recalculate all paths when target changes."""
        mode_dir = ENGAGEMENTS_DIR / self.engagement_mode
        self.dir = mode_dir / self._safe_name()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)
        self.findings_db_path = self.dir / "findings.db"
        self.state_path = self.dir / "state.json"
        self.checkpoint_path = self.dir / "checkpoint.json"
        self.plan_path = self.dir / "plan.json"

    # --- Scope ---

    def _rebuild_scope(self):
        """Rebuild scope enforcer from current scope + targets. Single call site."""
        if not self.scope and not self.targets:
            self.scope_enforcer = None
            return
        scope_def = ScopeDefinition.parse(self.scope) if self.scope else ScopeDefinition()
        for t in self.targets:
            ScopeDefinition._classify_token(scope_def, t, excluded=False)
        self.scope_enforcer = ScopeEnforcer(scope_def)

    # --- Target ---

    def set_target(self, target: str, scope: str = "", roe: str = ""):
        """Set target and configure scope/ROE. Updates all paths."""
        raw_targets = [t.strip() for t in target.replace(",", " ").split() if t.strip()]
        self.target = raw_targets[0] if raw_targets else target
        self.targets = raw_targets if len(raw_targets) > 1 else [self.target]
        if scope:
            self.scope = scope
        if roe:
            self.roe = roe

        self._update_paths()
        self.target_manager.add_hosts(self.targets, source="manual")
        self._rebuild_scope()

        # Advance phase from setup to recon
        if self.phases.current == Phase.SETUP:
            self.phases.advance(Phase.RECON)

    # --- Credentials / Hosts ---

    def add_credential(self, username: str, secret: str, secret_type: str, source: str = ""):
        self.credentials.append({
            "username": username,
            "secret": secret,
            "type": secret_type,
            "source": source,
            "time": datetime.now().isoformat(),
        })

    def add_compromised_host(self, hostname: str, ip: str = "", access_level: str = "user"):
        self.compromised_hosts.append({
            "hostname": hostname,
            "ip": ip,
            "access_level": access_level,
            "time": datetime.now().isoformat(),
        })

    def parse_credentials_from_text(self, text: str, source: str = "user_input") -> int:
        """Extract credentials from free-form text (user messages, agent output).

        Recognizes patterns like:
          - username / password  (with keyword prefix)
          - username:password    (only with keyword context)
          - NTLM hashes (user:RID:LM:NT)

        Returns count of new credentials added.
        """
        import re as _re
        added = 0
        existing_pairs = {(c["username"].lower(), c["secret"]) for c in self.credentials}

        # Usernames must look like actual account names
        _VALID_USER = r'[A-Za-z][A-Za-z0-9_.\\-]{1,30}'
        # Passwords must be plausible (no markdown, prose fragments, or command artifacts)
        _INVALID_SECRET = _re.compile(
            r'^\*|'                      # markdown bold/italic
            r'^#|'                       # markdown header
            r'^--|'                      # markdown separator
            r'^\(|'                      # parenthetical
            r'.*[\'\"`,;]\s*$|'          # trailing quote/comma from command text
            r'^(Primary|Secondary|None|True|False|null|undefined)$|'  # keywords
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            _re.IGNORECASE
        )
        # Usernames that are obviously not accounts
        _INVALID_USER = _re.compile(
            r'^(http|https|ftp|ssh|smb|ldap|port|type|cache|set|get|run|'
            r'use|the|and|for|not|but|can|has|was|are|this|that|from|'
            r'extraction|service|status|error|result|output|target|'
            r'detail|value|source|module|class|import|return|print|'
            r'note|step|phase|chain|path|file|host|cert|hash|key|'
            r'config|query|admin|domain|group|scope|check|test|scan|'
            r's|t|n|r|x|e|d)$',
            _re.IGNORECASE
        )

        def _valid_cred(user: str, secret: str) -> bool:
            """Validate a parsed credential pair is plausible."""
            # Strip trailing punctuation from password (command artifacts)
            secret = secret.rstrip("'\"`,;)")
            if len(user) < 2 or len(secret) < 4:
                return False
            if _INVALID_USER.match(user):
                return False
            if _INVALID_SECRET.match(secret):
                return False
            # Must contain at least one letter (not just numbers/symbols)
            if not _re.search(r'[A-Za-z]', secret):
                return False
            return True

        def _clean_secret(secret: str) -> str:
            """Strip command/syntax artifacts from a parsed password."""
            return secret.rstrip("'\"`,;)")

        # Pattern 1: "account_name / password" or "username / password"
        # Requires a keyword prefix to avoid matching prose "X / Y" patterns
        for m in _re.finditer(
            r'(?:account|user(?:name)?|login|cred(?:ential)?s?\s+(?:for\s+)?(?:the\s+)?(?:account\s+)?)'
            r'\s*[:=]?\s*'
            r'(' + _VALID_USER + r')'
            r'\s*[/|]\s*'
            r'(\S+)',
            text, _re.IGNORECASE
        ):
            user, secret = m.group(1).strip(), _clean_secret(m.group(2).strip())
            if _valid_cred(user, secret) and (user.lower(), secret) not in existing_pairs:
                self.add_credential(user, secret, "password", source=source)
                existing_pairs.add((user.lower(), secret))
                added += 1

        # Pattern 2: "user:password" — ONLY when preceded by a credential-context keyword
        # within 40 chars. This prevents matching command fragments like "certutil:http"
        # or prose like "cache:Primary".
        for m in _re.finditer(
            r'(?:password|cred(?:ential)?s?|hash|cracked|spray|login|auth)\b'
            r'.{0,40}?'
            r'\b(' + _VALID_USER + r'):([^\s:()]{4,60})',
            text, _re.IGNORECASE
        ):
            user, secret = m.group(1), _clean_secret(m.group(2))
            if _re.match(r'^\d+$', secret):
                continue
            if not _valid_cred(user, secret):
                continue
            if (user.lower(), secret) not in existing_pairs:
                self.add_credential(user, secret, "password", source=source)
                existing_pairs.add((user.lower(), secret))
                added += 1

        # Pattern 3: NTLM hash lines — user:RID:LM:NT (very specific, low false positive)
        for m in _re.finditer(
            r'(' + _VALID_USER + r'):\d+:[a-f0-9]{32}:([a-f0-9]{32})',
            text, _re.IGNORECASE
        ):
            user, nt_hash = m.group(1), m.group(2)
            if _INVALID_USER.match(user):
                continue
            if (user.lower(), nt_hash) not in existing_pairs:
                self.add_credential(user, nt_hash, "ntlm_hash", source=source)
                existing_pairs.add((user.lower(), nt_hash))
                added += 1

        if added:
            self.save()
        return added

    def parse_hosts_from_text(self, text: str, source: str = "agent_output") -> int:
        """Extract discovered hosts from agent/tool output and add to state.

        Parses IPs and hostnames from common tool output formats:
          - nmap scan results (Nmap scan report for X)
          - DNS resolution output (X has address Y)
          - ping/traceroute output
          - SMB/LDAP/RPC enumeration output
          - Bare IPs in structured output (tables, lists)
          - Subdomain enumeration output (subfinder, amass, etc.)

        Only adds hosts that are in scope (if scope enforcer is configured).
        Ignores the primary target, localhost, and link-local addresses.
        Returns count of new hosts added.
        """
        import re as _re
        import ipaddress as _ip

        added = 0
        existing = set()

        # Collect already-known hosts
        for h in self.discovered_hosts:
            if isinstance(h, dict):
                existing.add(h.get("host", "").lower())
            else:
                existing.add(str(h).lower())
        existing.add(self.target.lower() if self.target else "")
        for t in self.targets:
            existing.add(t.lower())

        # IPs to always skip
        _SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
        _SKIP_NETS = [
            _ip.ip_network("127.0.0.0/8"),
            _ip.ip_network("169.254.0.0/16"),   # link-local
            _ip.ip_network("224.0.0.0/4"),       # multicast
        ]

        # Hostnames to always skip
        _SKIP_HOSTS = _re.compile(
            r'^(localhost|broadcasthost|ip6-localhost|ip6-loopback|'
            r'kali|attacker|attack-box|attack_box)$',
            _re.IGNORECASE
        )

        def _is_skippable_ip(addr_str: str) -> bool:
            if addr_str in _SKIP_IPS:
                return True
            try:
                addr = _ip.ip_address(addr_str)
                return any(addr in net for net in _SKIP_NETS)
            except ValueError:
                return False

        def _valid_hostname(name: str) -> bool:
            """Check if a string looks like a real hostname."""
            if len(name) < 4 or len(name) > 253:
                return False
            if _SKIP_HOSTS.match(name):
                return False
            # Must have at least one dot and look like a domain
            if "." not in name:
                return False
            return bool(_re.match(
                r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$',
                name, _re.IGNORECASE
            ))

        candidates: set[str] = set()

        # Pattern 1: IPv4 addresses (common in tool output)
        for m in _re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
            ip = m.group(1)
            try:
                _ip.ip_address(ip)  # validate
                candidates.add(ip)
            except ValueError:
                pass

        # Pattern 2: Nmap "Nmap scan report for hostname (ip)" or "for ip"
        for m in _re.finditer(
            r'Nmap scan report for\s+([^\s(]+)(?:\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\))?',
            text, _re.IGNORECASE
        ):
            host = m.group(1).strip()
            ip = m.group(2)
            if ip:
                candidates.add(ip)
            if _valid_hostname(host):
                candidates.add(host.lower())

        # Pattern 3: DNS "X has address Y" or "X resolves to Y"
        for m in _re.finditer(
            r'([a-z0-9][a-z0-9.\-]+)\s+(?:has address|resolves to|A record)\s+'
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            text, _re.IGNORECASE
        ):
            hostname = m.group(1).lower()
            ip = m.group(2)
            candidates.add(ip)
            if _valid_hostname(hostname):
                candidates.add(hostname)

        # Pattern 4: Subdomain enumeration (one hostname per line, common format)
        for m in _re.finditer(
            r'^([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+)\s*$',
            text, _re.MULTILINE | _re.IGNORECASE
        ):
            hostname = m.group(1).lower()
            if _valid_hostname(hostname):
                candidates.add(hostname)

        # Pattern 5: SMB/NetBIOS "\\hostname" or "//hostname"
        for m in _re.finditer(r'[\\\\//]{2}([A-Za-z][A-Za-z0-9._-]+)', text):
            host = m.group(1).lower()
            if _valid_hostname(host) or _re.match(r'^[a-z][a-z0-9-]{1,15}$', host, _re.IGNORECASE):
                candidates.add(host)

        # Pattern 6: LDAP/AD "DC=sub,DC=domain,DC=tld" → sub.domain.tld
        for m in _re.finditer(r'(?:DC=([^,\s]+),?\s*){2,}', text, _re.IGNORECASE):
            # Re-extract all DC components from the full match
            dcs = _re.findall(r'DC=([^,\s]+)', m.group(0), _re.IGNORECASE)
            if len(dcs) >= 2:
                domain = ".".join(dcs).lower()
                if _valid_hostname(domain):
                    candidates.add(domain)

        # Pattern 7: crackmapexec/netexec "[+] 10.0.0.5:445" or "SMB  10.0.0.5  445"
        for m in _re.finditer(
            r'(?:SMB|LDAP|RDP|WinRM|SSH|MSSQL|FTP)\s+'
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            text, _re.IGNORECASE
        ):
            candidates.add(m.group(1))

        # Filter candidates
        for host in candidates:
            host_lower = host.lower().strip(".")
            if not host_lower:
                continue
            if host_lower in existing:
                continue

            # Skip loopback/link-local/multicast IPs
            if _re.match(r'^\d+\.\d+\.\d+\.\d+$', host_lower):
                if _is_skippable_ip(host_lower):
                    continue

            # Scope check — only add in-scope hosts
            if self.scope_enforcer:
                in_scope, _ = self.scope_enforcer.is_in_scope(host_lower)
                if not in_scope:
                    continue

            # Add to discovered_hosts
            self.discovered_hosts.append({
                "host": host_lower,
                "source": source,
                "discovered_at": datetime.now().isoformat(),
            })
            existing.add(host_lower)

            # Also register in target_manager
            self.target_manager.add_host(host_lower, source=source)

            added += 1

        if added:
            self.save()
        return added

    # --- Serialization (one source of truth) ---

    def _to_dict(self) -> dict:
        """Serialize all state to a dict."""
        data = {}
        for attr, key, _ in _FIELDS:
            data[key] = getattr(self, attr)
        # Derived / subsystem fields
        data["ctf_mode"] = self.engagement_mode == "ctf"
        data["target_manager"] = self.target_manager.to_dict()
        data["task_ledger"] = self.task_ledger.to_dict()
        data["phases"] = self.phases.to_dict()
        data["saved_at"] = datetime.now().isoformat()
        return data

    def _from_dict(self, data: dict):
        """Restore state from a dict. Rebuilds all subsystems."""
        for attr, key, default_spec in _FIELDS:
            setattr(self, attr, data.get(key, _default(default_spec)))
        self.ctf_mode = self.engagement_mode == "ctf"

        # Rebuild scope
        self._rebuild_scope()

        # Restore target manager
        tm_data = data.get("target_manager", [])
        self.target_manager = TargetManager()
        if tm_data:
            self.target_manager.load_from_dict(tm_data)
        elif self.targets:
            self.target_manager.add_hosts(self.targets, source="loaded")

        # Restore task ledger
        tl_data = data.get("task_ledger", [])
        self.task_ledger = TaskLedger()
        if tl_data:
            self.task_ledger.load_from_dict(tl_data)

        # Restore phase tracker
        ph_data = data.get("phases", {})
        self.phases = PhaseTracker()
        if ph_data:
            self.phases.load_from_dict(ph_data)

    def save(self):
        """Save engagement state to its per-engagement directory."""
        if not self.target:
            return
        self._update_paths()
        self.state_path.write_text(json.dumps(self._to_dict(), indent=2))

    def load(self) -> bool:
        """Load engagement state from its directory."""
        if not self.state_path.exists():
            return False
        data = json.loads(self.state_path.read_text())
        self._from_dict(data)
        # Recalculate paths in case mode changed after __init__
        self._update_paths()
        # Clean up garbage credentials on load (from overly aggressive parser)
        self.sanitize_credentials()
        return True

    def dashboard(self) -> dict:
        """Return a structured summary of this engagement for display."""
        # Cost and time
        cost = getattr(self, "total_cost", 0.0)
        time_secs = getattr(self, "total_time_secs", 0.0)
        mins, secs = divmod(int(time_secs), 60)
        time_str = f"{mins}m{secs:02d}s" if mins < 60 else f"{mins // 60}h{mins % 60:02d}m"

        # Resume point (truncated)
        resume = getattr(self, "resume_point", "") or ""
        if len(resume) > 80:
            resume = resume[:77] + "..."

        # Last log entries
        log_tail = []
        log_path = self.dir / "engagement.log"
        if log_path.exists():
            try:
                lines = log_path.read_text().strip().split("\n")
                log_tail = lines[-5:]  # last 5 entries
            except Exception:
                pass

        # Findings count from SQLite DB (if it exists)
        findings_count = 0
        findings_by_severity = {}
        findings_db_path = self.dir / "findings.db"
        if findings_db_path.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(findings_db_path))
                row = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
                findings_count = row[0] if row else 0
                for sev_row in conn.execute(
                    "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                ).fetchall():
                    findings_by_severity[sev_row[0]] = sev_row[1]
                conn.close()
            except Exception:
                pass

        # Phase info
        _current = getattr(self.phases, "current", "unknown") if hasattr(self, "phases") else "unknown"
        phase = _current.value if hasattr(_current, "value") else str(_current)

        return {
            "target": self.target,
            "mode": self.engagement_mode,
            "status": self.status,
            "cost": f"${cost:.2f}",
            "cost_raw": cost,
            "time": time_str,
            "time_secs": time_secs,
            "creds": len(self.credentials),
            "hosts": len(self.compromised_hosts),
            "notes": len(self.notes),
            "defenses": len(getattr(self, "defenses", {})),
            "findings": findings_count,
            "findings_by_severity": findings_by_severity,
            "resume": resume,
            "phase": phase,
            "log_tail": log_tail,
            "saved_at": getattr(self, "_to_dict", lambda: {})().get("saved_at", ""),
        }

    # --- Status ---

    @staticmethod
    def nuke(target: str) -> list[str]:
        """Completely delete all data for an engagement. Returns list of deleted paths.

        Removes: engagement directory (state, evidence, findings, plan, checkpoint),
        stuck detector files, and agent session files.
        """
        import shutil
        deleted = []
        safe = target.replace(".", "_").replace("/", "_").replace(":", "_").replace(" ", "_")

        # Delete engagement directory
        eng_dir = ENGAGEMENTS_DIR / safe
        if eng_dir.exists():
            shutil.rmtree(eng_dir)
            deleted.append(str(eng_dir))

        # Delete stuck detector and agent session files
        for pattern in ("_stuck_*.json", "_agent_*.json"):
            for f in ENGAGEMENTS_DIR.glob(pattern):
                try:
                    f.unlink()
                    deleted.append(str(f))
                except Exception:
                    pass

        # Clean up active pointer if it points to this target
        active_file = ENGAGEMENTS_DIR / "_active.json"
        if active_file.exists():
            try:
                import json
                data = json.loads(active_file.read_text())
                if data.get("target") == target:
                    active_file.unlink()
                    deleted.append(str(active_file))
            except Exception:
                pass

        # Clean up tool artifacts on disk that reference this target IP.
        # These cause the agent to find stale data from prior engagements.
        from pathlib import Path
        _safe = target.replace(".", "_")

        # Responder logs
        responder_dir = Path("/usr/share/responder/logs")
        if responder_dir.exists():
            for f in responder_dir.glob(f"*{target}*"):
                try:
                    f.unlink()
                    deleted.append(str(f))
                except Exception:
                    pass
            for f in responder_dir.glob(f"*{_safe}*"):
                try:
                    f.unlink()
                    deleted.append(str(f))
                except Exception:
                    pass

        # Global evidence directory (legacy flat files)
        if EVIDENCE_BASE.exists():
            for f in EVIDENCE_BASE.glob(f"*{_safe}*"):
                try:
                    if f.is_file():
                        f.unlink()
                        deleted.append(str(f))
                    elif f.is_dir():
                        shutil.rmtree(f)
                        deleted.append(str(f))
                except Exception:
                    pass

        # Kerberos ccache files referencing engagement users
        for ccache_dir in [Path.home(), Path.home() / "OffensiveAI"]:
            if ccache_dir.exists():
                for f in ccache_dir.glob("*.ccache"):
                    try:
                        f.unlink()
                        deleted.append(str(f))
                    except Exception:
                        pass

        # /etc/hosts entries (remove lines with this IP)
        hosts_path = Path("/etc/hosts")
        try:
            lines = hosts_path.read_text().splitlines()
            clean_lines = [l for l in lines if target not in l]
            if len(clean_lines) < len(lines):
                hosts_path.write_text("\n".join(clean_lines) + "\n")
                deleted.append(f"/etc/hosts ({len(lines) - len(clean_lines)} lines removed)")
        except PermissionError:
            pass  # Needs sudo — skip silently
        except Exception:
            pass

        return deleted

    def reset_resume(self):
        """Clear the resume checkpoint. Used when the resume_point is stale or wrong."""
        self.resume_point = ""
        self.resume_priority = 0
        self.save()

    def sanitize_credentials(self):
        """Remove obviously invalid credentials (command fragments, prose matches)."""
        import re as _re
        valid = []
        seen = set()  # (username_lower, clean_secret)
        for c in self.credentials:
            user = c.get("username", "")
            secret = c.get("secret", "")
            # Skip single-char usernames or common non-account words
            if len(user) <= 1 or len(secret) < 4:
                continue
            if _re.match(r'^(cache|extraction|set|get|the|and|for|not|but|can|has|was|'
                         r'are|this|that|from|note|step|path|host|cert|hash|key|s|t|n|r|x|e|d)$',
                         user, _re.IGNORECASE):
                continue
            # Skip secrets that are obviously not passwords
            if _re.match(r'^\*', secret) or _re.match(
                r'^(Primary|Secondary|None|True|False|null|undefined)$', secret, _re.IGNORECASE
            ):
                continue
            # Strip leading/trailing quotes and command artifacts
            clean_secret = secret.strip("'\"`,;)(`")
            # Skip secrets containing IP addresses (command fragments like "pass@10.129.32.197")
            if _re.search(r'@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', clean_secret):
                continue
            # Skip secrets that are just IPs or look like command paths
            if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', clean_secret):
                continue
            # Deduplicate: keep only the cleanest version of each user:secret pair
            dedup_key = (user.lower(), clean_secret)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            c["secret"] = clean_secret
            valid.append(c)
        if len(valid) != len(self.credentials):
            self.credentials = valid
            self.save()
        return len(self.credentials)

    def retarget(self, new_ip: str) -> "Engagement":
        """Change the target IP while preserving all engagement state.

        Used when a box resets and gets a new IP but all findings,
        credentials, ACL chains, and capabilities are still valid.

        Creates a new engagement directory, copies state, symlinks evidence,
        and records the IP change.
        """
        import shutil

        old_ip = self.target
        old_dir = self.dir

        # Update target fields
        self.target = new_ip
        self.targets = [new_ip if t == old_ip else t for t in self.targets]
        if new_ip not in self.targets:
            self.targets[0] = new_ip

        # Update target manager
        self.target_manager.add_hosts([new_ip], source="retarget")

        # Record the change
        self.notes.append(
            f"[retarget] IP changed: {old_ip} → {new_ip}. "
            f"All findings, credentials, and attack paths from the previous IP still apply."
        )

        # Update paths to new directory
        self._update_paths()

        # Copy evidence from old directory (symlink to save space)
        if old_dir.exists() and old_dir != self.dir:
            old_evidence = old_dir / "evidence"
            if old_evidence.exists():
                import os
                for f in old_evidence.iterdir():
                    dest = self.evidence_dir / f.name
                    if not dest.exists():
                        try:
                            os.symlink(f.resolve(), dest)
                        except Exception:
                            try:
                                shutil.copy2(f, dest)
                            except Exception:
                                pass

            # Copy attack plan if exists
            old_plan = old_dir / "plan.json"
            if old_plan.exists() and not self.plan_path.exists():
                shutil.copy2(old_plan, self.plan_path)

            # Copy findings DB
            old_findings = old_dir / "findings.db"
            if old_findings.exists() and not self.findings_db_path.exists():
                shutil.copy2(old_findings, self.findings_db_path)

        # Reset resume point (old IP context is stale)
        if self.resume_point and old_ip in self.resume_point:
            self.resume_point = self.resume_point.replace(old_ip, new_ip)

        # Rebuild scope with new IP
        self._rebuild_scope()

        self.save()
        return self

    def mark_solved(self, flags: dict = None):
        """Mark engagement as solved with captured flags."""
        self.status = EngagementStatus.SOLVED
        if flags:
            self.flags = flags
        self.phases.advance(Phase.COMPLETED)
        self.save()

    @property
    def is_solved(self) -> bool:
        # Explicit status always honored
        if self.status == EngagementStatus.SOLVED:
            return True
        # Heuristic detection (resume_point / notes) is CTF-only.
        # In LE/RT mode, SOLVED requires explicit mark_solved() call with
        # proof of exploitation — heuristics cause false positives when
        # the agent narrative mentions "solved" or "objective complete"
        # in a non-literal context.
        if getattr(self, "engagement_mode", "ctf") != "ctf":
            return False
        rp = (self.resume_point or "").upper()
        if "OBJECTIVE COMPLETE" in rp:
            return True
        if any("SOLVED" in n.upper() for n in self.notes):
            return True
        return False

    @property
    def has_exploit_data(self) -> bool:
        return bool(self.credentials or self.capabilities or self.trust_relationships)

    # --- Prompt Summaries ---

    def summary(self) -> str:
        """Compact summary for agent prompts."""
        lines = ["## Engagement State"]

        if self.resume_point:
            lines.append(f"\n### >>> RESUME FROM HERE -- DO NOT REDO EARLIER STEPS <<<")
            lines.append(self.resume_point)
            lines.append("---")

        lines.append(f"- Target: {self.target or 'Not set'}")
        lines.append(f"- Scope: {self.scope or 'Not set'}")
        lines.append(f"- Mode: {'AUTONOMOUS' if self.autonomous else 'Interactive'}")
        lines.append(f"- {self.phases.summary()}")

        if self.compromised_hosts:
            lines.append(f"\n### Compromised Hosts ({len(self.compromised_hosts)})")
            for h in self.compromised_hosts:
                lines.append(f"  - {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]")

        if self.credentials:
            lines.append(f"\n### Credentials ({len(self.credentials)})")
            for c in self.credentials:
                lines.append(f"  - {c['username']} [{c['type']}] from {c.get('source', 'unknown')}")

        if self.discovered_hosts:
            lines.append(f"\n### Discovered Hosts ({len(self.discovered_hosts)})")
            for h in self.discovered_hosts[:20]:
                lines.append(f"  - {h}")
            if len(self.discovered_hosts) > 20:
                lines.append(f"  ... and {len(self.discovered_hosts) - 20} more")

        # Operator directives (from user intervention after Ctrl+C) — show prominently
        directives = [n for n in self.notes if n.startswith("[operator directive]")]
        if directives:
            lines.append(f"\n### ⚠ OPERATOR DIRECTIVES (follow these)")
            for d in directives[-5:]:
                lines.append(f"  - {d.replace('[operator directive] ', '')}")

        if self.notes:
            other_notes = [n for n in self.notes if not n.startswith("[operator directive]")]
            if other_notes:
                lines.append(f"\n### Engagement Notes")
                for n in other_notes[-10:]:
                    lines.append(f"  - {n}")

        # Task ledger (compact in main summary)
        task_summary = self.task_ledger.summary(compact=True)
        if task_summary:
            lines.append(f"\n{task_summary}")

        return "\n".join(lines)

    def synthesis_context(self) -> str:
        """Rich structured context for the synthesis agent."""
        lines = [f"## TARGET: {self.target or 'Unknown'}"]
        if self.engagement_mode == "le":
            lines.append(f"## OBJECTIVE: Identify and document security vulnerabilities (bug bounty / pentest findings)")
        elif self.engagement_mode == "rt":
            lines.append(f"## OBJECTIVE: Achieve operational objectives per rules of engagement")
        else:
            lines.append(f"## OBJECTIVE: Compromise domain admin / get root flag")

        if self.defenses:
            lines.append("\n## DEFENSES (HARD BLOCKLIST)")
            for defense, value in self.defenses.items():
                if value:
                    lines.append(f"  - {defense}: {value}")

        if self.capabilities:
            lines.append(f"\n## ATTACK PRIMITIVES ({len(self.capabilities)})")
            for cap in self.capabilities:
                lines.append(
                    f"  - [{cap.get('account', '?')}] CAN: {cap.get('capability', '?')} "
                    f"ON: {cap.get('target', '?')} -- {cap.get('detail', '')}"
                )

        if self.attack_surfaces:
            lines.append(f"\n## ATTACK SURFACES ({len(self.attack_surfaces)})")
            for surf in self.attack_surfaces:
                lines.append(
                    f"  - [{surf.get('type', '?')}] {surf.get('target', '?')}: "
                    f"{surf.get('detail', '')} (access: {surf.get('access', '?')})"
                )

        if self.trust_relationships:
            lines.append(f"\n## TRUST RELATIONSHIPS ({len(self.trust_relationships)})")
            for tr in self.trust_relationships:
                lines.append(
                    f"  - {tr.get('source', '?')} TRUSTS {tr.get('target', '?')} "
                    f"[{tr.get('type', '?')}]: {tr.get('detail', '')}"
                )

        if self.service_configs:
            lines.append(f"\n## SERVICE CONFIGURATIONS ({len(self.service_configs)})")
            for sc in self.service_configs:
                lines.append(
                    f"  - [{sc.get('service', '?')}] {sc.get('key', '?')} = "
                    f"{sc.get('value', '?')} -> {sc.get('implication', '')}"
                )

        if self.credentials:
            lines.append(f"\n## OWNED ACCOUNTS ({len(self.credentials)})")
            for c in self.credentials:
                lines.append(
                    f"  - {c['username']} [{c['type']}]: {c.get('secret', '***')[:30]} "
                    f"(from: {c.get('source', '?')})"
                )

        exhausted_notes = [n for n in self.notes if "EXHAUSTED" in n or "DEAD" in n]
        unexplored_notes = [n for n in self.notes if "UNEXPLORED" in n]
        other_notes = [n for n in self.notes
                       if "EXHAUSTED" not in n and "DEAD" not in n and "UNEXPLORED" not in n]

        if exhausted_notes:
            lines.append(f"\n## DEAD ENDS ({len(exhausted_notes)})")
            for n in exhausted_notes:
                lines.append(f"  - {n}")

        if unexplored_notes:
            lines.append(f"\n## UNEXPLORED VECTORS ({len(unexplored_notes)})")
            for n in unexplored_notes:
                lines.append(f"  - {n}")

        if other_notes:
            lines.append(f"\n## OTHER NOTES")
            for n in other_notes[-15:]:
                lines.append(f"  - {n}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engagement Manager — lifecycle orchestrator
# ---------------------------------------------------------------------------

class EngagementManager:
    """Manages the lifecycle of engagements. Only ONE engagement is active at a time."""

    _ACTIVE_FILE = ENGAGEMENTS_DIR / "_active.json"

    def __init__(self):
        ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
        self.current: Engagement | None = None
        self._load_active()

    def _load_active(self):
        """On startup, load the last active engagement."""
        if not self._ACTIVE_FILE.exists():
            self._try_legacy_load()
            return
        try:
            data = json.loads(self._ACTIVE_FILE.read_text())
            target = data.get("target", "")
            if not target:
                return
            eng = Engagement(target, data.get("mode", "ctf"))
            if eng.state_path.exists():
                eng.load()
                if eng.is_solved:
                    self.current = None
                    return
                self.current = eng
            else:
                self._try_legacy_load()
        except Exception:
            self._try_legacy_load()

    def _try_legacy_load(self):
        """Attempt migration from legacy flat JSON files (one-time)."""
        session_path = ENGAGEMENTS_DIR / "_session.json"
        if not session_path.exists():
            return
        try:
            data = json.loads(session_path.read_text())
            target = data.get("target", "")
            if not target:
                return
            safe_name = target.replace(".", "_").replace("/", "_").replace(":", "_")
            legacy_path = ENGAGEMENTS_DIR / f"{safe_name}.json"
            if not legacy_path.exists():
                legacy_path = ENGAGEMENTS_DIR / "default.json"
            if not legacy_path.exists():
                return
            eng = self._migrate_legacy(legacy_path)
            if eng and not eng.is_solved:
                self.current = eng
                self._set_active(eng.target, eng.engagement_mode)
        except Exception:
            pass

    def _migrate_legacy(self, legacy_path: Path) -> Engagement | None:
        """Import a legacy flat JSON file into the new directory structure."""
        try:
            data = json.loads(legacy_path.read_text())
            target = data.get("target", "")
            if not target:
                return None
            eng = Engagement(target, data.get("engagement_mode", "ctf"))
            # _from_dict handles all field restoration + subsystem rebuild
            eng._from_dict(data)
            # Detect solved from legacy indicators
            rp = (eng.resume_point or "").upper()
            if "OBJECTIVE COMPLETE" in rp or any("SOLVED" in n.upper() for n in eng.notes):
                eng.status = EngagementStatus.SOLVED
            eng.save()

            # Symlink old evidence into new location
            old_evidence = EVIDENCE_BASE / eng._safe_name()
            if old_evidence.exists() and old_evidence != eng.evidence_dir:
                import os
                for f in old_evidence.iterdir():
                    dest = eng.evidence_dir / f.name
                    if not dest.exists():
                        try:
                            os.symlink(f, dest)
                        except Exception:
                            pass
            return eng
        except Exception:
            return None

    def create(self, target: str, mode: str = "ctf") -> Engagement:
        """Create a new engagement. Saves current if exists."""
        if self.current and self.current.target:
            self.current.save()
        eng = Engagement(target, mode)
        eng.set_target(target)
        eng.save()
        self.current = eng
        self._set_active(target, mode)
        return eng

    def switch(self, target: str) -> Engagement | None:
        """Switch to an existing engagement by target name.

        Searches across all mode directories (ctf/, le/, redteam/).
        Supports exact match, safe-name match, and fuzzy substring match
        so "paypal" finds "paypal_bb" or a target containing "paypal".
        """
        if self.current and self.current.target:
            self.current.save()
        safe_name = target.replace(".", "_").replace("/", "_").replace(":", "_")

        # Pass 1: Exact match on safe name
        for mode in ("ctf", "le", "redteam"):
            eng_dir = ENGAGEMENTS_DIR / mode / safe_name
            state_path = eng_dir / "state.json"
            if state_path.exists():
                eng = Engagement(target, mode)
                eng.load()
                self.current = eng
                self._set_active(target, eng.engagement_mode)
                return eng

        # Fallback: check old flat layout (pre-migration)
        old_dir = ENGAGEMENTS_DIR / safe_name
        if (old_dir / "state.json").exists():
            eng = Engagement(target)
            eng.load()
            self.current = eng
            self._set_active(target, eng.engagement_mode)
            return eng

        # Pass 2: Fuzzy substring match — "paypal" matches "paypal_bb" or
        # a target whose directory name or state.json target contains the query.
        query = target.lower().strip()
        if len(query) >= 3:
            candidates = []
            for mode in ("ctf", "le", "redteam"):
                mode_dir = ENGAGEMENTS_DIR / mode
                if not mode_dir.exists():
                    continue
                for d in mode_dir.iterdir():
                    if not d.is_dir() or d.name.startswith("_"):
                        continue
                    state_path = d / "state.json"
                    if not state_path.exists():
                        continue
                    # Match against directory name and target in state.json
                    dir_name = d.name.lower()
                    if query in dir_name:
                        candidates.append((mode, d.name, dir_name))
                        continue
                    # Also check target field inside state.json
                    try:
                        import json
                        data = json.loads(state_path.read_text())
                        eng_target = data.get("target", "").lower()
                        if query in eng_target:
                            candidates.append((mode, d.name, eng_target))
                    except Exception:
                        pass

            if len(candidates) == 1:
                mode, dir_name, _ = candidates[0]
                # Reconstruct target from state.json
                state_path = ENGAGEMENTS_DIR / mode / dir_name / "state.json"
                try:
                    import json
                    data = json.loads(state_path.read_text())
                    real_target = data.get("target", dir_name.replace("_", "."))
                except Exception:
                    real_target = dir_name.replace("_", ".")
                eng = Engagement(real_target, mode)
                eng.load()
                self.current = eng
                self._set_active(real_target, eng.engagement_mode)
                return eng

        return None

    def list_all(self) -> list[dict]:
        """List all engagements with status, across all mode directories."""
        results = []
        if not ENGAGEMENTS_DIR.exists():
            return results
        for mode in ("ctf", "le", "redteam"):
            mode_dir = ENGAGEMENTS_DIR / mode
            if not mode_dir.exists():
                continue
            for d in sorted(mode_dir.iterdir()):
                if not d.is_dir() or d.name.startswith("_"):
                    continue
                state_path = d / "state.json"
                if not state_path.exists():
                    continue
                try:
                    data = json.loads(state_path.read_text())
                    results.append({
                        "target": data.get("target", d.name),
                        "status": data.get("status", EngagementStatus.ACTIVE),
                        "mode": data.get("engagement_mode", mode),
                        "saved_at": data.get("saved_at", ""),
                        "creds": len(data.get("credentials", [])),
                        "notes": len(data.get("notes", [])),
                        "tasks": len(data.get("task_ledger", [])),
                        "phase": data.get("phases", {}).get("current", "?"),
                    })
                except Exception:
                    pass
        return results

    def dashboard_all(self) -> list[dict]:
        """Load full dashboard data for all engagements across all modes."""
        results = []
        for mode in ("ctf", "le", "redteam"):
            mode_dir = ENGAGEMENTS_DIR / mode
            if not mode_dir.exists():
                continue
            for d in sorted(mode_dir.iterdir()):
                if not d.is_dir() or d.name.startswith("_"):
                    continue
                state_path = d / "state.json"
                if not state_path.exists():
                    continue
                try:
                    eng = Engagement(d.name.replace("_", "."), mode)
                    eng.load()
                    info = eng.dashboard()
                    # Mark if this is the active engagement
                    info["active"] = (
                        self.current is not None
                        and self.current.target == eng.target
                    )
                    results.append(info)
                except Exception:
                    pass
        return results

    def _set_active(self, target: str, mode: str = "ctf"):
        """Mark which engagement is currently active."""
        ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
        data = {"target": target, "mode": mode}
        self._ACTIVE_FILE.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# Backward compatibility alias
# ---------------------------------------------------------------------------

# Code that imports EngagementState will get Engagement directly.
# No shim, no wrapper — Engagement IS the class now.
EngagementState = Engagement
