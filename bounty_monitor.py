"""Bounty Monitor — watch bug bounty platforms for new programs and scope changes.

Polls HackerOne, Bugcrowd (and others via bounty-targets-data) for:
  1. New programs launching
  2. Scope expansions on existing programs (new domains, wildcards, CIDRs)

When qualifying changes are detected, fires a callback so the orchestrator
can auto-create an LE engagement and dispatch recon immediately.

Data sources (in priority order):
  - arkadiyt/bounty-targets-data: all platforms, updated every 30m, zero auth
  - HackerOne API: real-time, requires API key
  - Bugcrowd /engagements.json: public, no scope detail

Usage:
    monitor = BountyMonitor(data_dir, on_new_program=cb1, on_scope_change=cb2)
    monitor.start(interval=300)
"""

import json
import threading
import time
import re
import base64
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ScopeAsset:
    """A single in-scope asset from a bug bounty program."""
    asset_type: str          # url, domain, wildcard, cidr, ip, api, ios, android, other
    identifier: str          # *.example.com, 10.0.0.0/8, https://app.example.com
    eligible_for_bounty: bool = True
    max_severity: str = ""   # critical, high, medium, low
    instruction: str = ""

    def is_web(self) -> bool:
        return self.asset_type in ("url", "domain", "wildcard", "api", "website")

    def is_network(self) -> bool:
        return self.asset_type in ("cidr", "ip", "ip_address")

    def recon_target(self) -> str:
        """Extract the scannable target from this asset."""
        ident = self.identifier.strip()
        if self.asset_type in ("url", "api", "website"):
            parsed = urlparse(ident if "://" in ident else f"https://{ident}")
            return parsed.hostname or ident
        if self.asset_type == "wildcard":
            return ident.lstrip("*.")
        return ident


@dataclass
class Program:
    """A bug bounty program from any platform."""
    name: str
    handle: str
    platform: str            # hackerone, bugcrowd, intigriti, yeswehack
    url: str
    offers_bounties: bool = True
    bounty_min: float = 0
    bounty_max: float = 0
    scopes: list[dict] = field(default_factory=list)  # list of ScopeAsset dicts
    first_seen: str = ""
    last_seen: str = ""
    state: str = ""          # open, paused, etc.

    @property
    def web_targets(self) -> list[str]:
        """Extract scannable web targets from scope."""
        targets = []
        for s in self.scopes:
            asset = ScopeAsset(**s) if isinstance(s, dict) else s
            if asset.is_web() and asset.eligible_for_bounty:
                t = asset.recon_target()
                if t:
                    targets.append(t)
        return targets

    @property
    def all_targets(self) -> list[str]:
        targets = []
        for s in self.scopes:
            asset = ScopeAsset(**s) if isinstance(s, dict) else s
            if asset.eligible_for_bounty:
                t = asset.recon_target()
                if t:
                    targets.append(t)
        return targets


@dataclass
class ProgramDelta:
    """Changes detected between two polling cycles."""
    new_programs: list[Program] = field(default_factory=list)
    scope_expansions: list[dict] = field(default_factory=list)  # {program, new_scopes[]}
    timestamp: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.new_programs or self.scope_expansions)

    def summary(self) -> str:
        parts = []
        if self.new_programs:
            names = ", ".join(p.name for p in self.new_programs[:5])
            if len(self.new_programs) > 5:
                names += f" (+{len(self.new_programs) - 5} more)"
            parts.append(f"{len(self.new_programs)} new programs: {names}")
        if self.scope_expansions:
            for exp in self.scope_expansions[:5]:
                prog = exp["program"]
                count = len(exp["new_scopes"])
                parts.append(f"{prog.name}: +{count} scope assets")
        return "; ".join(parts) if parts else "No changes"


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

@dataclass
class BountyFilter:
    """Criteria for which programs/changes are worth auto-recon."""
    min_bounty: float = 0            # minimum max_bounty to qualify
    platforms: list[str] = field(default_factory=lambda: ["hackerone", "bugcrowd"])
    asset_types: list[str] = field(default_factory=lambda: [
        "url", "domain", "wildcard", "api", "website", "cidr", "ip", "ip_address",
    ])
    paid_only: bool = True           # skip VDPs (offers_bounties=False)
    exclude_handles: list[str] = field(default_factory=list)  # programs to skip

    def accepts_program(self, program: Program) -> bool:
        if program.platform not in self.platforms:
            return False
        if self.paid_only and not program.offers_bounties:
            return False
        if self.min_bounty > 0 and program.bounty_max < self.min_bounty:
            return False
        if program.handle in self.exclude_handles:
            return False
        return True

    def accepts_scope(self, scope: ScopeAsset) -> bool:
        if not scope.eligible_for_bounty:
            return False
        if scope.asset_type not in self.asset_types:
            return False
        return True

    def filter_scopes(self, scopes: list[dict]) -> list[dict]:
        return [s for s in scopes if self.accepts_scope(
            ScopeAsset(**s) if isinstance(s, dict) else s
        )]


# ---------------------------------------------------------------------------
# Data source fetchers
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: dict | None = None, timeout: int = 30) -> tuple[str, int]:
    """HTTP GET via curl. Returns (body, status_code)."""
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-w", "\n%{http_code}"]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        lines = r.stdout.rsplit("\n", 2)
        if len(lines) >= 2:
            body = "\n".join(lines[:-1])
            try:
                status = int(lines[-1].strip())
            except ValueError:
                status = 0
            return body, status
        return r.stdout, 0
    except (subprocess.TimeoutExpired, Exception) as e:
        return str(e), 0


def fetch_bounty_targets_data(platform: str = "hackerone") -> list[Program]:
    """Fetch from arkadiyt/bounty-targets-data (zero auth, all platforms)."""
    base = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
    url = f"{base}/{platform}_data.json"

    body, status = _http_get(url, timeout=60)
    if status != 200:
        return []

    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        return []

    programs = []
    for entry in raw:
        scopes = []

        if platform == "hackerone":
            name = entry.get("name", "")
            handle = entry.get("handle", "")
            url = f"https://hackerone.com/{handle}"
            offers_bounties = entry.get("offers_bounties", False)
            for target in entry.get("targets", {}).get("in_scope", []):
                scopes.append(asdict(ScopeAsset(
                    asset_type=target.get("asset_type", "other").lower(),
                    identifier=target.get("asset_identifier", ""),
                    eligible_for_bounty=target.get("eligible_for_bounty", True),
                    max_severity=target.get("max_severity") or "",
                    instruction=(target.get("instruction") or "")[:200],
                )))

        elif platform == "bugcrowd":
            name = entry.get("name", "")
            handle = entry.get("url", "").rstrip("/").split("/")[-1]
            url = entry.get("url", "")
            max_payout = entry.get("max_payout", 0) or 0
            offers_bounties = max_payout > 0
            for target in entry.get("targets", {}).get("in_scope", []):
                asset_type = target.get("type", "other").lower()
                # Normalize bugcrowd types to common format
                if asset_type == "website":
                    asset_type = "url"
                scopes.append(asdict(ScopeAsset(
                    asset_type=asset_type,
                    identifier=target.get("target", target.get("uri", "")),
                    eligible_for_bounty=True,
                )))

        elif platform == "intigriti":
            name = entry.get("name", "")
            handle = entry.get("company_handle", name.lower().replace(" ", "-"))
            url = f"https://app.intigriti.com/programs/{handle}"
            min_bounty = entry.get("min_bounty", {}).get("value", 0) or 0
            max_bounty = entry.get("max_bounty", {}).get("value", 0) or 0
            offers_bounties = max_bounty > 0
            for target in entry.get("targets", {}).get("in_scope", []):
                scopes.append(asdict(ScopeAsset(
                    asset_type=target.get("type", "other").lower(),
                    identifier=target.get("endpoint", ""),
                    eligible_for_bounty=True,
                )))

        elif platform == "yeswehack":
            name = entry.get("title", "")
            handle = entry.get("slug", name.lower().replace(" ", "-"))
            url = f"https://yeswehack.com/programs/{handle}"
            min_bounty = entry.get("bounty_min", 0) or 0
            max_bounty = entry.get("bounty_max", 0) or 0
            offers_bounties = max_bounty > 0
            for scope_entry in entry.get("scopes", []):
                scopes.append(asdict(ScopeAsset(
                    asset_type=scope_entry.get("scope_type", "other").lower(),
                    identifier=scope_entry.get("scope", ""),
                    eligible_for_bounty=True,
                )))

        if not name:
            continue

        prog = Program(
            name=name,
            handle=handle,
            platform=platform,
            url=url,
            offers_bounties=offers_bounties,
            scopes=scopes,
        )

        # Extract bounty range where available
        if platform == "bugcrowd":
            prog.bounty_max = entry.get("max_payout", 0) or 0
        elif platform == "hackerone":
            # H1 bounty-targets-data doesn't include bounty ranges directly
            # but offers_bounties flag is reliable
            pass

        programs.append(prog)

    return programs


def fetch_hackerone_api(username: str, token: str, max_pages: int = 20) -> list[Program]:
    """Fetch programs directly from HackerOne API (real-time, requires auth)."""
    programs = []
    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}

    for page in range(1, max_pages + 1):
        url = f"https://api.hackerone.com/v1/hackers/programs?page[number]={page}&page[size]=100"
        body, status = _http_get(url, headers=headers, timeout=30)
        if status != 200:
            break

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            break

        entries = data.get("data", [])
        if not entries:
            break

        for entry in entries:
            attrs = entry.get("attributes", {})
            handle = attrs.get("handle", "")
            prog = Program(
                name=attrs.get("name", handle),
                handle=handle,
                platform="hackerone",
                url=f"https://hackerone.com/{handle}",
                offers_bounties=attrs.get("offers_bounties", False),
                state=attrs.get("submission_state", ""),
            )
            programs.append(prog)

    # Fetch scopes for each program (expensive — only do for new/changed)
    return programs


def fetch_hackerone_scopes(handle: str, username: str, token: str) -> list[dict]:
    """Fetch structured scopes for a specific H1 program."""
    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}

    scopes = []
    for page in range(1, 10):
        url = (f"https://api.hackerone.com/v1/hackers/programs/{handle}"
               f"/structured_scopes?page[number]={page}&page[size]=100")
        body, status = _http_get(url, headers=headers)
        if status != 200:
            break

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            break

        entries = data.get("data", [])
        if not entries:
            break

        for entry in entries:
            attrs = entry.get("attributes", {})
            scopes.append(asdict(ScopeAsset(
                asset_type=attrs.get("asset_type", "other").lower(),
                identifier=attrs.get("asset_identifier", ""),
                eligible_for_bounty=attrs.get("eligible_for_bounty", True),
                max_severity=attrs.get("max_severity") or "",
                instruction=(attrs.get("instruction") or "")[:200],
            )))

    return scopes


def fetch_bugcrowd_public(max_pages: int = 10) -> list[Program]:
    """Fetch from Bugcrowd's public engagements endpoint (no auth, no scope detail)."""
    programs = []

    for offset in range(0, max_pages * 25, 25):
        url = (f"https://bugcrowd.com/engagements.json"
               f"?category=bug_bounty&sort_by=promoted&sort_direction=desc"
               f"&offset={offset}&limit=25")
        body, status = _http_get(url)
        if status != 200:
            break

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            break

        engagements = data.get("engagements", [])
        if not engagements:
            break

        for eng in engagements:
            reward = eng.get("rewardSummary", {})
            min_reward = _parse_bounty(reward.get("minReward", ""))
            max_reward = _parse_bounty(reward.get("maxReward", ""))
            brief_url = eng.get("briefUrl", "")
            handle = brief_url.strip("/").split("/")[-1] if brief_url else ""

            prog = Program(
                name=eng.get("name", ""),
                handle=handle,
                platform="bugcrowd",
                url=f"https://bugcrowd.com{brief_url}" if brief_url else "",
                offers_bounties=max_reward > 0,
                bounty_min=min_reward,
                bounty_max=max_reward,
                state=eng.get("accessStatus", ""),
            )
            programs.append(prog)

    return programs


def _parse_bounty(s: str) -> float:
    """Parse '$1,500' or '$250' into a float."""
    if not s:
        return 0
    cleaned = re.sub(r"[^\d.]", "", s)
    try:
        return float(cleaned)
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def compute_program_diff(
    old_state: dict[str, Program],
    new_programs: list[Program],
    bounty_filter: BountyFilter,
) -> ProgramDelta:
    """Compare old program state against freshly fetched programs.

    Returns delta with new programs and scope expansions that pass the filter.
    """
    delta = ProgramDelta(timestamp=datetime.now().isoformat())

    for prog in new_programs:
        key = f"{prog.platform}:{prog.handle}"

        if not bounty_filter.accepts_program(prog):
            continue

        if key not in old_state:
            # New program — filter scopes
            filtered = bounty_filter.filter_scopes(prog.scopes)
            if filtered:
                prog.scopes = filtered
                prog.first_seen = delta.timestamp
                prog.last_seen = delta.timestamp
                delta.new_programs.append(prog)
        else:
            # Existing program — check for scope expansion
            old_prog = old_state[key]
            old_identifiers = {s.get("identifier", "") for s in old_prog.scopes}
            new_scopes = []
            for scope in prog.scopes:
                ident = scope.get("identifier", "")
                if ident and ident not in old_identifiers:
                    asset = ScopeAsset(**scope) if isinstance(scope, dict) else scope
                    if bounty_filter.accepts_scope(asset):
                        new_scopes.append(scope)

            if new_scopes:
                delta.scope_expansions.append({
                    "program": prog,
                    "new_scopes": new_scopes,
                })

    return delta


# ---------------------------------------------------------------------------
# BountyMonitor — the main class
# ---------------------------------------------------------------------------

class BountyMonitor:
    """Watches bug bounty platforms for new programs and scope expansions.

    Runs as a background daemon thread. When qualifying changes are detected,
    fires callbacks that the orchestrator uses to auto-create engagements
    and dispatch recon.
    """

    def __init__(
        self,
        data_dir: Path,
        on_new_program: Callable[[Program], None] | None = None,
        on_scope_change: Callable[[Program, list[dict]], None] | None = None,
        on_status: Callable[[str], None] | None = None,
        bounty_filter: BountyFilter | None = None,
        h1_username: str = "",
        h1_token: str = "",
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.on_new_program = on_new_program
        self.on_scope_change = on_scope_change
        self.on_status = on_status
        self.bounty_filter = bounty_filter or BountyFilter()

        # HackerOne API credentials (optional — falls back to bounty-targets-data)
        self.h1_username = h1_username
        self.h1_token = h1_token

        # Monitor state
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._interval: int = 300
        self._running: bool = False
        self._cycle_count: int = 0
        self._new_program_count: int = 0
        self._scope_change_count: int = 0
        self._last_poll: str = ""
        self._last_delta: ProgramDelta | None = None

        # Persistence paths
        self._state_path = self.data_dir / "bounty_programs.json"
        self._history_path = self.data_dir / "bounty_history.json"
        self._config_path = self.data_dir / "bounty_config.json"
        self._filter_path = self.data_dir / "bounty_filter.json"

        # Load persisted state
        self._programs: dict[str, Program] = {}  # "platform:handle" -> Program
        self._load_state()
        self._load_config()

    # --- Persistence ---

    def _load_state(self):
        """Load known programs from disk."""
        if not self._state_path.exists():
            return
        try:
            raw = json.loads(self._state_path.read_text())
            for key, pdata in raw.items():
                self._programs[key] = Program(**pdata)
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    def _save_state(self):
        """Save known programs to disk."""
        raw = {}
        for key, prog in self._programs.items():
            raw[key] = asdict(prog)
        self._state_path.write_text(json.dumps(raw, indent=2, default=str))

    def _load_config(self):
        if not self._config_path.exists():
            return
        try:
            cfg = json.loads(self._config_path.read_text())
            self._interval = cfg.get("interval", self._interval)
            self._cycle_count = cfg.get("cycle_count", 0)
            self._new_program_count = cfg.get("new_program_count", 0)
            self._scope_change_count = cfg.get("scope_change_count", 0)
        except (json.JSONDecodeError, KeyError):
            pass

    def _save_config(self):
        cfg = {
            "interval": self._interval,
            "cycle_count": self._cycle_count,
            "new_program_count": self._new_program_count,
            "scope_change_count": self._scope_change_count,
        }
        self._config_path.write_text(json.dumps(cfg, indent=2))

    def _append_history(self, delta: ProgramDelta):
        history = []
        if self._history_path.exists():
            try:
                history = json.loads(self._history_path.read_text())
            except json.JSONDecodeError:
                pass

        entry = {
            "timestamp": delta.timestamp,
            "new_programs": [
                {"name": p.name, "handle": p.handle, "platform": p.platform,
                 "url": p.url, "targets": len(p.all_targets)}
                for p in delta.new_programs
            ],
            "scope_expansions": [
                {"name": e["program"].name, "platform": e["program"].platform,
                 "new_assets": len(e["new_scopes"])}
                for e in delta.scope_expansions
            ],
        }
        history.append(entry)

        # Keep last 200 entries
        if len(history) > 200:
            history = history[-200:]
        self._history_path.write_text(json.dumps(history, indent=2))

    def save_filter(self):
        """Persist current filter settings."""
        self._filter_path.write_text(json.dumps(asdict(self.bounty_filter), indent=2))

    def load_filter(self):
        """Load filter settings from disk."""
        if self._filter_path.exists():
            try:
                data = json.loads(self._filter_path.read_text())
                self.bounty_filter = BountyFilter(**data)
            except (json.JSONDecodeError, TypeError):
                pass

    # --- Fetching ---

    def _fetch_all(self) -> list[Program]:
        """Fetch programs from all configured sources."""
        all_programs = []

        platforms = self.bounty_filter.platforms

        # Primary: bounty-targets-data (covers all platforms with scope)
        for platform in platforms:
            if self.on_status:
                self.on_status(f"[bounty] Fetching {platform} via bounty-targets-data...")
            programs = fetch_bounty_targets_data(platform)
            if programs:
                all_programs.extend(programs)
                if self.on_status:
                    self.on_status(f"[bounty] {platform}: {len(programs)} programs")

        # Optional: direct H1 API for faster detection (if credentials configured)
        if self.h1_username and self.h1_token and "hackerone" in platforms:
            if self.on_status:
                self.on_status("[bounty] Supplementing with HackerOne API (real-time)...")
            h1_direct = fetch_hackerone_api(self.h1_username, self.h1_token)
            if h1_direct:
                # Merge: H1 API programs that aren't already in bounty-targets-data
                existing_handles = {p.handle for p in all_programs if p.platform == "hackerone"}
                new_from_api = [p for p in h1_direct if p.handle not in existing_handles]
                if new_from_api:
                    # Fetch scopes for truly new programs
                    for prog in new_from_api:
                        prog.scopes = fetch_hackerone_scopes(
                            prog.handle, self.h1_username, self.h1_token
                        )
                    all_programs.extend(new_from_api)
                    if self.on_status:
                        self.on_status(
                            f"[bounty] H1 API: {len(new_from_api)} programs not yet in bounty-targets-data"
                        )

        return all_programs

    # --- Polling cycle ---

    def run_cycle(self) -> ProgramDelta:
        """Run one polling cycle. Fetch, diff, update state, fire callbacks."""
        all_programs = self._fetch_all()

        if not all_programs:
            if self.on_status:
                self.on_status("[bounty] No programs fetched (network error?)")
            return ProgramDelta(timestamp=datetime.now().isoformat())

        # Compute diff
        delta = compute_program_diff(self._programs, all_programs, self.bounty_filter)

        if delta.has_changes:
            if self.on_status:
                self.on_status(f"[bounty] CHANGES DETECTED: {delta.summary()}")
            self._append_history(delta)

            # Fire callbacks
            for prog in delta.new_programs:
                self._new_program_count += 1
                if self.on_new_program:
                    try:
                        self.on_new_program(prog)
                    except Exception as e:
                        if self.on_status:
                            self.on_status(f"[bounty] Callback error (new program): {e}")

            for expansion in delta.scope_expansions:
                self._scope_change_count += 1
                if self.on_scope_change:
                    try:
                        self.on_scope_change(expansion["program"], expansion["new_scopes"])
                    except Exception as e:
                        if self.on_status:
                            self.on_status(f"[bounty] Callback error (scope change): {e}")
        else:
            if self.on_status:
                self.on_status(f"[bounty] No changes ({len(all_programs)} programs checked)")

        # Update state with ALL programs (not just filtered ones, so we track everything)
        now = datetime.now().isoformat()
        for prog in all_programs:
            key = f"{prog.platform}:{prog.handle}"
            if key in self._programs:
                # Update existing — merge scopes, update last_seen
                existing = self._programs[key]
                existing.last_seen = now
                # Update scopes to latest
                existing.scopes = prog.scopes
                existing.offers_bounties = prog.offers_bounties
                existing.bounty_min = prog.bounty_min
                existing.bounty_max = prog.bounty_max
            else:
                prog.first_seen = now
                prog.last_seen = now
                self._programs[key] = prog

        self._cycle_count += 1
        self._last_poll = now
        self._last_delta = delta
        self._save_state()
        self._save_config()
        return delta

    # --- Background thread ---

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                self.run_cycle()
            except Exception as e:
                if self.on_status:
                    self.on_status(f"[bounty] Cycle error: {e}")
            self._stop_event.wait(self._interval)

    def start(self, interval: int | None = None):
        if self._running:
            if self.on_status:
                self.on_status("[bounty] Already running")
            return

        if interval is not None:
            self._interval = max(60, interval)

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="redops-bounty-monitor",
            daemon=True,
        )
        self._thread.start()
        if self.on_status:
            self.on_status(
                f"[bounty] Started — polling every {self._interval}s "
                f"({self._interval // 60}m). "
                f"Platforms: {', '.join(self.bounty_filter.platforms)}"
            )

    def stop(self):
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=15)
        self._running = False
        self._save_config()
        if self.on_status:
            self.on_status(
                f"[bounty] Stopped. {self._cycle_count} cycles, "
                f"{self._new_program_count} new programs, "
                f"{self._scope_change_count} scope changes detected total."
            )

    def is_running(self) -> bool:
        return self._running

    def set_interval(self, seconds: int):
        self._interval = max(60, seconds)
        self._save_config()

    # --- Status / Info ---

    def status(self) -> str:
        lines = [
            "## Bounty Monitor Status",
            "",
            f"- **Running:** {'YES' if self._running else 'NO'}",
            f"- **Interval:** {self._interval}s ({self._interval // 60}m)",
            f"- **Cycles:** {self._cycle_count}",
            f"- **New programs found:** {self._new_program_count}",
            f"- **Scope expansions found:** {self._scope_change_count}",
            f"- **Last poll:** {self._last_poll[:19] if self._last_poll else 'never'}",
            f"- **Programs tracked:** {len(self._programs)}",
            "",
            "### Filter",
            f"- Platforms: {', '.join(self.bounty_filter.platforms)}",
            f"- Paid only: {self.bounty_filter.paid_only}",
            f"- Min bounty: ${self.bounty_filter.min_bounty:.0f}",
            f"- Asset types: {', '.join(self.bounty_filter.asset_types)}",
            f"- Excluded: {', '.join(self.bounty_filter.exclude_handles) or 'none'}",
        ]

        if self.h1_username:
            lines.append(f"- H1 API: configured (user: {self.h1_username})")
        else:
            lines.append("- H1 API: not configured (using bounty-targets-data only)")

        # Recent changes
        if self._history_path.exists():
            try:
                history = json.loads(self._history_path.read_text())
                recent = history[-10:]
                if recent:
                    lines.append("")
                    lines.append("### Recent Activity")
                    for entry in reversed(recent):
                        ts = entry["timestamp"][:16]
                        new_count = len(entry.get("new_programs", []))
                        exp_count = len(entry.get("scope_expansions", []))
                        parts = []
                        if new_count:
                            names = ", ".join(
                                p["name"] for p in entry["new_programs"][:3]
                            )
                            parts.append(f"+{new_count} programs ({names})")
                        if exp_count:
                            names = ", ".join(
                                e["name"] for e in entry["scope_expansions"][:3]
                            )
                            parts.append(f"+{exp_count} scope changes ({names})")
                        if parts:
                            lines.append(f"- [{ts}] {'; '.join(parts)}")
            except (json.JSONDecodeError, KeyError):
                pass

        return "\n".join(lines)

    def list_programs(self, platform: str = "", limit: int = 20,
                      sort_by: str = "first_seen") -> list[Program]:
        """List tracked programs, optionally filtered by platform."""
        progs = list(self._programs.values())
        if platform:
            progs = [p for p in progs if p.platform == platform]
        if sort_by == "first_seen":
            progs.sort(key=lambda p: p.first_seen or "", reverse=True)
        elif sort_by == "bounty":
            progs.sort(key=lambda p: p.bounty_max, reverse=True)
        elif sort_by == "name":
            progs.sort(key=lambda p: p.name.lower())
        return progs[:limit]

    def get_program(self, handle: str, platform: str = "") -> Program | None:
        """Look up a specific program by handle."""
        if platform:
            return self._programs.get(f"{platform}:{handle}")
        # Search all platforms
        for key, prog in self._programs.items():
            if prog.handle == handle:
                return prog
        return None

    @property
    def program_count(self) -> int:
        return len(self._programs)

    def reset(self):
        """Clear all tracked state (start fresh)."""
        self._programs.clear()
        self._cycle_count = 0
        self._new_program_count = 0
        self._scope_change_count = 0
        self._last_poll = ""
        self._last_delta = None
        for path in (self._state_path, self._history_path):
            if path.exists():
                path.unlink()
        self._save_config()
