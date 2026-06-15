"""Multi-target parallel CTF dispatcher (blitz mode).

Spawns one autonomous RedTeamAgent per target, each in its own thread
with isolated engagement state, session, and evidence directory.
No global state mutation — each worker is fully self-contained.
"""

import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable

from agent import RedTeamAgent
from engagement import Engagement, EngagementStatus
from engagement_logger import EngagementLogger


class WorkerStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SOLVED = "solved"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class TargetSpec:
    """A single target in a blitz run."""
    ip: str
    description: str = ""
    points: int = 0
    flag_id: str = ""          # e.g. "Flag 1"
    jumpbox: str = ""          # SSH command for internal targets
    internal: bool = False


@dataclass
class WorkerState:
    """Thread-safe status snapshot for one blitz worker."""
    target: str
    description: str
    status: WorkerStatus = WorkerStatus.QUEUED
    phase: str = "init"
    turns: int = 0
    cost: float = 0.0
    flags_found: dict = field(default_factory=dict)
    last_activity: str = ""
    error: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    thread: threading.Thread | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = 0.0
            if self.start_time:
                end = self.end_time or time.time()
                elapsed = end - self.start_time
            return {
                "target": self.target,
                "description": self.description,
                "status": self.status.value,
                "phase": self.phase,
                "turns": self.turns,
                "cost": self.cost,
                "flags": dict(self.flags_found),
                "last_activity": self.last_activity,
                "error": self.error,
                "elapsed_secs": elapsed,
            }


class BlitzDispatcher:
    """Dispatches autonomous agents against multiple CTF targets concurrently."""

    def __init__(self):
        self._workers: dict[str, WorkerState] = {}  # target IP -> state
        self._stop_events: dict[str, threading.Event] = {}  # target IP -> stop signal
        self._lock = threading.Lock()

    @property
    def active(self) -> bool:
        """True if any workers are still running."""
        with self._lock:
            return any(
                w.status == WorkerStatus.RUNNING
                for w in self._workers.values()
            )

    @property
    def worker_count(self) -> int:
        with self._lock:
            return len(self._workers)

    def launch(
        self,
        targets: list[TargetSpec],
        fast_mode: bool = False,
        custom_prompt: str = "",
        on_event: Callable[[str, str], None] | None = None,
        max_concurrent: int = 5,
    ) -> int:
        """Launch agents against multiple targets.

        Args:
            targets: List of TargetSpec to attack
            fast_mode: Use Sonnet instead of Opus
            custom_prompt: Additional operator context injected into each agent
            on_event: Callback(target, message) for live status updates
            max_concurrent: Max concurrent threads (rate-limits API load)

        Returns:
            Number of targets launched
        """
        launched = 0
        semaphore = threading.Semaphore(max_concurrent)

        for spec in targets:
            if spec.ip in self._workers:
                existing = self._workers[spec.ip]
                if existing.status == WorkerStatus.RUNNING:
                    continue  # Already running

            stop_event = threading.Event()
            worker_state = WorkerState(
                target=spec.ip,
                description=spec.description,
            )

            self._stop_events[spec.ip] = stop_event

            thread = threading.Thread(
                target=self._run_worker,
                args=(spec, worker_state, stop_event, semaphore,
                      fast_mode, custom_prompt, on_event),
                name=f"blitz-{spec.ip}",
                daemon=True,
            )
            worker_state.thread = thread

            with self._lock:
                self._workers[spec.ip] = worker_state

            thread.start()
            launched += 1

        return launched

    def _run_worker(
        self,
        spec: TargetSpec,
        state: WorkerState,
        stop_event: threading.Event,
        semaphore: threading.Semaphore,
        fast_mode: bool,
        custom_prompt: str,
        on_event: Callable | None,
    ):
        """Worker thread: create engagement, run agent autonomously."""
        # Acquire semaphore to limit concurrency
        semaphore.acquire()
        try:
            state.update(status=WorkerStatus.RUNNING, start_time=time.time())

            # Create isolated engagement
            eng = Engagement(spec.ip, "ctf")
            eng.set_target(spec.ip)
            eng.autonomous = True

            # Try to load existing state (resume)
            if eng.state_path.exists():
                eng.load()
                eng.autonomous = True
                if on_event:
                    on_event(spec.ip, f"Resuming ({len(eng.notes)} notes, {len(eng.credentials)} creds)")
            else:
                eng.save()

            # Create standalone agent bound to this engagement
            agent = RedTeamAgent(engagement=eng)
            agent.fast_mode = fast_mode
            agent.state.autonomous = True
            agent.stop_event = stop_event  # Wire external stop signal

            # Build initial prompt
            prompt = self._build_target_prompt(spec, custom_prompt)

            if on_event:
                on_event(spec.ip, "Started")

            # Status callback — updates worker state from agent HUD
            def _on_status(msg: str):
                state.update(last_activity=msg[:100])
                # Parse phase/turn info from HUD format: "T5/25 │ $0.12 │ 2m30s │ recon │ ..."
                parts = msg.split("│")
                if len(parts) >= 4:
                    turn_part = parts[0].strip()
                    turn_match = re.search(r'T(\d+)', turn_part)
                    if turn_match:
                        state.update(turns=int(turn_match.group(1)))
                    phase_part = parts[3].strip() if len(parts) > 3 else ""
                    if phase_part:
                        state.update(phase=phase_part[:20])
                # Track cost from agent state
                cost = getattr(agent.state, "total_cost", 0.0)
                if cost:
                    state.update(cost=cost)

            # Run the agent — this blocks until complete or stopped
            # Agent auto-continues in CTF mode (up to MAX_AUTO_CONTINUES_CTF)
            response = agent.chat(prompt, on_status=_on_status)

            # Check for flag captures
            flags = getattr(agent.state, "_ctf_flags", {})
            if flags:
                state.update(flags_found=dict(flags))

            # Check if solved
            if agent.state.status == EngagementStatus.SOLVED or flags.get("root"):
                state.update(
                    status=WorkerStatus.SOLVED,
                    end_time=time.time(),
                    cost=getattr(agent.state, "total_cost", 0.0),
                )
                if on_event:
                    on_event(spec.ip, f"SOLVED — flags: {flags}")
            elif stop_event.is_set():
                state.update(
                    status=WorkerStatus.STOPPED,
                    end_time=time.time(),
                    cost=getattr(agent.state, "total_cost", 0.0),
                )
                if on_event:
                    on_event(spec.ip, "Stopped by operator")
            else:
                # Agent finished (hit max continues) without solving
                state.update(
                    status=WorkerStatus.STOPPED,
                    end_time=time.time(),
                    cost=getattr(agent.state, "total_cost", 0.0),
                    last_activity=response[:100] if response else "Max continues reached",
                )
                if on_event:
                    on_event(spec.ip, "Finished (max continues)")

            # Save final state
            agent.state.save()

        except Exception as e:
            state.update(
                status=WorkerStatus.ERROR,
                error=str(e)[:200],
                end_time=time.time(),
            )
            if on_event:
                on_event(spec.ip, f"ERROR: {e}")
        finally:
            semaphore.release()

    def _build_target_prompt(self, spec: TargetSpec, custom_prompt: str) -> str:
        """Build the initial exploitation prompt for a target."""
        parts = [f"Target: {spec.ip}"]

        if spec.description:
            parts.append(f"Hint: {spec.description}")

        if spec.flag_id:
            parts.append(f"Flag: {spec.flag_id} ({spec.points}pts)")

        if spec.internal and spec.jumpbox:
            parts.append(
                f"\nThis is an INTERNAL target. You must access it through the jumpbox:\n"
                f"  {spec.jumpbox}\n"
                f"SSH into the jumpbox first, then pivot to {spec.ip} from there.\n"
                f"All commands targeting {spec.ip} must be run FROM the jumpbox."
            )

        parts.append(
            "\nEnumerate this target thoroughly, identify vulnerabilities, "
            "exploit them, and capture all flags (user.txt, root.txt, or "
            "any CTF flag format). Work autonomously until solved."
        )

        if custom_prompt:
            parts.append(f"\nOperator context: {custom_prompt}")

        return "\n".join(parts)

    def stop(self, target: str | None = None):
        """Stop one or all workers.

        Sets the stop event — the agent will finish its current turn
        and not auto-continue further. Does NOT kill subprocesses.
        """
        if target:
            event = self._stop_events.get(target)
            if event:
                event.set()
                worker = self._workers.get(target)
                if worker:
                    worker.update(status=WorkerStatus.STOPPED, end_time=time.time())
        else:
            for ip, event in self._stop_events.items():
                event.set()
                worker = self._workers.get(ip)
                if worker:
                    worker.update(status=WorkerStatus.STOPPED, end_time=time.time())

    def status_table(self) -> str:
        """Return a formatted markdown status table for all workers."""
        if not self._workers:
            return "No blitz targets. Use `/blitz <ip1> <ip2> ...` to launch."

        lines = [
            "## Blitz Status",
            "",
            "| Target | Status | Phase | Turns | Cost | Elapsed | Flags | Activity |",
            "|--------|--------|-------|-------|------|---------|-------|----------|",
        ]

        total_cost = 0.0
        solved = 0
        running = 0

        for ip in sorted(self._workers.keys()):
            snap = self._workers[ip].snapshot()
            elapsed = snap["elapsed_secs"]
            mins, secs = divmod(int(elapsed), 60)
            time_str = f"{mins}m{secs:02d}s" if mins < 60 else f"{mins // 60}h{mins % 60:02d}m"

            status = snap["status"]
            if status == "solved":
                status_icon = "SOLVED"
                solved += 1
            elif status == "running":
                status_icon = "RUNNING"
                running += 1
            elif status == "error":
                status_icon = "ERROR"
            elif status == "stopped":
                status_icon = "STOPPED"
            else:
                status_icon = status.upper()

            flags_str = ""
            if snap["flags"]:
                flag_keys = list(snap["flags"].keys())
                flags_str = ", ".join(flag_keys)

            desc = snap["description"]
            if desc and len(desc) > 25:
                desc = desc[:22] + "..."
            target_str = f"{snap['target']}"
            if desc:
                target_str += f" ({desc})"

            activity = snap["last_activity"][:35] if snap["last_activity"] else ""
            if snap["error"]:
                activity = snap["error"][:35]

            total_cost += snap["cost"]

            lines.append(
                f"| {target_str} | {status_icon} | {snap['phase']} | "
                f"{snap['turns']} | ${snap['cost']:.2f} | {time_str} | "
                f"{flags_str} | {activity} |"
            )

        lines.append("")
        lines.append(
            f"**{solved} solved, {running} running, "
            f"{len(self._workers) - solved - running} stopped/error** "
            f"| Total cost: ${total_cost:.2f}"
        )

        return "\n".join(lines)

    def summary(self) -> dict:
        """Return aggregate stats."""
        snapshots = [w.snapshot() for w in self._workers.values()]
        return {
            "total": len(snapshots),
            "running": sum(1 for s in snapshots if s["status"] == "running"),
            "solved": sum(1 for s in snapshots if s["status"] == "solved"),
            "stopped": sum(1 for s in snapshots if s["status"] == "stopped"),
            "error": sum(1 for s in snapshots if s["status"] == "error"),
            "total_cost": sum(s["cost"] for s in snapshots),
            "total_flags": sum(len(s["flags"]) for s in snapshots),
        }


def parse_targets(text: str) -> list[TargetSpec]:
    """Parse target specifications from user input.

    Supports formats:
        13.59.71.59                          # IP only
        13.59.71.59 Custom services          # IP + description
        Flag 1 (20pts) — 13.59.71.59 — Custom services  # Full CTF format
        10.0.0.12 --jumpbox "ssh ..."        # Internal target
    """
    targets = []
    seen = set()

    # Try structured CTF format first:
    # "Flag N (Xpts) — IP — Description"
    ctf_pattern = re.compile(
        r'Flag\s+(\d+)\s*\((\d+)pts?\)\s*[-—]+\s*'
        r'(\d+\.\d+\.\d+\.\d+)\s*[-—]+\s*(.+)',
        re.IGNORECASE
    )
    for match in ctf_pattern.finditer(text):
        flag_id = f"Flag {match.group(1)}"
        points = int(match.group(2))
        ip = match.group(3)
        desc = match.group(4).strip()
        if ip not in seen:
            seen.add(ip)
            targets.append(TargetSpec(
                ip=ip, description=desc, points=points, flag_id=flag_id
            ))

    if targets:
        return targets

    # Fallback: extract all IPs, then try to grab trailing descriptions
    for ip in re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', text):
        if ip not in seen:
            seen.add(ip)
            # Try to find a description after the IP (e.g. "IP — desc" or "IP desc")
            desc_match = re.search(
                re.escape(ip) + r'\s+[-—]+\s+(.+?)(?:\n|$)', text
            )
            desc = desc_match.group(1).strip() if desc_match else ""
            targets.append(TargetSpec(ip=ip, description=desc))

    return targets
