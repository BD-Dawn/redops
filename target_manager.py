"""Multi-target management layer — handles multiple hosts simultaneously.

Tracks per-host state, priority, agent assignments, and findings counts.
The orchestrator uses this to dispatch agents across hosts in priority order.
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class HostState:
    """Per-host tracking state."""

    host: str
    status: str = "discovered"  # discovered | triaged | active | exploited | completed | skipped
    priority: int = 0           # Higher = more promising (set by triage agent)
    priority_reason: str = ""
    assigned_agents: list[str] = field(default_factory=list)
    findings_count: int = 0
    last_activity: str = ""     # ISO timestamp
    source: str = "manual"      # How this host was added: manual | recon | nmap | dns
    metadata: dict = field(default_factory=dict)  # Ports, services, OS, etc.

    def is_available(self) -> bool:
        """Host is available for new agent dispatch."""
        return self.status in ("discovered", "triaged") and not self.assigned_agents


VALID_STATUSES = {"discovered", "triaged", "active", "exploited", "completed", "skipped"}


class TargetManager:
    """Manages multiple hosts with priority sorting and agent assignment tracking.

    Thread-safe for concurrent access from parallel agent dispatches.
    """

    def __init__(self):
        self.hosts: dict[str, HostState] = {}
        self._lock = threading.Lock()

    def add_hosts(self, hosts: list[str], source: str = "manual") -> int:
        """Add hosts to the target list. Skips duplicates. Returns count of new hosts added."""
        added = 0
        with self._lock:
            for host in hosts:
                host = host.strip()
                if not host:
                    continue
                canonical = self._canonicalize(host)
                if canonical not in self.hosts:
                    self.hosts[canonical] = HostState(
                        host=canonical,
                        source=source,
                        last_activity=datetime.now().isoformat(),
                    )
                    added += 1
        return added

    def add_host(self, host: str, source: str = "manual", priority: int = 0,
                 metadata: dict | None = None) -> HostState:
        """Add a single host with optional metadata. Returns the HostState."""
        host = self._canonicalize(host.strip())
        with self._lock:
            if host not in self.hosts:
                self.hosts[host] = HostState(
                    host=host,
                    source=source,
                    priority=priority,
                    metadata=metadata or {},
                    last_activity=datetime.now().isoformat(),
                )
            else:
                # Update existing
                if priority:
                    self.hosts[host].priority = priority
                if metadata:
                    self.hosts[host].metadata.update(metadata)
            return self.hosts[host]

    def get_next_targets(self, count: int = 3) -> list[HostState]:
        """Get the top N targets by priority that are available for dispatch.

        Returns hosts sorted by priority (descending), filtered to
        status in (discovered, triaged) and no current agent assignments.
        """
        with self._lock:
            available = [
                h for h in self.hosts.values()
                if h.is_available()
            ]
        # Sort by priority descending, then by discovery order
        available.sort(key=lambda h: (-h.priority, h.host))
        return available[:count]

    def get_all_by_status(self, status: str) -> list[HostState]:
        """Get all hosts with a given status."""
        with self._lock:
            return [h for h in self.hosts.values() if h.status == status]

    def assign_agent(self, host: str, agent_name: str) -> None:
        """Mark an agent as working on a host."""
        host = self._canonicalize(host)
        with self._lock:
            if host in self.hosts:
                hs = self.hosts[host]
                if agent_name not in hs.assigned_agents:
                    hs.assigned_agents.append(agent_name)
                hs.status = "active"
                hs.last_activity = datetime.now().isoformat()

    def release_agent(self, host: str, agent_name: str) -> None:
        """Remove an agent assignment from a host."""
        host = self._canonicalize(host)
        with self._lock:
            if host in self.hosts:
                hs = self.hosts[host]
                if agent_name in hs.assigned_agents:
                    hs.assigned_agents.remove(agent_name)
                # If no agents remain, keep status as-is (active stays active)

    def update_status(self, host: str, status: str) -> None:
        """Update host status."""
        if status not in VALID_STATUSES:
            return
        host = self._canonicalize(host)
        with self._lock:
            if host in self.hosts:
                self.hosts[host].status = status
                self.hosts[host].last_activity = datetime.now().isoformat()

    def update_priority(self, host: str, priority: int, reason: str = "") -> None:
        """Update host priority (set by triage agent)."""
        host = self._canonicalize(host)
        with self._lock:
            if host in self.hosts:
                self.hosts[host].priority = priority
                self.hosts[host].priority_reason = reason

    def update_metadata(self, host: str, metadata: dict) -> None:
        """Merge metadata into host state (ports, services, OS, etc.)."""
        host = self._canonicalize(host)
        with self._lock:
            if host in self.hosts:
                self.hosts[host].metadata.update(metadata)

    def update_findings_count(self, host: str, count: int) -> None:
        """Update cached findings count for a host."""
        host = self._canonicalize(host)
        with self._lock:
            if host in self.hosts:
                self.hosts[host].findings_count = count

    def get_active_hosts(self) -> list[HostState]:
        """Get all hosts with agents currently assigned."""
        with self._lock:
            return [h for h in self.hosts.values() if h.assigned_agents]

    def summary(self) -> str:
        """Rich text summary of all hosts for display."""
        with self._lock:
            hosts = sorted(self.hosts.values(), key=lambda h: (-h.priority, h.host))

        if not hosts:
            return "No targets registered."

        lines = [
            f"## Targets ({len(hosts)})",
            "",
            "| Host | Status | Priority | Agents | Findings | Source |",
            "|------|--------|----------|--------|----------|--------|",
        ]

        for h in hosts:
            agents_str = ", ".join(h.assigned_agents) if h.assigned_agents else "-"
            priority_str = f"{h.priority}"
            if h.priority_reason:
                priority_str += f" ({h.priority_reason[:30]})"
            lines.append(
                f"| {h.host} | {h.status} | {priority_str} | "
                f"{agents_str} | {h.findings_count} | {h.source} |"
            )

        return "\n".join(lines)

    def summary_for_prompt(self) -> str:
        """Compact summary suitable for injection into agent prompts."""
        with self._lock:
            hosts = sorted(self.hosts.values(), key=lambda h: (-h.priority, h.host))

        if not hosts:
            return ""

        lines = ["## Target Hosts"]
        for h in hosts:
            status_tag = f"[{h.status.upper()}]"
            priority_tag = f"P{h.priority}" if h.priority else ""
            agents_tag = f" (agents: {', '.join(h.assigned_agents)})" if h.assigned_agents else ""
            lines.append(f"- {h.host} {status_tag} {priority_tag}{agents_tag}")

        return "\n".join(lines)

    def to_dict(self) -> list[dict]:
        """Serialize for JSON persistence."""
        with self._lock:
            return [
                {
                    "host": h.host,
                    "status": h.status,
                    "priority": h.priority,
                    "priority_reason": h.priority_reason,
                    "assigned_agents": h.assigned_agents,
                    "findings_count": h.findings_count,
                    "last_activity": h.last_activity,
                    "source": h.source,
                    "metadata": h.metadata,
                }
                for h in self.hosts.values()
            ]

    def load_from_dict(self, data: list[dict]) -> None:
        """Restore from serialized data."""
        with self._lock:
            self.hosts.clear()
            for item in data:
                host = item["host"]
                self.hosts[host] = HostState(
                    host=host,
                    status=item.get("status", "discovered"),
                    priority=item.get("priority", 0),
                    priority_reason=item.get("priority_reason", ""),
                    assigned_agents=item.get("assigned_agents", []),
                    findings_count=item.get("findings_count", 0),
                    last_activity=item.get("last_activity", ""),
                    source=item.get("source", "loaded"),
                    metadata=item.get("metadata", {}),
                )

    @staticmethod
    def _canonicalize(host: str) -> str:
        """Normalize host string for consistent keying."""
        host = host.strip().lower()
        # Strip trailing dots from domains
        if not host.replace(".", "").isdigit():
            host = host.rstrip(".")
        # Strip protocol from URLs if someone passes a URL as a host
        if host.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            parsed = urlparse(host)
            host = parsed.hostname or host
        return host
