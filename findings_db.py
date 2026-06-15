"""Structured findings database — SQLite-backed queryable storage for engagement findings.

Agents write findings via the Python API. Other agents and the orchestrator
can query findings without eating context window. Used by the exit evaluator
for metric counting and by the report generator for structured output.
"""

import sqlite3
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import EVIDENCE_DIR, ENGAGEMENTS_DIR


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ordered by severity for comparison
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class FindingType(str, Enum):
    VULN = "vulnerability"
    CREDENTIAL = "credential"
    HOST = "host_discovery"
    SERVICE = "service"
    MISCONFIG = "misconfiguration"
    ACCESS = "access_gained"
    CVE = "cve"
    SECRET = "secret"


class PocStatus:
    PENDING = "pending"          # Not yet verified
    CONFIRMED = "confirmed"      # PoC succeeded — reproducible
    UNCONFIRMED = "unconfirmed"  # PoC attempted, couldn't reproduce
    MANUAL = "manual_required"   # Agent can't PoC this — needs operator


@dataclass
class Finding:
    """A single structured finding from an agent."""
    host: str
    port: int | None = None
    service: str = ""
    finding_type: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    evidence: str = ""
    evidence_path: str = ""
    cve_id: str = ""
    agent: str = ""
    tags: str = ""
    exploitable: bool = False
    exploited: bool = False
    poc_status: str = PocStatus.PENDING
    poc_script: str = ""          # Reproducible PoC command/script (if confirmed)
    poc_instructions: str = ""    # Manual PoC steps for operator (if manual_required)


class FindingsDB:
    """SQLite-backed findings database with thread-safe concurrent access.

    Each engagement should pass its own db_path (from engagement.findings_db_path).
    The class-level DB_PATH is a fallback for backward compat only.
    """

    DB_PATH = EVIDENCE_DIR / "findings.db"

    def __init__(self, db_path: Path | None = None):
        self._db_path = str(db_path or self.DB_PATH)
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local connection (SQLite connections aren't thread-safe)."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER,
                service TEXT DEFAULT '',
                finding_type TEXT DEFAULT '',
                severity TEXT DEFAULT 'info',
                title TEXT DEFAULT '',
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                evidence_path TEXT DEFAULT '',
                cve_id TEXT DEFAULT '',
                agent TEXT DEFAULT '',
                tags TEXT DEFAULT '',
                exploitable INTEGER DEFAULT 0,
                exploited INTEGER DEFAULT 0,
                poc_status TEXT DEFAULT 'pending',
                poc_script TEXT DEFAULT '',
                poc_instructions TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
            CREATE INDEX IF NOT EXISTS idx_findings_agent ON findings(agent);
            CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
        """)
        conn.commit()
        # Migrate existing DBs — add PoC columns if missing
        self._migrate_poc_columns(conn)

    def _migrate_poc_columns(self, conn):
        """Add PoC columns to existing databases that don't have them."""
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
            for col, default in [
                ("poc_status", "'pending'"),
                ("poc_script", "''"),
                ("poc_instructions", "''"),
            ]:
                if col not in cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT {default}")
            conn.commit()
        except Exception:
            pass  # Best-effort migration

    def add(self, finding: Finding) -> int:
        """Insert a finding and return its ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO findings
               (host, port, service, finding_type, severity, title, description,
                evidence, evidence_path, cve_id, agent, tags, exploitable, exploited,
                poc_status, poc_script, poc_instructions)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.host,
                finding.port,
                finding.service,
                finding.finding_type,
                finding.severity,
                finding.title,
                finding.description,
                finding.evidence[:5000],  # Truncate evidence to avoid bloat
                finding.evidence_path,
                finding.cve_id,
                finding.agent,
                finding.tags,
                int(finding.exploitable),
                int(finding.exploited),
                finding.poc_status,
                finding.poc_script[:5000],
                finding.poc_instructions[:3000],
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def add_many(self, findings: list[Finding]) -> list[int]:
        """Insert multiple findings. Returns list of IDs."""
        return [self.add(f) for f in findings]

    def query(
        self,
        host: str | None = None,
        severity: str | None = None,
        min_severity: str | None = None,
        finding_type: str | None = None,
        agent: str | None = None,
        exploitable: bool | None = None,
        exploited: bool | None = None,
        cve_id: str | None = None,
        since_minutes: int | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Flexible query with optional filters. Returns list of row dicts."""
        conditions = []
        params = []

        if host is not None:
            conditions.append("host = ?")
            params.append(host)
        if severity is not None:
            conditions.append("severity = ?")
            params.append(severity)
        if min_severity is not None:
            # Include this severity and everything more severe
            allowed = [
                s for s, order in _SEVERITY_ORDER.items()
                if order <= _SEVERITY_ORDER.get(min_severity, 4)
            ]
            placeholders = ",".join("?" for _ in allowed)
            conditions.append(f"severity IN ({placeholders})")
            params.extend(allowed)
        if finding_type is not None:
            conditions.append("finding_type = ?")
            params.append(finding_type)
        if agent is not None:
            conditions.append("agent = ?")
            params.append(agent)
        if exploitable is not None:
            conditions.append("exploitable = ?")
            params.append(int(exploitable))
        if exploited is not None:
            conditions.append("exploited = ?")
            params.append(int(exploited))
        if cve_id is not None:
            conditions.append("cve_id = ?")
            params.append(cve_id)
        if since_minutes is not None:
            cutoff = (datetime.now() - timedelta(minutes=since_minutes)).isoformat()
            conditions.append("created_at >= ?")
            params.append(cutoff)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM findings {where} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        conn = self._get_conn()
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def count(
        self,
        host: str | None = None,
        since_minutes: int | None = None,
        min_severity: str | None = None,
    ) -> int:
        """Count findings matching filters. Used by exit evaluator."""
        conditions = []
        params = []

        if host is not None:
            conditions.append("host = ?")
            params.append(host)
        if since_minutes is not None:
            cutoff = (datetime.now() - timedelta(minutes=since_minutes)).isoformat()
            conditions.append("created_at >= ?")
            params.append(cutoff)
        if min_severity is not None:
            allowed = [
                s for s, order in _SEVERITY_ORDER.items()
                if order <= _SEVERITY_ORDER.get(min_severity, 4)
            ]
            placeholders = ",".join("?" for _ in allowed)
            conditions.append(f"severity IN ({placeholders})")
            params.extend(allowed)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT COUNT(*) FROM findings {where}"

        conn = self._get_conn()
        return conn.execute(sql, params).fetchone()[0]

    def update_poc(self, finding_id: int, poc_status: str,
                   poc_script: str = "", poc_instructions: str = "") -> bool:
        """Update PoC status for a finding after verification."""
        conn = self._get_conn()
        cursor = conn.execute(
            """UPDATE findings SET poc_status = ?, poc_script = ?, poc_instructions = ?
               WHERE id = ?""",
            (poc_status, poc_script[:5000], poc_instructions[:3000], finding_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_pending_poc(self, host: str | None = None,
                       min_severity: str = "low") -> list[dict]:
        """Get findings that need PoC verification."""
        conditions = ["poc_status = 'pending'"]
        params = []
        if host:
            conditions.append("host = ?")
            params.append(host)
        # Filter by severity
        allowed = [
            s for s, order in _SEVERITY_ORDER.items()
            if order <= _SEVERITY_ORDER.get(min_severity, 3)
        ]
        if allowed:
            placeholders = ",".join("?" for _ in allowed)
            conditions.append(f"severity IN ({placeholders})")
            params.extend(allowed)

        where = f"WHERE {' AND '.join(conditions)}"
        conn = self._get_conn()
        rows = conn.execute(
            f"SELECT * FROM findings {where} ORDER BY created_at DESC", params
        ).fetchall()
        return [dict(row) for row in rows]

    def get_hosts_with_findings(self) -> list[dict]:
        """Get summary of findings per host."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT host,
                   COUNT(*) as finding_count,
                   MIN(CASE severity
                       WHEN 'critical' THEN 0
                       WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2
                       WHEN 'low' THEN 3
                       ELSE 4 END) as max_severity_order,
                   GROUP_CONCAT(DISTINCT finding_type) as finding_types,
                   SUM(CASE WHEN exploitable THEN 1 ELSE 0 END) as exploitable_count
            FROM findings
            GROUP BY host
            ORDER BY max_severity_order ASC, finding_count DESC
        """).fetchall()

        severity_names = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}
        return [
            {
                "host": row["host"],
                "finding_count": row["finding_count"],
                "max_severity": severity_names.get(row["max_severity_order"], "info"),
                "finding_types": row["finding_types"] or "",
                "exploitable_count": row["exploitable_count"],
            }
            for row in rows
        ]

    def mark_exploited(self, finding_id: int) -> None:
        """Mark a finding as successfully exploited."""
        conn = self._get_conn()
        conn.execute("UPDATE findings SET exploited = 1 WHERE id = ?", (finding_id,))
        conn.commit()

    def unproven_findings(self, min_severity: str = "medium") -> list[dict]:
        """Return findings that are exploitable but not yet exploited to proof.

        These represent attack chains that were identified but never completed —
        the gap between "vulnerability scanner" and "penetration tester."
        """
        return self.query(
            exploitable=True, exploited=False,
            min_severity=min_severity, limit=20,
        )

    def summary_for_prompt(self, host: str | None = None, max_chars: int = 3000) -> str:
        """Generate a compressed findings summary suitable for injection into agent prompts.

        Groups findings by severity and type, avoids raw evidence dumps.
        """
        findings = self.query(host=host, limit=200)
        if not findings:
            return ""

        lines = ["## Known Findings from Previous Agents"]

        # Group by severity
        by_severity: dict[str, list[dict]] = {}
        for f in findings:
            sev = f["severity"]
            by_severity.setdefault(sev, []).append(f)

        for sev in ["critical", "high", "medium", "low", "info"]:
            group = by_severity.get(sev, [])
            if not group:
                continue
            lines.append(f"\n### {sev.upper()} ({len(group)})")
            for f in group[:15]:  # Cap per-severity to avoid bloat
                host_str = f["host"]
                port_str = f":{f['port']}" if f["port"] else ""
                svc_str = f" ({f['service']})" if f["service"] else ""
                cve_str = f" [{f['cve_id']}]" if f["cve_id"] else ""
                exploit_str = " [EXPLOITABLE]" if f["exploitable"] else ""
                title = f["title"] or f["finding_type"] or "finding"
                lines.append(
                    f"- {host_str}{port_str}{svc_str}: {title}{cve_str}{exploit_str}"
                )
                if f["description"]:
                    desc = f["description"][:150]
                    lines.append(f"  {desc}")

        result = "\n".join(lines)
        if len(result) > max_chars:
            result = result[:max_chars] + "\n\n... (truncated — query findings DB for full list)"
        return result

    def export_markdown(self) -> str:
        """Export all findings as a structured markdown report."""
        findings = self.query(limit=500)
        if not findings:
            return "No findings recorded."

        lines = [
            "# Findings Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total findings:** {len(findings)}",
            "",
        ]

        # Summary table
        host_summary = self.get_hosts_with_findings()
        if host_summary:
            lines.append("## Host Summary")
            lines.append("| Host | Findings | Max Severity | Exploitable |")
            lines.append("|------|----------|-------------|-------------|")
            for h in host_summary:
                lines.append(
                    f"| {h['host']} | {h['finding_count']} | "
                    f"{h['max_severity']} | {h['exploitable_count']} |"
                )
            lines.append("")

        # Detailed findings grouped by host
        by_host: dict[str, list[dict]] = {}
        for f in findings:
            by_host.setdefault(f["host"], []).append(f)

        for host, host_findings in by_host.items():
            lines.append(f"## {host}")
            # Sort by severity
            host_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 4))
            for f in host_findings:
                port_str = f":{f['port']}" if f["port"] else ""
                svc_str = f" ({f['service']})" if f["service"] else ""
                cve_str = f" — {f['cve_id']}" if f["cve_id"] else ""
                lines.append(
                    f"### [{f['severity'].upper()}] {f['title'] or f['finding_type']}"
                    f"{cve_str}"
                )
                lines.append(f"- **Target:** {host}{port_str}{svc_str}")
                lines.append(f"- **Type:** {f['finding_type']}")
                lines.append(f"- **Agent:** {f['agent']}")
                if f["exploitable"]:
                    lines.append("- **Exploitable:** Yes")
                if f["exploited"]:
                    lines.append("- **Exploited:** Yes")
                if f["description"]:
                    lines.append(f"\n{f['description']}")
                if f["evidence"] and len(f["evidence"]) < 500:
                    lines.append(f"\n**Evidence:**\n```\n{f['evidence']}\n```")
                elif f["evidence_path"]:
                    lines.append(f"\n**Evidence:** See {f['evidence_path']}")
                lines.append("")

        return "\n".join(lines)

    def clear(self):
        """Clear all findings. Used for test reset."""
        conn = self._get_conn()
        conn.execute("DELETE FROM findings")
        conn.commit()

    def close(self):
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
