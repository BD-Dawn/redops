"""Structured findings database — SQLite-backed queryable storage for engagement findings.

Agents write findings via the Python API. Other agents and the orchestrator
can query findings without eating context window. Used by the exit evaluator
for metric counting and by the report generator for structured output.
"""

import re
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

# A finding has "material impact" — worth reporting — at medium severity or above.
# Low/info findings are recorded but treated as low-hanging fruit: noted for the
# operator to review and promote if context makes them matter, never auto-reported.
_MATERIAL_SEVERITIES = {"critical", "high", "medium"}


# Report disposition — where a finding lands when a report is generated.
class Disposition:
    REPORTABLE = "reportable"    # Material + proven PoC (or operator-promoted)
    NEEDS_POC = "needs_poc"      # Material but PoC not yet confirmed — the gate holds it back
    NOTED = "noted"              # Low/info, or operator-demoted — operator decides


def classify_disposition(severity: str, poc_status: str, report_override: str = "") -> str:
    """Decide where a finding lands in a report. Pure function of its fields.

    Operator overrides win. Otherwise: material findings need a confirmed (or
    manual) PoC to be reportable — unproven material findings are held in
    NEEDS_POC (the verification gate). Low/info are always NOTED.
    """
    if report_override == "promote":
        return Disposition.REPORTABLE
    if report_override == "demote":
        return Disposition.NOTED

    material = (severity or "info").lower() in _MATERIAL_SEVERITIES
    if not material:
        return Disposition.NOTED

    if poc_status in (PocStatus.CONFIRMED, PocStatus.MANUAL):
        return Disposition.REPORTABLE
    # Material but pending/unconfirmed — the PoC gate holds it back
    return Disposition.NEEDS_POC


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
    cvss_vector: str = ""         # CVSS 3.1 vector string (e.g. AV:N/AC:L/...) for submission
    report_override: str = ""     # Operator override: '' (auto), 'promote', 'demote'


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
                cvss_vector TEXT DEFAULT '',
                report_override TEXT DEFAULT '',
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
        """Add PoC + triage columns to existing databases that don't have them."""
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
            for col, default in [
                ("poc_status", "'pending'"),
                ("poc_script", "''"),
                ("poc_instructions", "''"),
                ("cvss_vector", "''"),
                ("report_override", "''"),
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
                poc_status, poc_script, poc_instructions, cvss_vector, report_override)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                finding.cvss_vector,
                finding.report_override,
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

    # --- Report triage: disposition-based classification ----------------------

    def _all_with_disposition(self, host: str | None = None) -> list[dict]:
        """Return all findings, each annotated with its report disposition."""
        rows = self.query(host=host, limit=500)
        for f in rows:
            f["disposition"] = classify_disposition(
                f.get("severity", "info"),
                f.get("poc_status", PocStatus.PENDING),
                f.get("report_override", ""),
            )
        return rows

    def reportable_findings(self, host: str | None = None) -> list[dict]:
        """Material findings with a proven PoC (or operator-promoted) — go in the report."""
        return [f for f in self._all_with_disposition(host)
                if f["disposition"] == Disposition.REPORTABLE]

    def noted_findings(self, host: str | None = None) -> list[dict]:
        """Low/info or operator-demoted findings — recorded, operator decides if they matter."""
        return [f for f in self._all_with_disposition(host)
                if f["disposition"] == Disposition.NOTED]

    def needs_poc(self, host: str | None = None) -> list[dict]:
        """Material findings still missing a confirmed PoC — the verification gate's queue."""
        return [f for f in self._all_with_disposition(host)
                if f["disposition"] == Disposition.NEEDS_POC]

    def set_report_override(self, finding_id: int, override: str) -> bool:
        """Operator override: 'promote' (force into report), 'demote' (force to notes), '' (auto)."""
        if override not in ("", "promote", "demote"):
            raise ValueError("override must be '', 'promote', or 'demote'")
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE findings SET report_override = ? WHERE id = ?", (override, finding_id)
        )
        conn.commit()
        return cursor.rowcount > 0

    def set_cvss(self, finding_id: int, cvss_vector: str) -> bool:
        """Attach a CVSS 3.1 vector string to a finding."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE findings SET cvss_vector = ? WHERE id = ?", (cvss_vector[:200], finding_id)
        )
        conn.commit()
        return cursor.rowcount > 0

    def potential_duplicates(self) -> list[list[dict]]:
        """Group findings that look like duplicates (same host + same finding_type +
        similar title). Returns clusters with 2+ members so the operator can dedup
        before submission. Title similarity is a normalized token-overlap heuristic.
        """
        findings = self.query(limit=500)

        def _norm_tokens(title: str) -> set:
            return set(re.findall(r"[a-z0-9]+", (title or "").lower()))

        clusters: list[list[dict]] = []
        used = set()
        for i, a in enumerate(findings):
            if a["id"] in used:
                continue
            group = [a]
            a_tokens = _norm_tokens(a.get("title", ""))
            for b in findings[i + 1:]:
                if b["id"] in used:
                    continue
                if b["host"] != a["host"] or b["finding_type"] != a["finding_type"]:
                    continue
                b_tokens = _norm_tokens(b.get("title", ""))
                if not a_tokens or not b_tokens:
                    continue
                overlap = len(a_tokens & b_tokens) / max(len(a_tokens | b_tokens), 1)
                if overlap >= 0.6 or a.get("cve_id") and a.get("cve_id") == b.get("cve_id"):
                    group.append(b)
                    used.add(b["id"])
            if len(group) > 1:
                used.add(a["id"])
                clusters.append(group)
        return clusters

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
        """Export findings as a triaged markdown report.

        Two sections: REPORTABLE (material + proven PoC) and NOTES (low/info or
        unproven material). Material findings still missing a PoC are surfaced
        separately so the operator knows what the verification gate is holding back.
        """
        annotated = self._all_with_disposition()
        if not annotated:
            return "No findings recorded."

        reportable = [f for f in annotated if f["disposition"] == Disposition.REPORTABLE]
        needs_poc = [f for f in annotated if f["disposition"] == Disposition.NEEDS_POC]
        noted = [f for f in annotated if f["disposition"] == Disposition.NOTED]

        lines = [
            "# Findings Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Reportable:** {len(reportable)}  |  "
            f"**Awaiting PoC:** {len(needs_poc)}  |  **Notes (low/info):** {len(noted)}",
            "",
        ]

        def _render(f: dict) -> list[str]:
            host = f["host"]
            port_str = f":{f['port']}" if f["port"] else ""
            svc_str = f" ({f['service']})" if f["service"] else ""
            cve_str = f" — {f['cve_id']}" if f["cve_id"] else ""
            out = [
                f"### [{f['severity'].upper()}] {f['title'] or f['finding_type']}{cve_str}",
                f"- **Target:** {host}{port_str}{svc_str}",
                f"- **Type:** {f['finding_type']}",
            ]
            if f.get("cvss_vector"):
                out.append(f"- **CVSS 3.1:** {f['cvss_vector']}")
            out.append(f"- **PoC status:** {f.get('poc_status', 'pending')}")
            if f["exploited"]:
                out.append("- **Exploited:** Yes")
            if f["description"]:
                out.append(f"\n{f['description']}")
            if f.get("poc_script"):
                out.append(f"\n**Reproduce:**\n```\n{f['poc_script'][:1500]}\n```")
            elif f.get("poc_instructions"):
                out.append(f"\n**Manual PoC steps:**\n{f['poc_instructions'][:1500]}")
            if f["evidence"] and len(f["evidence"]) < 500:
                out.append(f"\n**Evidence:**\n```\n{f['evidence']}\n```")
            elif f["evidence_path"]:
                out.append(f"\n**Evidence:** See {f['evidence_path']}")
            out.append("")
            return out

        def _section(title: str, items: list[dict], note: str = "") -> None:
            if not items:
                return
            lines.append(f"## {title}")
            if note:
                lines.append(f"*{note}*\n")
            items.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 4))
            for f in items:
                lines.extend(_render(f))

        _section("Reportable Findings", reportable,
                  "Material impact with a verified PoC — submission-ready.")
        _section("Awaiting PoC Verification", needs_poc,
                 "Material findings held back by the PoC gate. Run `/findings verify` "
                 "or confirm manually before submitting.")
        _section("Notes — Low-Hanging Fruit (operator review)", noted,
                 "Low/informational or unproven. Not reported by default. "
                 "Promote with `/findings promote <id>` if context makes one material.")

        return "\n".join(lines)

    # Per-platform submission templates
    _PLATFORM_LABELS = {
        "hackerone": "HackerOne",
        "bugcrowd": "Bugcrowd",
        "generic": "Generic",
    }

    def export_for_platform(self, platform: str = "generic") -> str:
        """Export ONLY reportable findings, formatted for a bounty platform.

        Each finding becomes a self-contained submission block with the fields
        triage platforms expect: title, severity/CVSS, asset, steps to reproduce,
        impact, and remediation. Low/info and unproven findings are excluded.
        """
        platform = platform.lower()
        label = self._PLATFORM_LABELS.get(platform, "Generic")
        reportable = self.reportable_findings()
        if not reportable:
            return (f"No reportable findings. (Material findings need a confirmed PoC — "
                    f"check `/findings verify`, or `/findings promote <id>` to override.)")

        reportable.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 4))
        blocks = [f"# {label} Submission Package",
                  f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  "
                  f"**Findings:** {len(reportable)}", ""]

        for i, f in enumerate(reportable, 1):
            host = f["host"]
            port_str = f":{f['port']}" if f["port"] else ""
            svc_str = f" ({f['service']})" if f["service"] else ""
            title = f["title"] or f["finding_type"] or "Finding"
            sev = f["severity"].upper()
            blocks.append(f"## {i}. {title}  [{sev}]")
            blocks.append(f"**Asset:** {host}{port_str}{svc_str}")
            if f.get("cvss_vector"):
                blocks.append(f"**CVSS 3.1 Vector:** `{f['cvss_vector']}`")
            if f.get("cve_id"):
                blocks.append(f"**CVE:** {f['cve_id']}")
            blocks.append("")
            blocks.append("**Description**")
            blocks.append(f["description"] or "_(fill in technical description)_")
            blocks.append("")
            blocks.append("**Steps to Reproduce**")
            if f.get("poc_script"):
                blocks.append(f"```\n{f['poc_script'][:2000]}\n```")
            elif f.get("poc_instructions"):
                blocks.append(f["poc_instructions"][:2000])
            else:
                blocks.append("_(no PoC recorded)_")
            blocks.append("")
            blocks.append("**Impact**")
            blocks.append("_(describe business impact — what an attacker gains)_")
            blocks.append("")
            blocks.append("**Remediation**")
            blocks.append("_(recommended fix)_")
            if f["evidence_path"]:
                blocks.append("")
                blocks.append(f"**Evidence:** {f['evidence_path']}")
            blocks.append("\n---\n")

        return "\n".join(blocks)

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
