"""Exit evaluator — deterministic "nothing here" detection.

Scores whether the engagement should stop based on hard metrics,
not LLM judgment. The orchestrator uses this score to inform its
decision-making and can auto-stop when the score exceeds the threshold.

No LLM calls — pure deterministic scoring from findings DB and phase log.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime


# Configurable via environment
EXIT_THRESHOLD = float(os.getenv("REDOPS_EXIT_THRESHOLD", "0.7"))

# Time window for "no new findings" check (minutes)
FINDINGS_WINDOW_MINUTES = int(os.getenv("REDOPS_FINDINGS_WINDOW", "30"))


@dataclass
class ExitScore:
    """Result of the exit evaluation."""
    should_exit: bool
    score: float               # 0.0 (keep going) to 1.0 (definitely stop)
    reasons: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def format_for_operator(self) -> str:
        """Format the exit score for human review."""
        lines = []
        if self.should_exit:
            lines.append(f"**EXIT RECOMMENDED** (score: {self.score:.2f}/{EXIT_THRESHOLD})")
        else:
            lines.append(f"**Continue** (exit score: {self.score:.2f}/{EXIT_THRESHOLD})")

        if self.reasons:
            lines.append("\nFactors:")
            for r in self.reasons:
                lines.append(f"  - {r}")

        if self.metrics:
            lines.append("\nMetrics:")
            for k, v in self.metrics.items():
                lines.append(f"  - {k}: {v}")

        return "\n".join(lines)

    def format_for_prompt(self) -> str:
        """Compact format for injection into LLM analysis prompt."""
        status = "EXIT RECOMMENDED" if self.should_exit else "CONTINUE"
        reasons_str = "; ".join(self.reasons) if self.reasons else "none"
        return (
            f"[Exit Evaluator: {status} | score={self.score:.2f}/{EXIT_THRESHOLD} | "
            f"factors: {reasons_str}]"
        )


class ExitEvaluator:
    """Deterministic scoring for engagement exit decisions.

    Factors are additive — each contributes a weight to the total score.
    When the total exceeds EXIT_THRESHOLD, the evaluator recommends stopping.
    The LLM decision maker sees the score and can override.
    """

    def __init__(self, findings_db, phase_log: list[dict]):
        """
        Args:
            findings_db: FindingsDB instance for querying finding counts
            phase_log: Orchestrator's phase_log list (dicts with agent, stuck_killed, turns, etc.)
        """
        self.db = findings_db
        self.phase_log = phase_log

    def evaluate(self, host: str | None = None) -> ExitScore:
        """Run all scoring factors and return the aggregate exit score.

        Args:
            host: If provided, evaluate exit for a specific host only.
                  If None, evaluate globally across all hosts.
        """
        score = 0.0
        reasons = []
        metrics = {}

        # Factor 1: No new findings in the time window
        score, reasons, metrics = self._check_recent_findings(
            score, reasons, metrics, host
        )

        # Factor 2: All findings are info/low severity only
        score, reasons, metrics = self._check_finding_severity(
            score, reasons, metrics, host
        )

        # Factor 3: High stuck-kill rate in recent phases
        score, reasons, metrics = self._check_stuck_rate(
            score, reasons, metrics
        )

        # Factor 4: Consecutive phases with no progress
        score, reasons, metrics = self._check_diminishing_returns(
            score, reasons, metrics
        )

        # Factor 5: All core agents ran with zero findings
        score, reasons, metrics = self._check_exhausted_agents(
            score, reasons, metrics, host
        )

        should_exit = score >= EXIT_THRESHOLD

        if should_exit:
            reasons.insert(0, f"EXIT RECOMMENDED (score: {score:.2f}/{EXIT_THRESHOLD})")

        return ExitScore(
            should_exit=should_exit,
            score=min(score, 1.0),
            reasons=reasons,
            metrics=metrics,
        )

    def _check_recent_findings(self, score, reasons, metrics, host):
        """Factor 1: No new findings in the configured time window."""
        recent = self.db.count(host=host, since_minutes=FINDINGS_WINDOW_MINUTES)
        total = self.db.count(host=host)
        metrics["recent_findings"] = recent
        metrics["total_findings"] = total
        metrics["findings_window_minutes"] = FINDINGS_WINDOW_MINUTES

        if recent == 0 and len(self.phase_log) >= 2:
            score += 0.3
            reasons.append(
                f"No new findings in last {FINDINGS_WINDOW_MINUTES} min "
                f"({total} total across all time)"
            )
        return score, reasons, metrics

    def _check_finding_severity(self, score, reasons, metrics, host):
        """Factor 2: All findings are info/low severity only (or zero findings)."""
        total = self.db.count(host=host)
        high_plus = self.db.count(host=host, min_severity="medium")
        metrics["high_severity_findings"] = high_plus

        if high_plus == 0 and len(self.phase_log) >= 2:
            if total > 0:
                score += 0.2
                reasons.append(
                    f"All {total} findings are info/low severity — "
                    f"no exploitable vulnerabilities identified"
                )
            elif total == 0:
                # Zero findings is even worse — nothing found at all
                score += 0.2
                reasons.append(
                    "Zero findings after multiple phases — "
                    "target appears to have minimal attack surface"
                )
        return score, reasons, metrics

    def _check_stuck_rate(self, score, reasons, metrics):
        """Factor 3: High stuck-kill rate in recent phases."""
        if not self.phase_log:
            return score, reasons, metrics

        recent = self.phase_log[-3:]
        stuck_count = sum(1 for p in recent if p.get("stuck_killed"))
        metrics["recent_stuck_kills"] = stuck_count
        metrics["recent_phase_count"] = len(recent)

        if len(recent) >= 2 and stuck_count / len(recent) >= 0.5:
            score += 0.25
            reasons.append(
                f"{stuck_count}/{len(recent)} recent agents stuck-killed — "
                f"available attack paths are failing"
            )
        return score, reasons, metrics

    def _check_diminishing_returns(self, score, reasons, metrics):
        """Factor 4: Multiple consecutive phases with no meaningful progress."""
        if not self.phase_log:
            return score, reasons, metrics

        consecutive = 0
        for phase in reversed(self.phase_log):
            # A phase with no progress: stuck-killed, or very few turns (agent gave up fast)
            if phase.get("stuck_killed") or phase.get("turns", 0) <= 2:
                consecutive += 1
            else:
                break

        metrics["consecutive_no_progress"] = consecutive

        if consecutive >= 3:
            score += 0.25
            reasons.append(
                f"{consecutive} consecutive phases with no progress — "
                f"agents are failing or exiting immediately"
            )
        return score, reasons, metrics

    def _check_exhausted_agents(self, score, reasons, metrics, host):
        """Factor 5: All core agents have run with zero total findings."""
        agents_run = set(p["agent"] for p in self.phase_log)
        core_agents = {"recon", "exploit", "cvehunter"}
        metrics["agents_run"] = sorted(agents_run)
        metrics["core_agents_covered"] = sorted(core_agents & agents_run)

        total = self.db.count(host=host)

        exploitable = self.db.count(host=host, min_severity="medium")
        if core_agents.issubset(agents_run) and exploitable == 0:
            score += 0.3
            reasons.append(
                f"All core agents ({', '.join(sorted(core_agents))}) have run "
                f"with no exploitable findings — attack surface appears minimal"
            )
        return score, reasons, metrics
