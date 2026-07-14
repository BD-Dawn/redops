"""Orchestrator — LLM-powered coordinator with human-in-the-loop decision making.

The orchestrator uses Claude to analyze each phase's output, decide the next move,
and either proceed autonomously or ask the operator for guidance when uncertain.
"""

import json
import subprocess

import claude_client
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from collections import Counter

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST, MODEL_PLANNER, EVIDENCE_DIR, FINDINGS_DIR, CHAIN_MAX_TURNS, MAX_ENGAGEMENT_COST, SESSION_USAGE_WARN_PCT
from agents.recon import ReconAgent
from agents.exploit import ExploitAgent
from agents.postex import PostExAgent
from agents.codereview import CodeReviewAgent
from agents.cvehunter import CVEHunterAgent
from agents.triage import TriageAgent
from agents.noise_filter import NoiseFilter
from agents.sanity_checker import SanityChecker
from agents.report import ReportAgent
from agents.param_analyzer import ParamAnalyzer
from agents.synthesis import SynthesisAgent
from agents.linux_postex import LinuxPostExAgent
from agents.windows_postex import WindowsPostExAgent
from agents.linux_lateral import LinuxLateralAgent
from agents.windows_lateral import WindowsLateralAgent
from agents.cloud import CloudAgent
from agents.summarizer import cache_output, summarize_output, extract_findings_from_summary
from findings_db import FindingsDB
from exit_evaluator import ExitEvaluator
from agents.base import StuckDetector
from attack_plan import AttackPlan
from impact_evaluator import gate_finding
from scope_enforcer import ScopeEnforcer
from task_decomposer import TaskDecomposer, SubTask


# Decision confidence threshold (0-100).
# Above this: orchestrator proceeds autonomously.
# Below this: pauses and asks the operator.
DEFAULT_CONFIDENCE_THRESHOLD = 70


class CostTracker:
    """Tracks cost-of-pass metric per agent and overall.

    cost_of_pass = total_cost / success_rate
    From Zhou et al. 2025 "Efficient Agents" — the primary efficiency metric.
    """

    def __init__(self):
        self.agent_costs: dict[str, float] = {}    # agent → cumulative cost
        self.agent_turns: dict[str, int] = {}       # agent → total turns
        self.agent_successes: dict[str, int] = {}   # agent → milestone hits
        self.total_cost: float = 0
        self.total_turns: int = 0

    def record(self, agent_name: str, cost: float, turns: int, milestone_hit: bool = False):
        """Record a dispatch's cost and outcome."""
        self.agent_costs[agent_name] = self.agent_costs.get(agent_name, 0) + cost
        self.agent_turns[agent_name] = self.agent_turns.get(agent_name, 0) + turns
        if milestone_hit:
            self.agent_successes[agent_name] = self.agent_successes.get(agent_name, 0) + 1
        self.total_cost += cost
        self.total_turns += turns

    def cost_of_pass(self, agent_name: str = "") -> float:
        """Calculate cost-of-pass for a specific agent or overall.

        Returns cost/success_rate. Lower is better. Returns -1 if no successes.
        """
        if agent_name:
            cost = self.agent_costs.get(agent_name, 0)
            successes = self.agent_successes.get(agent_name, 0)
        else:
            cost = self.total_cost
            successes = sum(self.agent_successes.values())
        if successes == 0:
            return -1  # No successes yet
        dispatches = sum(1 for _ in self.agent_costs) if not agent_name else 1
        success_rate = successes / max(dispatches, 1)
        return cost / max(success_rate, 0.01)

    def summary(self) -> str:
        """Format a compact summary for display."""
        lines = [f"## Cost Efficiency (total: ${self.total_cost:.4f}, {self.total_turns} turns)"]
        for agent in sorted(self.agent_costs.keys()):
            cost = self.agent_costs[agent]
            turns = self.agent_turns[agent]
            successes = self.agent_successes.get(agent, 0)
            cop = self.cost_of_pass(agent)
            cop_str = f"{cop:.3f}" if cop >= 0 else "no milestones"
            lines.append(f"  {agent}: ${cost:.4f} / {turns}t / {successes} milestones / COP: {cop_str}")
        overall_cop = self.cost_of_pass()
        if overall_cop >= 0:
            lines.append(f"  Overall cost-of-pass: {overall_cop:.3f}")
        return "\n".join(lines)


class Decision:
    """Represents an orchestrator decision between phases."""

    def __init__(self, raw: dict):
        self.next_agent: str = raw.get("next_agent", "")
        self.task: str = raw.get("task", "")
        self.reasoning: str = raw.get("reasoning", "")
        self.confidence: int = raw.get("confidence", 0)
        self.alternatives: list[dict] = raw.get("alternatives", [])
        self.should_stop: bool = raw.get("should_stop", False)
        self.stop_reason: str = raw.get("stop_reason", "")

    @property
    def is_confident(self) -> bool:
        return self.confidence >= DEFAULT_CONFIDENCE_THRESHOLD

    def format_for_operator(self) -> str:
        """Format the decision for human review."""
        lines = []
        if self.should_stop:
            lines.append(f"**RECOMMENDATION: STOP** — {self.stop_reason}")
            lines.append(f"\n**Reasoning:** {self.reasoning}")
            return "\n".join(lines)

        lines.append(f"**Proposed action:** Dispatch **{self.next_agent}** agent")
        lines.append(f"**Confidence:** {self.confidence}%")
        lines.append(f"\n**Reasoning:** {self.reasoning}")
        lines.append(f"\n**Task for {self.next_agent} agent:**")
        # Show first ~500 chars of task
        task_preview = self.task[:500]
        if len(self.task) > 500:
            task_preview += "..."
        lines.append(task_preview)

        if self.alternatives:
            lines.append("\n**Alternatives considered:**")
            for i, alt in enumerate(self.alternatives, 1):
                lines.append(f"  {i}. [{alt.get('agent', '?')}] {alt.get('description', '')}")

        return "\n".join(lines)


class Orchestrator:
    """LLM-powered orchestrator with human-in-the-loop.

    After each phase, the orchestrator:
    1. Analyzes the results using Claude
    2. Decides the next action (which agent, what task)
    3. If confident (above threshold) → proceeds automatically
    4. If uncertain → presents its reasoning and asks the operator
    5. The operator can approve, modify, redirect, or stop
    """

    PHASES = [
        "recon", "exploit", "postex", "codereview", "cvehunter", "cloud",
        "triage", "noise_filter", "param_analyzer", "sanity_checker", "synthesis", "report",
        "linux_postex", "windows_postex", "linux_lateral", "windows_lateral",
    ]

    _CHECKPOINT_PATH = FINDINGS_DIR / ".chain_checkpoint.json"

    # Agent name → class mapping for lazy initialization
    _AGENT_CLASSES: dict[str, type] = {
        "recon": ReconAgent,
        "exploit": ExploitAgent,
        "postex": PostExAgent,
        "codereview": CodeReviewAgent,
        "cvehunter": CVEHunterAgent,
        "triage": TriageAgent,
        "noise_filter": NoiseFilter,
        "sanity_checker": SanityChecker,
        "report": ReportAgent,
        "param_analyzer": ParamAnalyzer,
        "synthesis": SynthesisAgent,
        "linux_postex": LinuxPostExAgent,
        "windows_postex": WindowsPostExAgent,
        "linux_lateral": LinuxLateralAgent,
        "windows_lateral": WindowsLateralAgent,
        "cloud": CloudAgent,
    }

    def __init__(self, engagement_state, autonomous: bool = True):
        self.state = engagement_state
        self.autonomous = autonomous
        self.confidence_threshold = DEFAULT_CONFIDENCE_THRESHOLD
        # Lazy agent cache — agents instantiated on first access via _get_agent()
        self._agents: dict[str, object] = {}
        self.phase_log: list[dict] = []
        self.decisions: list[Decision] = []
        # Last sanity check result — used by _analyze_and_decide for course correction
        self._last_sanity_review: str = ""
        # New components — use per-engagement paths when available
        _findings_path = getattr(engagement_state, 'findings_db_path', None)
        self.findings_db = FindingsDB(db_path=_findings_path)
        self.task_decomposer = TaskDecomposer()
        self.cost_tracker = CostTracker()

        # Checkpoint path — per-engagement if available
        _checkpoint = getattr(engagement_state, 'checkpoint_path', None)
        if _checkpoint:
            self._CHECKPOINT_PATH = _checkpoint

        # Attack plan — per-engagement if available
        _plan_path = getattr(engagement_state, 'plan_path', None)
        self.attack_plan = AttackPlan(engagement_state.target)
        if _plan_path:
            self.attack_plan._plan_path_override = _plan_path
        self.attack_plan.load()  # Restore from disk if exists
        # Callback for asking the operator — set by main.py
        self.ask_operator = None  # Callable[[str], str] or None

        # Bounty monitor — initialized via setup_bounty_monitor()
        self.bounty_monitor = None  # BountyMonitor | None

        # Sync findings from interactive agent (notes/capabilities) into FindingsDB
        # so the exit evaluator and orchestrator see them.
        self._sync_findings_from_state()

    def _sync_findings_from_state(self):
        """Backfill FindingsDB from engagement notes/capabilities.

        The interactive agent stores findings as free-text notes and structured
        capabilities. The orchestrator's exit evaluator and planning logic use
        FindingsDB (SQLite). This method bridges the two so the orchestrator
        sees findings discovered by the interactive layer.

        Only runs when the DB is empty but the engagement has findings data —
        avoids duplicating on every init.
        """
        if self.findings_db.count() > 0:
            return  # DB already populated
        if not getattr(self.state, "notes", None) and not getattr(self.state, "capabilities", None):
            return  # Nothing to sync

        from findings_db import Finding
        host = self.state.target or "unknown"
        synced = 0

        # Known finding patterns from notes — map keywords to structured findings.
        # Each tuple: (keywords_any, title, severity, finding_type, description_source_keywords)
        _finding_patterns = [
            (["s3 bucket", "public listing", "certs.platacard"],
             "S3 Bucket Listing — PKI Infrastructure", "medium", "misconfiguration"),
            (["s3 bucket", "public listing", "file-service", "prime.bancoplata"],
             "S3 Bucket Listing — File Service", "low", "misconfiguration"),
            (["subdomain takeover", "event.bancoplata", "framer", "dangling cname"],
             "Subdomain Takeover — event.bancoplata.mx", "high", "misconfiguration"),
            (["google maps api key", "unrestricted"],
             "Unrestricted Google Maps API Key", "medium", "information-disclosure"),
            (["env.json", "configuration", "architecture disclosure"],
             "Configuration/Architecture Disclosure (env.json)", "low", "information-disclosure"),
            (["clickjacking", "x-frame-options", "business.*login", "empresa"],
             "Clickjacking on Business Banking Login", "medium", "vulnerability"),
            (["otp", "sms bomb", "rate limit", "login flow creation", "flooding"],
             "Unrestricted Login Flow Creation / OTP Abuse", "medium", "vulnerability"),
        ]

        notes_blob = " ".join(getattr(self.state, "notes", []) or []).lower()
        import re
        for keywords, title, severity, ftype in _finding_patterns:
            if any(kw in notes_blob for kw in keywords):
                # Extract a description snippet from notes
                desc_parts = []
                for note in self.state.notes:
                    if any(kw in note.lower() for kw in keywords):
                        desc_parts.append(note)
                        if len(desc_parts) >= 3:
                            break
                finding = Finding(
                    host=host,
                    title=title,
                    severity=severity,
                    finding_type=ftype,
                    description="; ".join(desc_parts)[:500],
                    agent="interactive",
                )
                self.findings_db.add(finding)
                synced += 1

        if synced > 0:
            self.state.save()

    def _get_agent(self, name: str):
        """Lazy-initialize and return an agent by name. Cached after first access."""
        if name not in self._agents:
            cls = self._AGENT_CLASSES.get(name)
            if cls is None:
                return None
            self._agents[name] = cls(self.state, self.autonomous)
        return self._agents[name]

    def __getattr__(self, name: str):
        """Allow self.recon, self.exploit etc. to work via lazy init."""
        if name in self._AGENT_CLASSES:
            return self._get_agent(name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    # --- Checkpoint persistence for resume after Ctrl+C ---

    def _save_checkpoint(self, results: dict, current_phase: str, current_output: str,
                         iteration: int):
        """Save chain progress so run_chain can resume after interruption."""
        try:
            data = {
                "current_phase": current_phase,
                "iteration": iteration,
                "completed_phases": list(results.keys()),
                "phase_summaries": {k: v[:2000] for k, v in results.items()},
                "current_output_preview": current_output[:1000],
                "phase_log": self.phase_log,
                "decisions": [
                    {
                        "next_agent": d.next_agent,
                        "reasoning": d.reasoning[:200],
                        "confidence": d.confidence,
                        "should_stop": d.should_stop,
                    }
                    for d in self.decisions
                ],
                "target": self.state.target,
                "time": datetime.now().isoformat(),
            }
            self._CHECKPOINT_PATH.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _load_checkpoint(self) -> dict | None:
        """Load chain checkpoint if one exists for the current target."""
        try:
            if not self._CHECKPOINT_PATH.exists():
                return None
            data = json.loads(self._CHECKPOINT_PATH.read_text())
            # Only resume if same target
            if data.get("target") != self.state.target:
                return None
            return data
        except Exception:
            return None

    def _clear_checkpoint(self):
        """Remove the checkpoint file after chain completion."""
        try:
            self._CHECKPOINT_PATH.unlink(missing_ok=True)
        except Exception:
            pass

    def _detect_os(self) -> str:
        """Detect the target OS from engagement state and phase outputs.

        Returns: "linux", "windows", or "unknown"
        """
        # Check engagement notes for OS clues
        notes_str = " ".join(self.state.notes).lower()
        # Check recon/exploit results for OS indicators
        results_str = ""
        for agent in (self.recon, self.exploit):
            if agent.results:
                last = agent.results[-1].get("response", "") + agent.results[-1].get("summary", "")
                results_str += last.lower()

        combined = notes_str + " " + results_str

        # Windows indicators
        windows_signals = [
            "winrm", "windows", "smb", "active directory", "domain controller",
            "powershell", "cmd.exe", "ntlm", "kerberos", "c:\\",
            "iis", "aspx", "mssql", ".exe", "mimikatz", "bloodhound",
        ]
        # Linux indicators
        linux_signals = [
            "linux", "ubuntu", "debian", "centos", "alpine", "www-data",
            "uid=", "/bin/bash", "/bin/sh", "apache", "nginx", "ssh",
            "docker", "container", "/etc/passwd", "cron", "systemd",
        ]

        win_score = sum(1 for s in windows_signals if s in combined)
        linux_score = sum(1 for s in linux_signals if s in combined)

        if linux_score > win_score and linux_score >= 2:
            return "linux"
        elif win_score > linux_score and win_score >= 2:
            return "windows"
        return "unknown"

    def _detect_cloud(self) -> bool:
        """Detect if the engagement involves cloud infrastructure."""
        notes_str = " ".join(self.state.notes).lower()
        results_str = ""
        for agent in (self._agents.get("recon"), self._agents.get("exploit")):
            if agent and agent.results:
                last = agent.results[-1].get("response", "") + agent.results[-1].get("summary", "")
                results_str += last.lower()

        combined = notes_str + " " + results_str

        cloud_signals = [
            "aws", "boto3", "iam", "s3 bucket", "lambda", "ec2",
            "sqs", "sts", "codebuild", "localstack", "imds",
            "169.254.169.254", "metadata", "instance-profile",
            "gcloud", "gcp", "azure", "az ", "kubectl",
            "eks", "ecs", "fargate", "assume-role",
        ]
        return sum(1 for s in cloud_signals if s in combined) >= 2

    def _resolve_agent(self, agent_name: str) -> str:
        """Auto-route generic agent names to OS-specific or substrate-specific variants.

        Maps:
          postex → linux_postex / windows_postex
          lateral → linux_lateral / windows_lateral
          exploit (with cloud context) → cloud (when task is cloud-specific)
        """
        os_type = self._detect_os()

        if agent_name == "postex" and os_type != "unknown":
            resolved = f"{os_type}_postex"
            return resolved
        # Support "lateral" as a shorthand that gets resolved
        if agent_name in ("lateral", "postex_lateral"):
            if os_type != "unknown":
                return f"{os_type}_lateral"
            return "linux_lateral"  # Default to linux if unknown

        return agent_name

    def dispatch(self, agent_name: str, task: str, on_status=None, on_progress=None,
                 summarize: bool = True, host: str = "", max_turns: int | None = None,
                 skip_rag: bool = False) -> str:
        """Dispatch a task to a specific agent.

        Args:
            summarize: If True, cache raw output and return a compressed summary
                       for downstream consumption. Raw output saved to evidence/.output_cache/.
            host: Optional specific host for this dispatch (for multi-target).
            max_turns: Optional turn limit override (for subtask mode).
            skip_rag: Skip RAG retrieval (for narrow subtasks).
        """
        # Auto-route generic agents to OS-specific variants
        original_name = agent_name
        agent_name = self._resolve_agent(agent_name)
        if agent_name != original_name and on_status:
            on_status(f"[orchestrator] Auto-routing {original_name} → {agent_name} (detected OS: {self._detect_os()})")

        agent = self._get_agent(agent_name)
        if not agent:
            return f"Unknown agent: {agent_name}. Use: {', '.join(self.PHASES)}"

        # --- LE mode boundary: no post-exploitation or lateral movement ---
        # In bug bounty / pentest (LE) mode, stop at initial access. Prove you
        # can get a shell, document it, but don't pivot or escalate further.
        _le_blocked = ("postex", "linux_postex", "windows_postex",
                       "linux_lateral", "windows_lateral")
        if getattr(self.state, "engagement_mode", "ctf") == "le" and agent_name in _le_blocked:
            msg = (f"[orchestrator] BLOCKED: {agent_name} not permitted in LE mode — "
                   f"stop at initial access (reverse shell / proof of access)")
            if on_status:
                on_status(msg)
            if on_progress:
                on_progress({"type": "error", "agent": "orchestrator", "text": msg})
            return msg

        # --- Scope enforcement (hard gate) ---
        target_host = host or self.state.target
        scope_enforcer = getattr(self.state, "scope_enforcer", None)
        if scope_enforcer and target_host:
            in_scope, reason = scope_enforcer.is_in_scope(target_host)
            if not in_scope:
                msg = f"[orchestrator] BLOCKED: {agent_name} dispatch to {target_host} — {reason}"
                if on_status:
                    on_status(msg)
                if on_progress:
                    on_progress({"type": "error", "agent": "orchestrator", "text": msg})
                return msg

        # Track agent assignment in target manager
        if target_host and hasattr(self.state, "target_manager"):
            self.state.target_manager.assign_agent(target_host, agent_name)

        if on_status:
            host_label = f" ({target_host})" if host else ""
            on_status(f"[orchestrator] Dispatching to {agent_name} agent{host_label}...")
        if on_progress:
            on_progress({
                "type": "phase",
                "agent": agent_name,
                "text": f"Dispatching task to {agent_name} agent",
                "task": task[:300],
            })

        # Inject exhausted-category blacklist into the task so the agent
        # won't repeat approaches that were already proven unproductive.
        _stuck_state = StuckDetector.load(agent_name, getattr(self.state, "dir", None))
        if _stuck_state.exhausted_categories:
            blacklist = ", ".join(sorted(_stuck_state.exhausted_categories))
            task = (
                f"{task}\n\n"
                f"**BLACKLISTED ATTACK CATEGORIES (do NOT attempt):** {blacklist}\n"
                f"These categories were exhausted in previous dispatches. "
                f"Use a fundamentally different approach."
            )

        import time as _time
        phase_start = _time.monotonic()
        raw_response = agent.run(task, on_status=on_status, on_progress=on_progress,
                                 max_turns=max_turns, skip_rag=skip_rag)
        phase_elapsed = _time.monotonic() - phase_start

        # Cache raw output to disk
        cache_path = cache_output(agent_name, task, raw_response)

        # Check if agent was stuck-killed
        was_stuck = bool(agent.results and agent.results[-1].get("stuck_killed"))

        elapsed_str = f"{int(phase_elapsed // 60):02d}:{int(phase_elapsed % 60):02d}"

        # Detect if this dispatch achieved a milestone (for cost-of-pass tracking)
        milestone_hit = False
        if agent.results:
            resp = agent.results[-1].get("response", "").lower()
            milestone_keywords = [
                "rce confirm", "shell obtained", "uid=0", "whoami",
                "root flag", "user flag", "privilege escalat",
                "domain admin achieved", "domain admin access", "da access",
                "credentials found", "password crack", "authenticated",
            ]
            milestone_hit = any(kw in resp for kw in milestone_keywords)

        # Track cost-of-pass
        self.cost_tracker.record(
            agent_name, agent._last_cost, agent._last_turns, milestone_hit
        )

        self.phase_log.append({
            "agent": agent_name,
            "task": task[:200],
            "response_length": len(raw_response),
            "cost": agent._last_cost,
            "turns": agent._last_turns,
            "elapsed": elapsed_str,
            "elapsed_seconds": phase_elapsed,
            "opsec_events": len(agent.opsec_log),
            "stuck_killed": was_stuck,
            "milestone_hit": milestone_hit,
            "time": datetime.now().isoformat(),
            "cache_path": str(cache_path),
        })

        # Summarize for downstream handoff
        output = raw_response
        if summarize and len(raw_response) > 1500:
            summary = summarize_output(agent_name, raw_response, on_status)
            # Store both on the agent results for reporting
            if agent.results:
                agent.results[-1]["summary"] = summary
                agent.results[-1]["cache_path"] = str(cache_path)
            output = summary

        # Extract structured findings into DB — with impact gate
        # Skip for analysis-only agents (synthesis, report) — their output describes
        # PROPOSED actions, not actual exploitation results. Parsing them creates garbage.
        _new_finding_ids = []
        if agent_name not in ("synthesis", "report", "triage", "noise_filter", "sanity_checker"):
            raw_findings = extract_findings_from_summary(
                agent_name, output, target_host or self.state.target, db=None  # Don't write yet
            )
            # Apply impact gate before writing to DB
            for finding in raw_findings:
                gated = gate_finding(finding, evidence_text=output)
                fid = self.findings_db.add(gated)
                _new_finding_ids.append(fid)

        # LE mode: run PoC verification on new findings
        if _new_finding_ids and getattr(self.state, "engagement_mode", "ctf") == "le":
            try:
                from poc_verifier import verify_pending_findings
                evidence_dir = getattr(self.state, "evidence_dir", None)
                if evidence_dir:
                    poc_stats = verify_pending_findings(
                        self.findings_db, evidence_dir,
                        host=target_host or self.state.target,
                        on_status=on_status,
                    )
                    if on_status and poc_stats["total"] > 0:
                        on_status(
                            f"[poc] Results: {poc_stats['confirmed']} confirmed, "
                            f"{poc_stats['manual']} need manual PoC, "
                            f"{poc_stats['unconfirmed']} unconfirmed"
                        )
            except Exception:
                pass

        # Parse credentials from agent output into engagement state
        try:
            self.state.parse_credentials_from_text(raw_response)
        except Exception:
            pass

        # Parse discovered hosts from agent output
        try:
            self.state.parse_hosts_from_text(raw_response, source=agent_name)
        except Exception:
            pass

        # Update target manager findings count
        if target_host and hasattr(self.state, "target_manager"):
            count = self.findings_db.count(host=target_host)
            self.state.target_manager.update_findings_count(target_host, count)
            self.state.target_manager.release_agent(target_host, agent_name)

        # Queue sanity check for full-phase dispatches (skip subtasks and meta-agents).
        # Runs async — doesn't block the next dispatch.
        meta_agents = {"triage", "noise_filter", "sanity_checker", "report"}
        is_subtask = max_turns is not None and max_turns <= 5
        if agent_name not in meta_agents and not is_subtask and len(output) > 500:
            self._queue_sanity_check(agent_name, output, on_status)

        return output

    def execute_chain(self, chain_name: str, validation_commands: list[str],
                      execution_commands: list[str], agent_name: str = "exploit",
                      on_status=None, on_progress=None) -> str:
        """Execute a synthesis chain as a single coherent task with full turn budget.

        Unlike micro-dispatch (3 turns, isolated, batch-planned), chain execution:
        - Gives ONE agent ALL steps in one session
        - Uses Opus with 12+ turns for error handling
        - Commands are executed VERBATIM, not reinterpreted
        - Errors are fixed inline, not in the next dispatch
        """
        # Build the chain task prompt
        all_commands = []
        step_num = 0

        if validation_commands:
            all_commands.append("## PHASE 1: VALIDATION")
            all_commands.append("Run these validation checks first. If any fail critically, report why and stop.")
            for cmd in validation_commands:
                step_num += 1
                all_commands.append(f"  {step_num}. {cmd}")
            all_commands.append("")

        if execution_commands:
            all_commands.append("## PHASE 2: EXECUTION")
            all_commands.append("Execute these commands IN ORDER after validation passes:")
            for cmd in execution_commands:
                step_num += 1
                all_commands.append(f"  {step_num}. {cmd}")
            all_commands.append("")

        task_prompt = f"""[CHAIN EXECUTION: {chain_name}]

Execute this exploitation chain as a SINGLE coherent operation.

{chr(10).join(all_commands)}

## CRITICAL INSTRUCTIONS:
- Execute commands IN ORDER. Do NOT skip steps or reorder.
- Execute commands VERBATIM as written. Do NOT reinterpret or "improve" them.
- Use sudo for any operation that requires elevated privileges on Kali.
- Handle errors INLINE:
  - Clock skew? Run `sudo ntpdate <dc>` or `sudo timedatectl set-ntp false && sudo date -s "..."` then RETRY.
  - Connection refused? Check if the service is reachable, adjust port, then RETRY.
  - Auth failure? Check credentials in engagement state, then RETRY with correct creds.
  - Tool not found? Install it (`apt install` / `pip install`) then RETRY.
- Do NOT abandon the chain for fixable errors. Only stop if the attack path is fundamentally broken.
- Do NOT switch to a different technique unless every step has been attempted and failed.
- Report the outcome of each step before proceeding to the next.
- Save any credentials, flags, or access tokens to the evidence directory.
- **CTF MODE: STOP when you have the flag.** Once you read root.txt/user.txt, output it and STOP.
  Do NOT: establish persistence, create scheduled tasks, DCSync, enumerate further, clean up.
  The flag IS the objective. Everything after reading it is wasted.

## INLINE DECISION POINTS:
After each step, before proceeding to the next, check whether the output matches what the chain expects:
- **Version/service mismatch**: If the target service version, OS, or configuration differs from what the chain assumes, STOP and report the mismatch. Do NOT blindly run the remaining steps.
- **Unexpected auth state**: If an earlier step reveals the target requires different credentials, authentication method, or access path than planned, ADAPT the remaining steps or STOP.
- **Partial success**: If a step partially succeeds (e.g., code execution but no shell, write access but not where expected), note what DID work and adjust the next step to build on the actual result.
- **Different attack surface**: If validation reveals the target has different services/ports/paths than planned, report what you found and adapt.
Do NOT continue executing verbatim commands when the underlying assumptions have changed.

"""

        if on_status:
            on_status(f"[orchestrator] CHAIN EXEC ({chain_name}): {step_num} steps → {agent_name} agent (max {CHAIN_MAX_TURNS} turns)")
        if on_progress:
            on_progress({
                "type": "chain_exec",
                "agent": agent_name,
                "chain": chain_name,
                "steps": step_num,
                "max_turns": CHAIN_MAX_TURNS,
            })

        # Dispatch with full turn budget — bypasses batch planner entirely
        result = self.dispatch(
            agent_name, task_prompt,
            on_status=on_status, on_progress=on_progress,
            summarize=True, max_turns=CHAIN_MAX_TURNS, skip_rag=False,
        )

        if on_status:
            on_status(f"[orchestrator] CHAIN EXEC ({chain_name}): complete.")

        return result

    def dispatch_parallel(self, tasks: list[dict], on_status=None, on_progress=None,
                          summarize: bool = True) -> dict[str, str]:
        """Dispatch multiple agents in parallel.

        Args:
            tasks: List of dicts with 'agent' and 'task' keys.
            on_status: Status callback (shared, thread-safe via console).
            on_progress: Progress callback (shared, thread-safe via console).
            summarize: Summarize outputs for downstream consumption.

        Returns:
            Dict mapping agent_name -> output (summarized if enabled).
        """
        results = {}

        if on_status:
            agent_names = [t["agent"] for t in tasks]
            on_status(f"[orchestrator] Running in parallel: {', '.join(agent_names)}")
        if on_progress:
            on_progress({
                "type": "phase",
                "agent": "orchestrator",
                "text": f"Parallel dispatch: {', '.join(t['agent'] for t in tasks)}",
            })

        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {}
            for t in tasks:
                future = executor.submit(
                    self.dispatch,
                    t["agent"], t["task"],
                    on_status, on_progress, summarize,
                )
                futures[future] = t["agent"]

            for future in as_completed(futures):
                agent_name = futures[future]
                try:
                    results[agent_name] = future.result()
                except Exception as e:
                    results[agent_name] = f"[{agent_name}] Parallel execution error: {e}"
                    if on_status:
                        on_status(f"[orchestrator] {agent_name} failed: {e}")

        return results

    # --- Subtask-based dispatch ---

    def dispatch_subtasks(self, subtasks: list[SubTask], on_status=None, on_progress=None,
                          summarize: bool = True) -> dict[str, str]:
        """Execute subtasks respecting per-subtask dependencies.

        Uses a dependency-aware executor that starts each subtask as soon as
        its specific dependencies complete — not waiting for entire batches.
        This prevents slow subtasks (e.g., udp_scan) from blocking unrelated work.

        Returns: dict mapping subtask_name -> output text
        """
        all_results = {}
        by_name = {st.name: st for st in subtasks}

        # Track which subtasks are ready, running, done
        pending = set(st.name for st in subtasks)
        completed = set()

        if on_status:
            on_status(f"[orchestrator] Executing {len(subtasks)} subtasks with dependency resolution")

        with ThreadPoolExecutor(max_workers=min(12, len(subtasks))) as executor:
            active_futures = {}  # future -> subtask name

            while pending or active_futures:
                # Find subtasks whose dependencies are all satisfied
                ready = []
                for name in list(pending):
                    st = by_name[name]
                    if all(d in completed for d in st.depends_on):
                        ready.append(st)

                # Submit ready subtasks
                for st in ready:
                    pending.discard(st.name)

                    # Fill dependency context
                    TaskDecomposer.fill_dependency_context(st, all_results)

                    # Check skip condition
                    if st.skip_condition:
                        skip = self._should_skip_subtask(st, all_results)
                        if skip:
                            if on_status:
                                on_status(f"[orchestrator] Skipping {st.name}: {st.skip_condition}")
                            all_results[st.name] = f"(skipped: {st.skip_condition})"
                            completed.add(st.name)
                            continue

                    if on_status:
                        on_status(f"[orchestrator] Starting subtask: {st.name}")

                    future = executor.submit(
                        self.dispatch,
                        st.agent, st.task, on_status, on_progress,
                        summarize, st.host, st.max_turns, True,  # skip_rag=True
                    )
                    active_futures[future] = st.name

                if not active_futures:
                    break  # Nothing running and nothing ready — done or deadlocked

                # Wait for at least one to finish, then re-check ready list
                # Use a short timeout to poll for completions without blocking forever
                import concurrent.futures
                done, _ = concurrent.futures.wait(
                    active_futures.keys(),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    name = active_futures.pop(future)
                    try:
                        all_results[name] = future.result()
                    except Exception as e:
                        all_results[name] = f"[{name}] Error: {e}"
                    completed.add(name)
                    if on_status:
                        on_status(f"[orchestrator] Subtask completed: {name}")

        return all_results

    def _should_skip_subtask(self, subtask: SubTask, prior_results: dict) -> bool:
        """Evaluate whether a subtask should be skipped based on prior results."""
        port_scan_output = prior_results.get("port_scan", "")

        if subtask.skip_condition == "no_web_ports":
            # Skip web enum if no HTTP/HTTPS ports found
            import re
            web_indicators = re.search(r"(80|443|8080|8443|8000|8888|3000)/tcp\s+open", port_scan_output)
            http_indicators = re.search(r"https?|http|ssl/http|web", port_scan_output, re.IGNORECASE)
            return not (web_indicators or http_indicators)

        if subtask.skip_condition == "no_smb_port":
            return "445/tcp" not in port_scan_output and "microsoft-ds" not in port_scan_output.lower()

        if subtask.skip_condition == "no_credentials":
            return not self.state.credentials

        if subtask.skip_condition == "no_cves":
            return self.findings_db.count(finding_type="cve") == 0

        return False

    # --- Sanity checking (async, non-blocking) ---

    _sanity_executor = None  # Lazy-initialized thread pool
    _sanity_future = None    # Track the running sanity check

    def _queue_sanity_check(self, agent_name: str, agent_output: str, on_status=None):
        """Queue a sanity check to run async. Non-blocking — the next phase starts immediately.

        The result is picked up by _analyze_and_decide before the next decision point,
        which is the only place the sanity review is consumed.
        """
        # Wait for any prior sanity check to finish first (at most one in flight)
        self._collect_sanity_result(on_status)

        if self._sanity_executor is None:
            self._sanity_executor = ThreadPoolExecutor(max_workers=1)

        if on_status:
            on_status(f"[orchestrator] Sanity check queued for {agent_name} (async)")

        self._sanity_future = self._sanity_executor.submit(
            self._run_sanity_check, agent_name, agent_output, on_status
        )

    def _collect_sanity_result(self, on_status=None):
        """Collect the result of the async sanity check if one is running."""
        if self._sanity_future is not None and self._sanity_future.done():
            try:
                self._sanity_future.result()  # Propagate any exceptions
            except Exception as e:
                if on_status:
                    on_status(f"[orchestrator] Sanity check failed: {e}")
            self._sanity_future = None

    def _run_sanity_check(self, agent_name: str, agent_output: str, on_status=None):
        """Run the sanity checker. Called from background thread."""
        truncated = agent_output[:6000]
        if len(agent_output) > 6000:
            truncated += "\n\n... (truncated for review)"

        prompt = (
            f"Review this output from the **{agent_name}** agent. "
            f"Check for severity inflation, wasted turns, false positives, "
            f"narrative building, and speculative findings.\n\n"
            f"--- AGENT OUTPUT ---\n{truncated}\n--- END ---"
        )

        try:
            review = self.sanity_checker.run(
                prompt, on_status=on_status, max_turns=2, skip_rag=True
            )
            self._last_sanity_review = review
            self._apply_sanity_overrides(review, on_status)
        except Exception as e:
            if on_status:
                on_status(f"[orchestrator] Sanity check error: {e}")
            self._last_sanity_review = ""

    def _apply_sanity_overrides(self, review_text: str, on_status=None):
        """Parse sanity checker output and apply severity overrides to findings DB."""
        try:
            # Strip markdown fences
            text = review_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
            text = text.strip()

            review = json.loads(text)

            # Apply severity overrides
            overrides = review.get("severity_overrides", {})
            if overrides and on_status:
                on_status(f"[sanity] Applying {len(overrides)} severity override(s)")

            for title, new_severity in overrides.items():
                # Find matching findings in DB and update severity
                findings = self.findings_db.query(limit=100)
                for f in findings:
                    if title.lower() in (f.get("title", "") or "").lower():
                        conn = self.findings_db._get_conn()
                        conn.execute(
                            "UPDATE findings SET severity = ? WHERE id = ?",
                            (new_severity, f["id"]),
                        )
                        conn.commit()
                        if on_status:
                            on_status(
                                f"[sanity] {f['title']}: {f['severity']} -> {new_severity}"
                            )

            # Log quality assessment
            quality = review.get("overall_quality", "unknown")
            if on_status:
                on_status(f"[sanity] Quality: {quality}")

            wasted = review.get("wasted_turns", {})
            if wasted.get("count", 0) > 0 and on_status:
                on_status(f"[sanity] Wasted turns: {wasted['count']} — {wasted.get('description', '')[:100]}")

            if review.get("narrative_building", {}).get("detected") and on_status:
                on_status(f"[sanity] Narrative building detected: {review['narrative_building'].get('description', '')[:100]}")

        except (json.JSONDecodeError, KeyError, TypeError):
            # Non-JSON output — store raw review text for the orchestrator
            pass

    # --- Direct dispatch (manual control) ---

    def run_recon(self, task: str = "", on_status=None, on_progress=None) -> str:
        if not task:
            task = self._build_default_recon_task()
        return self.dispatch("recon", task, on_status, on_progress)

    def run_exploit(self, task: str = "", on_status=None, on_progress=None) -> str:
        if not task:
            task = self._build_default_exploit_task()
        return self.dispatch("exploit", task, on_status, on_progress)

    def run_postex(self, task: str = "", on_status=None, on_progress=None) -> str:
        if not task:
            task = self._build_default_postex_task()
        return self.dispatch("postex", task, on_status, on_progress)

    def run_codereview(self, task: str = "", on_status=None, on_progress=None) -> str:
        if not task:
            task = self._build_default_codereview_task()
        return self.dispatch("codereview", task, on_status, on_progress)

    def run_cvehunter(self, task: str = "", on_status=None, on_progress=None) -> str:
        if not task:
            task = self._build_default_cvehunter_task()
        return self.dispatch("cvehunter", task, on_status, on_progress)

    # --- LLM-powered decision making ---

    def _analyze_and_decide(self, phase_just_completed: str, phase_output: str,
                            on_status=None, host: str = "") -> Decision:
        """Use Claude to analyze phase results and decide the next move."""
        # Collect async sanity check result before deciding
        self._collect_sanity_result(on_status)

        if on_status:
            on_status("[orchestrator] Analyzing results and planning next move...")

        analysis_prompt = self._build_analysis_prompt(phase_just_completed, phase_output)

        try:
            result = claude_client.oneshot(analysis_prompt, model=MODEL_FAST, timeout=120)

            if result.returncode != 0 or not result.stdout.strip():
                # Fallback: use template-based decision
                return self._fallback_decision(phase_just_completed)

            return self._parse_decision(result.stdout.strip(), phase_just_completed)

        except Exception:
            return self._fallback_decision(phase_just_completed)

    def _plan_batch(self, phase_completed: str, output: str,
                    on_status=None, batch_size: int = 4) -> list[Decision]:
        """Generate a batch of micro-tasks at once to reduce orchestrator overhead.

        Instead of one haiku call per micro-dispatch, generates batch_size tasks
        in a single call. Tasks are executed sequentially without analysis between them.
        Re-planning happens only when the batch is exhausted or a milestone is hit.
        """
        self._collect_sanity_result(on_status)
        if on_status:
            on_status(f"[orchestrator] Planning next {batch_size} micro-tasks...")

        output_truncated = output[:4000]
        state_summary = self.state.summary()
        exit_eval = ExitEvaluator(self.findings_db, self.phase_log)
        exit_info = exit_eval.evaluate().format_for_prompt()
        findings_summary = self.findings_db.summary_for_prompt(max_chars=1000)

        # Include the strategic attack plan if it exists
        plan_context = self.attack_plan.for_prompt()

        # Check if synthesis has active HIGH chains — they take absolute priority
        synth_active = [p for p in self.attack_plan.paths
                        if p.get("source") == "synthesis" and p.get("status") == "active"]
        synth_directive = ""
        if synth_active:
            synth_directive = (
                "\n\n⚠️ SYNTHESIS OVERRIDE ACTIVE — the synthesis agent identified HIGH viability "
                "attack chains that SUPERSEDE all other paths. Your tasks MUST execute the synthesis "
                "chain steps. Do NOT plan tasks for superseded/exhausted paths. Do NOT deviate.\n"
                "Synthesis chains to execute:\n" +
                "\n".join(
                    f"  - {p['name']}: {p['steps']} (next: {p.get('next_step', '?')})"
                    for p in synth_active
                )
            )

        # Inject operator directives (user corrections/context after Ctrl+C)
        operator_directives = [
            n.replace("[operator directive] ", "")
            for n in self.state.notes if n.startswith("[operator directive]")
        ]
        directive_block = ""
        if operator_directives:
            directive_block = (
                "\n\n⚠️ OPERATOR DIRECTIVES (MANDATORY — the operator interrupted to give you these):\n"
                + "\n".join(f"  - {d}" for d in operator_directives[-3:])
                + "\nYour tasks MUST follow these directives. They override previous plans."
            )

        # --- Exploitation commitment gate ---
        # Check for findings that were identified but never exploited to proof.
        # If unproven exploitable findings exist, force the planner to complete
        # at least one attack chain before doing more recon.
        commitment_block = ""
        unproven = self.findings_db.unproven_findings(min_severity="medium")
        if unproven:
            # Format the top 3 most severe unproven findings
            unproven_lines = []
            for f in unproven[:3]:
                unproven_lines.append(
                    f"  - [{f['severity'].upper()}] {f['title']} on {f['host']}:{f['port']} "
                    f"(found by {f['agent']}, poc_status: {f['poc_status']})"
                )
            commitment_block = (
                "\n\n🔴 EXPLOITATION COMMITMENT REQUIRED — you have unproven findings:\n"
                + "\n".join(unproven_lines) +
                "\n\nA vulnerability scanner finds issues. A penetration tester PROVES them.\n"
                "BEFORE planning any new recon or enumeration tasks, your FIRST tasks MUST:\n"
                "  1. Pick the highest-severity unproven finding above\n"
                "  2. Complete the attack chain to proof (capture data, get a shell, demonstrate impact)\n"
                "  3. Only after proving OR disproving the finding can you move to new targets\n"
                "If exploitation fails, mark the finding as disproven and explain why — then move on.\n"
                "Do NOT scan new subdomains, enumerate new endpoints, or shift targets until this is done."
            )

        batch_prompt = f"""You are a red team engagement orchestrator. Plan the next {batch_size} SPECIFIC micro-tasks.
Each task will be executed by an agent with only 3 turns (1-2 commands). Be extremely specific.
Your tasks MUST serve the attack plan below — don't go off-plan unless all paths are blocked.{directive_block}
{synth_directive}
{commitment_block}

{plan_context if plan_context else "No attack plan yet — generate exploratory tasks."}

## State
{state_summary}
{exit_info}
{findings_summary or 'No findings yet.'}

## Last Output ({phase_completed})
{output_truncated}

## Phase History
{self._format_phase_history()[-1000:]}

## Available Agents
{self._available_agents_for_prompt()}

Respond with ONLY a JSON array of {batch_size} tasks (no markdown, no fences):
[
    {{"agent": "agent_name", "task": "SPECIFIC task: run this exact command on this target"}},
    {{"agent": "agent_name", "task": "SPECIFIC next step based on likely outcome of task 1"}},
    {{"agent": "agent_name", "task": "Alternative if task 2 doesn't yield results"}},
    {{"agent": "agent_name", "task": "Follow-up exploitation or enumeration"}}
]

Rules:
- Each task must be completable in 1-2 commands
- Include exact commands, file paths, endpoints, or parameters
- Order tasks logically — each builds on the likely output of the previous
- Set agent to the OS-specific variant when the OS is known

**Decision quality:**
- If a previous task FAILED, the next task should DIAGNOSE WHY — not try something different.
  Example: PKINIT failed with clock skew → next task: "run sudo ntpdate TARGET then retry PKINIT"
  NOT: "try a completely different technique"
- Fix prerequisites before retrying: clock sync, listener setup, file permissions
- Only abandon a vector when the failure is POLICY-BASED (access denied, not supported)
  not CONFIGURATION-BASED (clock skew, wrong port, missing tool)

**Efficiency:**
- When using indirect execution (DLL hijack, scheduled task), batch ALL checks into ONE payload.
  Plan: "deploy DLL that runs: whoami > out1.txt && query user > out2.txt && dir C:\\ > out3.txt"
  NOT: "deploy DLL for whoami" then next batch "deploy DLL for query user"
- Plan setup validation BEFORE triggers: "verify SMB listener captures auth" THEN "trigger target auth"
- If a technique has a 3-minute wait cycle, the NEXT task should use that wait time productively
  (enumerate from another angle while waiting)

**Tool selection (CRITICAL — wrong tool = wasted turns):**
- For one-shot remote commands on Windows targets:
  `crackmapexec winrm 10.129.32.101 -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5' -x 'COMMAND'`
  For PowerShell: use -X instead of -x
  NEVER use Invoke-Command with PSCredential (wrong auth method for hash-based accounts)
  NEVER use evil-winrm for one-shot commands (interactive only)
- For file upload: `crackmapexec smb TARGET -u USER -H HASH --put-file local_path remote_path`
- For cert enrollment FROM KALI: `certipy req -u USER -k -dc-ip DC ...` (uses .ccache TGT)
  NOT DLL hijack with certreq.exe (3-min feedback loop)
- For Kali local ops that need root: ALWAYS prefix with `sudo` (passwordless)
- ALWAYS prefer direct Kali execution over indirect target execution when credentials allow
- For TLS certs: ALWAYS specify `-dns HOSTNAME` for the SAN. Without it, TLS validation FAILS.
- NEVER use the old IP 10.129.245.130 — the current target is in the state.

**Defense awareness:**
- NEVER plan tasks blocked by known defenses (SMB signing = no relay, Protected Users = no NTLM, etc.)
- BloodHound first if AD escalation needed and not yet run
- Don't repeat failed techniques with different tools (same defense blocks all)"""

        try:
            result = claude_client.oneshot(batch_prompt, model=MODEL_PLANNER, timeout=90)
            if result.returncode != 0 or not result.stdout.strip():
                return [self._fallback_decision(phase_completed)]

            text = result.stdout.strip()
            # Strip markdown fences
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]

            tasks = json.loads(text.strip())
            decisions = []
            for t in tasks:
                d = Decision({
                    "next_agent": t.get("agent", "exploit"),
                    "task": t.get("task", ""),
                    "reasoning": f"Batch-planned task ({len(decisions)+1}/{len(tasks)})",
                    "confidence": 75,
                })
                if d.task and d.next_agent in self._AGENT_CLASSES:
                    decisions.append(d)

            return decisions if decisions else [self._fallback_decision(phase_completed)]

        except (json.JSONDecodeError, Exception):
            return [self._fallback_decision(phase_completed)]

    def _available_agents_for_prompt(self, verbose: bool = False) -> str:
        """Return the agent list appropriate for the current engagement mode.

        In LE (bug bounty/pentest) mode, postex and lateral agents are excluded —
        the engagement boundary is initial access (reverse shell / proof of access).
        """
        _all_agents = {
            "recon": "OSINT, passive/active reconnaissance, scanning, enumeration",
            "param_analyzer": "URL/parameter attack surface mapping — extracts parameters, maps to attack vectors, produces prioritized test plan",
            "exploit": "Vulnerability exploitation, credential attacks, payload delivery, initial access",
            "linux_postex": "Linux/container post-exploitation — enumeration, SUID/capability/kernel privesc, Docker escape, credential harvesting",
            "windows_postex": "Windows post-exploitation — enumeration, SeImpersonate/Potato/UAC/service privesc, SAM/LSASS dumping",
            "linux_lateral": "Linux lateral movement — SSH pivoting, tunneling (chisel/ligolo), credential reuse, container-to-host breakout",
            "windows_lateral": "Windows/AD lateral movement — pass-the-hash, Kerberos, ADCS, delegation, WinRM/DCOM, domain dominance, DCSync",
            "synthesis": "Combinatorial attack path analysis — finds chains that combine 2+ findings into viable paths",
            "postex": "Generic post-exploitation (fallback — prefer OS-specific agents above)",
            "cloud": "Cloud substrate specialist — IAM enumeration, permission-keyed escalation, SSRF→IMDS, cross-account lateral, SQS/Lambda/CodeBuild exploitation, LocalStack bypass. Use when cloud APIs, IAM roles, or managed services are involved.",
            "codereview": "Source code analysis, vulnerability discovery, secret extraction from discovered code",
            "cvehunter": "CVE scanning, PoC research and acquisition, vulnerability validation against discovered services",
        }
        _le_blocked = {"postex", "linux_postex", "windows_postex",
                       "linux_lateral", "windows_lateral"}
        is_le = getattr(self.state, "engagement_mode", "ctf") == "le"

        agents = {k: v for k, v in _all_agents.items()
                  if not (is_le and k in _le_blocked)}

        if verbose:
            lines = []
            for name, desc in agents.items():
                lines.append(f"- **{name}**: {desc}")
            if is_le:
                lines.append("\n**LE MODE BOUNDARY**: Post-exploitation and lateral movement agents are disabled. "
                             "Stop at initial access — prove the shell, document the finding, move to next target.")
            return "\n".join(lines)
        else:
            agent_list = ", ".join(agents.keys())
            if is_le:
                agent_list += ("\n\n**LE MODE BOUNDARY**: No postex or lateral movement. "
                               "If you achieve a reverse shell or RCE, document it as a finding and move to the next target.")
            return agent_list

    def _build_analysis_prompt(self, phase_completed: str, output: str) -> str:
        """Build the prompt for the LLM decision maker."""
        # Truncate output to avoid token limits
        output_truncated = output[:4000]
        if len(output) > 4000:
            output_truncated += "\n\n... (output truncated)"

        state_summary = self.state.summary()

        # Include exit evaluator score for informed decision-making
        exit_eval = ExitEvaluator(self.findings_db, self.phase_log)
        exit_score = exit_eval.evaluate(host=None)
        exit_info = exit_score.format_for_prompt()

        # Include findings DB summary
        findings_summary = self.findings_db.summary_for_prompt(max_chars=2000)

        # Exploitation commitment check
        commitment_section = ""
        unproven = self.findings_db.unproven_findings(min_severity="medium")
        if unproven:
            top3 = unproven[:3]
            commitment_section = (
                "\n\n🔴 EXPLOITATION COMMITMENT — unproven findings exist:\n"
                + "\n".join(
                    f"  - [{f['severity'].upper()}] {f['title']} on {f['host']}:{f['port']}"
                    for f in top3
                )
                + "\nYou MUST assign a task to exploit/prove one of these BEFORE any new recon."
            )

        return f"""You are a red team engagement orchestrator. You just completed the **{phase_completed}** phase. Analyze the results and decide the next action.

## Engagement State
{state_summary}
ROE: {self.state.roe or 'Standard rules — no denial of service, stay in scope'}
{commitment_section}

## Exit Evaluator
{exit_info}

## Known Findings (from database)
{findings_summary or 'No findings recorded yet.'}

## {phase_completed.upper()} Phase Output
{output_truncated}

## Sanity Check Review
{self._last_sanity_review[:2000] if self._last_sanity_review else 'No sanity check available.'}

## Previous Phases
{self._format_phase_history()}

## Available Agents
{self._available_agents_for_prompt(verbose=True)}

**IMPORTANT: Choose the OS-specific agent when you know the target OS.**
- Shell on Linux/container → use **linux_postex** (not generic postex)
- Shell on Windows → use **windows_postex** (not generic postex)
- Need to pivot from Linux → use **linux_lateral**
- Need AD/Windows lateral movement → use **windows_lateral**

## Your Task — MICRO-DISPATCH MODE
The agent will run for ONLY 3 turns (1-2 commands max). Write a NARROW, SPECIFIC task
that can be completed in 3 turns. Do NOT write broad tasks like "exploit the web app" —
write tasks like "run sqlmap on /api/v1/user with token=0 parameter" or
"check if C:\\ProgramData\\UpdateMonitor is writable with icacls".

Respond in EXACTLY this JSON format (no markdown, no code fences):

{{
    "next_agent": "recon|exploit|linux_postex|windows_postex|linux_lateral|windows_lateral|synthesis|codereview|cvehunter|param_analyzer",
    "task": "SPECIFIC task completable in 1-2 commands. Include exact targets, endpoints, parameters, or file paths.",
    "reasoning": "Why this is the right next step based on the output",
    "confidence": 0-100,
    "alternatives": [
        {{"agent": "agent_name", "description": "Alternative if primary fails"}}
    ],
    "should_stop": false,
    "stop_reason": ""
}}

**WHEN TO CHOOSE SYNTHESIS:**
- You have 2+ findings/ACL edges from different principals that might chain together
- The agent is stuck exploiting a single path — synthesis may reveal a multi-step chain
- You have dead-end findings that individually look useless but might combine (e.g., write-only ACL + coercion + relay)
- Task for synthesis: describe the primitives you want it to chain, e.g., "j.arbuckle has GenericWrite on l.wilson, l.wilson has ForceChangePassword on l.wilson_adm — find a viable chain"

**MICRO-TASK EXAMPLES (good):**
- "Run `certipy find -vulnerable` against DC01 with jaylee.clifton's TGT to enumerate ESC templates"
- "Check permissions on C:\\ProgramData\\UpdateMonitor with `icacls` via msa_health$ WinRM shell"
- "Try `evil-winrm -i TARGET -u svc_recovery -p 'Em3rg3ncyPa$$2026'` to test credential reuse"
- "Extract form fields from http://target/login and test token=0 type juggling"

**BAD (too broad):**
- "Exploit vulnerabilities on the target" ← too vague for 3 turns
- "Perform post-exploitation" ← what specifically?
- "Try different attack vectors" ← which ones?

**IMPORTANT — Agent stuck/terminated handling:**
If the output contains "AGENT TERMINATED — STUCK DETECTED" or mentions repeated failures,
you MUST choose a COMPLETELY DIFFERENT technique or agent. Do NOT retry the same approach
with minor variations. The output will include an "Approaches Tried" summary showing
which attack categories were attempted and which are marked EXHAUSTED. You MUST NOT
assign a task that falls into an exhausted category. Consider:
- Completing MISSING recon categories first (subdomain enum, directory brute-force, UDP scans)
- A different agent entirely (e.g., codereview instead of exploit)
- A fundamentally different attack vector NOT in the exhausted list
- Writing a standalone script to avoid multi-layer escaping issues
- Skipping this target and trying a different host/service

**RECON COMPLETENESS CHECK:**
Before assigning exploitation tasks, verify the recon output includes:
- Full TCP port scan results
- Web directory/endpoint enumeration
- Subdomain/vhost enumeration (ffuf with Host header fuzzing)
If any of these are missing, assign a recon task to fill the gap BEFORE exploitation.

Set confidence LOW (below 70) when:
- Results are ambiguous or incomplete
- Multiple equally valid paths exist
- High-risk techniques are the only option
- You're unsure about scope or ROE implications
- The phase failed or produced unexpected results
- An agent was terminated for being stuck (ALWAYS ask operator after stuck termination)

Set should_stop to true when:
- Engagement objectives are achieved (domain admin, data exfiltration, etc.)
- All attack paths are exhausted
- Continuing would violate ROE
- Critical OPSEC concern requires human decision

**SEVERITY CALIBRATION — do NOT treat these as findings:**
- CSP headers, technology identification, subdomain discovery = INFO recon data, not vulns
- API endpoints returning 401/403 = auth working correctly
- Login pages returning 200 = expected behavior
- Session cookies, debug headers = normal app behavior
- "Potential" or "possible" vulns without proof = unverified, do not escalate
Only count findings where exploitation was PROVEN (data accessed, auth bypassed, code executed).

Respond with ONLY the JSON object, nothing else."""

    def _format_phase_history(self) -> str:
        if not self.phase_log:
            return "None — this is the first phase."
        lines = []
        for entry in self.phase_log:
            suffix = ""
            if entry.get("stuck_killed"):
                suffix = " [STUCK — TERMINATED]"
            elapsed = entry.get("elapsed", "??:??")
            lines.append(
                f"- [{entry['time']}] {entry['agent']}: "
                f"{elapsed}, {entry['turns']} turns, "
                f"${entry['cost']:.4f}{suffix}"
            )
        return "\n".join(lines)

    def _parse_decision(self, raw_text: str, fallback_phase: str) -> Decision:
        """Parse the LLM's JSON decision, with fallback."""
        # Strip markdown fences if the model wrapped it
        text = raw_text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        try:
            data = json.loads(text)
            decision = Decision(data)
            # Validate
            if decision.next_agent not in self.PHASES and not decision.should_stop:
                return self._fallback_decision(fallback_phase)
            self.decisions.append(decision)
            return decision
        except (json.JSONDecodeError, KeyError):
            return self._fallback_decision(fallback_phase)

    def _fallback_decision(self, phase_completed: str) -> Decision:
        """Template-based fallback when LLM analysis fails."""
        next_phase = {
            "recon": "exploit",
            "exploit": "postex",
            "postex": "",
        }.get(phase_completed, "")

        if not next_phase:
            return Decision({
                "should_stop": True,
                "stop_reason": "All phases completed.",
                "reasoning": "Post-exploitation phase finished. Engagement cycle complete.",
                "confidence": 90,
            })

        # For exploit->postex, check if we have compromised hosts
        if next_phase == "postex" and not self.state.compromised_hosts:
            return Decision({
                "next_agent": "recon",
                "task": "The exploitation phase did not yield compromised hosts. "
                        "Conduct additional reconnaissance to find new attack vectors.",
                "reasoning": "Exploitation failed — need more recon to find alternative paths.",
                "confidence": 50,
                "alternatives": [
                    {"agent": "exploit", "description": "Retry exploitation with different techniques"},
                ],
            })

        # Auto-resolve OS-specific agents for postex phase
        if next_phase == "postex":
            next_phase = self._resolve_agent("postex")

        task_builders = {
            "exploit": self._build_default_exploit_task,
            "postex": self._build_default_postex_task,
            "linux_postex": self._build_default_postex_task,
            "windows_postex": self._build_default_postex_task,
        }
        task = task_builders.get(next_phase, lambda: "Continue the engagement.")()

        return Decision({
            "next_agent": next_phase,
            "task": task,
            "reasoning": f"Standard progression: {phase_completed} -> {next_phase} (OS: {self._detect_os()})",
            "confidence": 60,  # Low confidence to trigger human review on fallback
        })

    # --- Human-in-the-loop chain execution ---

    def run_chain(self, on_status=None, on_progress=None, resume: bool = False) -> str:
        """Execute the attack chain with LLM decision making and human-in-the-loop.

        Enhanced execution strategy:
        - Phase 1: Scope validation (deterministic)
        - Phase 2: Recon via TaskDecomposer (parallel subtasks)
        - Phase 3: Noise Filter (haiku) -> write findings to DB
        - Phase 4: Triage (sonnet) -> update TargetManager priorities
        - Phase 5: ExitEvaluator check
        - Phase 6: Per-target exploit via TaskDecomposer (parallel subtasks)
        - Phase 7+: LLM-decided sequential phases with exit evaluation
        - Human-in-the-loop for low-confidence decisions

        If resume=True and a checkpoint exists for the current target, skip
        already-completed phases and continue from where we left off.
        """
        results = {}
        phase_outputs = {}

        # ── Check for resume ──
        checkpoint = self._load_checkpoint() if resume else None
        if checkpoint:
            completed = checkpoint.get("completed_phases", [])
            results = checkpoint.get("phase_summaries", {})
            phase_outputs = dict(results)
            self.phase_log = checkpoint.get("phase_log", [])

            if on_status:
                on_status(
                    f"[orchestrator] Resuming from checkpoint — "
                    f"completed: {', '.join(completed)}"
                )
            if on_progress:
                on_progress({
                    "type": "phase", "agent": "orchestrator",
                    "text": f"RESUMING — completed phases: {', '.join(completed)}",
                })

        # ── Phase 1: Scope validation ──
        scope_enforcer = getattr(self.state, "scope_enforcer", None)
        if scope_enforcer and on_status:
            on_status("[orchestrator] === SCOPE VALIDATION ===")
            for target in self.state.targets:
                in_scope, reason = scope_enforcer.is_in_scope(target)
                status = "IN SCOPE" if in_scope else "OUT OF SCOPE"
                on_status(f"  {target}: {status} — {reason}")

        # ── Phase 2: Recon (skip if already completed) ──
        if "recon" not in results:
            if on_status:
                on_status("[orchestrator] === PHASE 1: RECONNAISSANCE (subtask decomposition) ===")
            if on_progress:
                on_progress({"type": "phase", "agent": "orchestrator",
                             "text": "=== PHASE 1: RECONNAISSANCE ==="})

            # Use task decomposer for parallel recon subtasks
            primary_target = self.state.target
            recon_subtasks = self.task_decomposer.decompose_recon(
                primary_target, self.state.scope, self.state.roe
            )

            if recon_subtasks:
                subtask_results = self.dispatch_subtasks(
                    recon_subtasks, on_status, on_progress, summarize=True
                )
                # Combine all subtask outputs into one recon summary
                recon_output = "\n\n".join(
                    f"### {name}\n{output}"
                    for name, output in subtask_results.items()
                    if not output.startswith("(skipped")
                )
            else:
                # Fallback to monolithic recon
                recon_output = self.run_recon(on_status=on_status, on_progress=on_progress)

            results["recon"] = recon_output
            phase_outputs["recon"] = recon_output
            self._save_checkpoint(results, "recon", recon_output, 0)
        else:
            recon_output = results["recon"]
            if on_status:
                on_status("[orchestrator] Recon already completed (resumed) — skipping")

        # ── Phase 2: Noise filtering + Triage (sonnet, combined) ──
        if "triage" not in results:
            if on_status:
                on_status("[orchestrator] === PHASE 2: FILTER + TRIAGE (sonnet) ===")

            # Run noise_filter and triage in parallel — both read-only on the same recon data
            filter_triage_tasks = [
                {"agent": "noise_filter", "task": f"Filter this recon output for signal vs noise:\n\n{recon_output[:8000]}"},
                {"agent": "triage", "task": f"Analyze and rank targets from this recon data:\n\n{recon_output[:8000]}"},
            ]
            ft_results = self.dispatch_parallel(
                filter_triage_tasks, on_status=on_status, on_progress=on_progress, summarize=False,
            )
            filtered_output = ft_results.get("noise_filter", recon_output)
            triage_output = ft_results.get("triage", "")
            results["noise_filter"] = filtered_output
            results["triage"] = triage_output

            # Parse triage rankings and update target manager
            self._apply_triage_rankings(triage_output, on_status)
            self._save_checkpoint(results, "triage", triage_output, 0)
        else:
            filtered_output = results.get("noise_filter", recon_output)

        # ── Phase 3: Parameter Analysis (haiku — attack surface mapping) ──
        if "param_analyzer" not in results:
            if on_status:
                on_status("[orchestrator] === PHASE 3: PARAMETER ANALYSIS (haiku) ===")
            if on_progress:
                on_progress({"type": "phase", "agent": "orchestrator",
                             "text": "=== PHASE 3: PARAMETER ANALYSIS ==="})

            # Feed the filtered recon output (signal, not noise) to the param analyzer.
            # Pre-filter to web-relevant content only — skip port scan noise, DNS records,
            # OSINT results that don't contain endpoint/parameter data.
            param_input = filtered_output if filtered_output else recon_output
            # Truncate aggressively — param analyzer doesn't need full scan output
            param_task = (
                f"Analyze the following recon output for {self.state.target}. "
                f"Extract all endpoints, URL parameters, form fields, and API patterns. "
                f"Map each to likely attack vectors. Output JSON attack plan only.\n\n"
                f"{param_input[:6000]}"
            )
            param_output = self.dispatch(
                "param_analyzer", param_task,
                on_status=on_status, on_progress=on_progress,
                max_turns=5, skip_rag=True,
            )
            results["param_analyzer"] = param_output
            phase_outputs["param_analyzer"] = param_output
            self._save_checkpoint(results, "param_analyzer", param_output, 0)
        else:
            param_output = results["param_analyzer"]
            if on_status:
                on_status("[orchestrator] Param analysis already completed (resumed) — skipping")

        # ── Generate/update attack plan from recon results ──
        all_recon = recon_output
        if results.get("param_analyzer"):
            all_recon += f"\n\n{results['param_analyzer'][:2000]}"
        if results.get("noise_filter"):
            all_recon += f"\n\n{results['noise_filter'][:2000]}"
        self.attack_plan.target = self.state.target
        self.attack_plan.generate(
            self.state,
            findings_summary=self.findings_db.summary_for_prompt(max_chars=1000),
            recon_output=all_recon[:4000],
            on_status=on_status,
        )
        if on_status and self.attack_plan.objective:
            on_status(f"[orchestrator] Attack plan: {self.attack_plan.objective}")

        # ── Phase 4: Exit evaluator check ──
        exit_eval = ExitEvaluator(self.findings_db, self.phase_log)
        exit_score = exit_eval.evaluate()

        if exit_score.should_exit:
            if on_status:
                on_status(f"[orchestrator] Exit evaluator: {exit_score.format_for_operator()}")
            if self.ask_operator:
                operator_input = self.ask_operator(
                    f"\n{exit_score.format_for_operator()}\n\n"
                    f"Type 'stop' to end, or 'continue' to override and keep going:"
                )
                if not operator_input or operator_input.strip().lower() in ("stop", "quit", "done"):
                    return self._finalize_report(results, on_status)
            elif self.autonomous:
                if on_status:
                    on_status("[orchestrator] Exit evaluator recommends stopping — auto-stopping")
                return self._finalize_report(results, on_status)

        # ── Phase 5: Exploit + CVEHunter via subtasks ──
        parallel_needed = []
        if "cvehunter" not in results:
            parallel_needed.append({"agent": "cvehunter", "task": self._build_default_cvehunter_task()})
        if "exploit" not in results:
            # Try subtask decomposition for exploit
            exploit_subtasks = self.task_decomposer.decompose_exploit(
                self.state.target, self.findings_db, self.state
            )
            if exploit_subtasks:
                if on_status:
                    on_status("[orchestrator] === PHASE 4: EXPLOIT (subtask decomposition) ===")
                # Run CVEHunter in parallel with exploit subtasks
                if "cvehunter" not in results:
                    # Add CVEHunter as a subtask too
                    cvehunter_subtask = SubTask(
                        name="cvehunter",
                        agent="cvehunter",
                        task=self._build_default_cvehunter_task(),
                        max_turns=SUBTASK_MAX_TURNS,
                        host=self.state.target,
                        priority=8,
                    )
                    exploit_subtasks.append(cvehunter_subtask)

                subtask_results = self.dispatch_subtasks(
                    exploit_subtasks, on_status, on_progress, summarize=True
                )
                for name, output in subtask_results.items():
                    if name == "cvehunter":
                        results["cvehunter"] = output
                    else:
                        results.setdefault("exploit", "")
                        results["exploit"] += f"\n\n### {name}\n{output}"
                phase_outputs.update(subtask_results)
                self._save_checkpoint(results, "exploit", results.get("exploit", ""), 0)
            else:
                # Fallback: monolithic dispatch
                parallel_needed.append({"agent": "exploit", "task": self._build_default_exploit_task()})

        if parallel_needed:
            agents_str = " + ".join(t["agent"].upper() for t in parallel_needed)
            if on_status:
                on_status(f"[orchestrator] === PHASE 4: {agents_str} ===")
            if on_progress:
                on_progress({"type": "phase", "agent": "orchestrator",
                             "text": f"=== PHASE 4: {agents_str} ==="})

            if len(parallel_needed) > 1:
                parallel_results = self.dispatch_parallel(
                    parallel_needed, on_status=on_status, on_progress=on_progress,
                )
            else:
                t = parallel_needed[0]
                parallel_results = {t["agent"]: self.dispatch(t["agent"], t["task"], on_status, on_progress)}

            results.update(parallel_results)
            phase_outputs.update(parallel_results)
            self._save_checkpoint(results, "exploit", results.get("exploit", ""), 0)

        # Build current context from exploit + cvehunter
        current_output = results.get("exploit", "")
        if results.get("cvehunter"):
            current_output += f"\n\n## CVE Hunter Findings\n{results['cvehunter']}"
        current_phase = "exploit"

        # ── Phase 6+: Batch micro-agent loop ──
        # Plan 4 micro-tasks at once, execute them without analysis between each.
        # Re-plan when: batch exhausted, milestone hit, or agent stuck-killed.
        # This is 3-4x faster than analyzing between every dispatch.
        max_micro_dispatches = 15
        cumulative_output = current_output
        task_queue: list[Decision] = []  # Pre-planned tasks
        iteration = 0

        while iteration < max_micro_dispatches:
            # Autonomous stop gate — mirrors the interactive agent per mode.
            # CTF: hard $ ceiling (bounded labs). LE/RT: no $ ceiling — halt at high
            # Claude session/context usage (max across dispatched agents) instead.
            _eng_cost = getattr(self.state, "total_cost", 0.0)
            _is_ctf = getattr(self.state, "engagement_mode", "ctf") == "ctf"
            if _is_ctf and _eng_cost >= MAX_ENGAGEMENT_COST:
                if on_status:
                    on_status(
                        f"[orchestrator] Cost ceiling ${MAX_ENGAGEMENT_COST:.2f} reached "
                        f"(${_eng_cost:.2f} spent) — halting autonomous dispatch."
                    )
                break
            if not _is_ctf:
                _ctx_frac = max(
                    (getattr(a, "_last_ctx_frac", 0.0) for a in self._agents.values()),
                    default=0.0,
                )
                if _ctx_frac >= SESSION_USAGE_WARN_PCT:
                    if on_status:
                        on_status(
                            f"[orchestrator] Claude session usage {_ctx_frac * 100:.0f}% reached "
                            f"(${_eng_cost:.2f} spent) — halting autonomous dispatch. "
                            f"Resume with /auto resume to continue."
                        )
                    break

            # Between batches: update attack plan, then exit check, then re-plan
            if not task_queue:
                # Update the strategic plan with results from last batch
                if iteration > 0:
                    self.attack_plan.update_after_batch(
                        cumulative_output[-3000:], self.state, on_status
                    )
                    if on_status and self.attack_plan.objective:
                        active_paths = [p["name"] for p in self.attack_plan.paths
                                        if p.get("status") == "active"]
                        on_status(
                            f"[orchestrator] Plan: {self.attack_plan.objective[:80]} | "
                            f"Active paths: {', '.join(active_paths[:3]) or 'none'}"
                        )

                    # Auto-trigger synthesis: proactive on primitive density, reactive on stagnation
                    active_paths = [p for p in self.attack_plan.paths
                                    if p.get("status") == "active"]
                    recent_stuck = sum(1 for p in self.phase_log[-4:]
                                       if p.get("stuck_killed"))
                    # Also detect category stagnation: same agent dispatched 3+ times in last 4
                    recent_agents = [p.get("agent", "") for p in self.phase_log[-4:]]
                    category_stagnation = (
                        len(recent_agents) >= 3 and
                        any(recent_agents.count(a) >= 3 for a in set(recent_agents))
                    )
                    # Proactive trigger: enough distinct primitives from different principals
                    # to make combinatorial analysis worthwhile (the whole point of synthesis)
                    capabilities = getattr(self.state, "capabilities", [])
                    trust_rels = getattr(self.state, "trust_relationships", [])
                    primitive_principals = set()
                    for cap in capabilities:
                        if isinstance(cap, dict):
                            primitive_principals.add(cap.get("principal", cap.get("account", "")))
                    primitive_density = len(primitive_principals) >= 3 or (
                        len(capabilities) >= 3 and len(trust_rels) >= 1
                    )

                    has_active_synth = any(
                        p.get("source") == "synthesis" and p.get("status") == "active"
                        for p in self.attack_plan.paths
                    )

                    # Trigger synthesis if (and no active synthesis paths exist):
                    # REACTIVE (iteration >= 1):
                    #   - All paths blocked, OR
                    #   - 2+ stuck-kills recently, OR
                    #   - Same agent dispatched 3/4 last times (grinding)
                    # PROACTIVE (iteration >= 1):
                    #   - 3+ primitives from distinct principals (combinatorial chains likely exist)
                    should_synth = (
                        not has_active_synth
                        and iteration >= 1
                        and (
                            not active_paths
                            or recent_stuck >= 2
                            or category_stagnation
                            or primitive_density
                        )
                    )
                    if should_synth:
                        trigger_reason = (
                            "all paths blocked" if not active_paths
                            else f"{recent_stuck} stuck-kills" if recent_stuck >= 2
                            else "category stagnation detected" if category_stagnation
                            else f"primitive density ({len(primitive_principals)} principals, {len(capabilities)} capabilities)"
                        )
                        if on_status:
                            on_status(f"[orchestrator] Synthesis triggered ({trigger_reason})...")
                        # Build RICH context for synthesis — not generic summary
                        synth_context = (
                            f"{self.state.synthesis_context()}\n\n"
                            f"## CURRENT ATTACK PLAN\n{self.attack_plan.for_prompt()}\n\n"
                            f"## RECENT EXECUTION OUTPUT\n{cumulative_output[-3000:]}"
                        )
                        synth_output = self.dispatch(
                            "synthesis", synth_context,
                            on_status=on_status, on_progress=on_progress,
                            skip_rag=False,  # Synthesis benefits from RAG
                        )
                        # Apply synthesis output authoritatively to the attack plan
                        plan_rewritten = self.attack_plan.apply_synthesis(
                            synth_output, on_status=on_status
                        )
                        if plan_rewritten:
                            # HIGH chain found — kill the current task queue and
                            # force re-planning from the synthesis chain
                            task_queue.clear()
                            # Generate tasks directly from synthesis commands
                            synth_tasks = self.attack_plan.get_synthesis_commands()
                            if synth_tasks:
                                for st in synth_tasks:
                                    d = Decision({
                                        "next_agent": st["agent"],
                                        "task": st["task"],
                                        "reasoning": "Synthesis-directed (HIGH viability chain)",
                                        "confidence": 90,
                                    })
                                    if d.next_agent in self._AGENT_CLASSES:
                                        task_queue.append(d)
                            if on_progress:
                                on_progress({
                                    "type": "phase", "agent": "orchestrator",
                                    "text": f"SYNTHESIS OVERRIDE: plan rewritten, {len(task_queue)} tasks from chain",
                                })
                        else:
                            # No HIGH chain — synthesis is advisory, append to context
                            cumulative_output += f"\n\n## SYNTHESIS ANALYSIS\n{synth_output[:3000]}"
                            if on_progress:
                                on_progress({
                                    "type": "phase", "agent": "orchestrator",
                                    "text": f"Synthesis complete — advisory (no HIGH chains), re-planning",
                                })

                exit_eval = ExitEvaluator(self.findings_db, self.phase_log)
                exit_score = exit_eval.evaluate()

                if exit_score.should_exit:
                    if on_status:
                        on_status(
                            f"[orchestrator] Exit evaluator recommends stopping "
                            f"(score: {exit_score.score:.2f})"
                        )
                    if self.ask_operator:
                        operator_input = self.ask_operator(
                            f"\n{exit_score.format_for_operator()}\n\n"
                            f"Type 'stop' to end, or 'continue' to override:"
                        )
                        if not operator_input or operator_input.strip().lower() in ("stop", "quit", "done"):
                            break
                    elif self.autonomous:
                        break

                # Plan next batch of 4 tasks
                if on_status:
                    on_status(f"[orchestrator] Planning next batch (dispatch {iteration+1}/{max_micro_dispatches})...")
                task_queue = self._plan_batch(
                    current_phase, cumulative_output[-4000:], on_status, batch_size=4
                )
                if on_progress:
                    on_progress({
                        "type": "phase", "agent": "orchestrator",
                        "text": f"Batch planned: {len(task_queue)} micro-tasks",
                    })

            # Pop next task from queue — batch tasks are pre-approved
            decision = task_queue.pop(0)

            if decision.should_stop:
                task_queue.clear()
                break

            # --- Exploitation commitment gate (hard enforcement) ---
            # If the planner scheduled recon but unproven exploitable findings
            # exist, override to exploitation. The prompt asked nicely; this
            # enforces it when the planner ignores the directive.
            agent_name = decision.next_agent
            _recon_agents = ("recon", "param_analyzer", "codereview", "cvehunter")
            if agent_name in _recon_agents:
                _unproven = self.findings_db.unproven_findings(min_severity="medium")
                if _unproven:
                    top = _unproven[0]
                    if on_status:
                        on_status(
                            f"[orchestrator] DEPTH GATE: overriding {agent_name} → exploit "
                            f"(unproven: {top['title']} [{top['severity']}])"
                        )
                    agent_name = "exploit"
                    decision.next_agent = "exploit"
                    decision.task = (
                        f"EXPLOITATION COMMITMENT: Prove or disprove this finding — "
                        f"[{top['severity'].upper()}] {top['title']} on {top['host']}:{top['port']}. "
                        f"Description: {(top.get('description') or '')[:300]}. "
                        f"Complete the attack chain to proof (capture data, get a session, "
                        f"demonstrate real impact). If it fails, explain WHY it's not exploitable."
                    )
            remaining_in_batch = len(task_queue)
            if on_status:
                on_status(
                    f"[orchestrator] === MICRO {iteration+1}/{max_micro_dispatches}: "
                    f"{agent_name.upper()} ({remaining_in_batch} queued) ==="
                )
            if on_progress:
                on_progress({
                    "type": "phase", "agent": "orchestrator",
                    "text": f"Micro {iteration+1}: {agent_name} — {decision.task[:100]}",
                })

            current_output = self.dispatch(
                agent_name, decision.task, on_status, on_progress,
                skip_rag=True,  # Micro-tasks are specific — RAG adds no value
            )

            # Accumulate output for context across micro-dispatches
            cumulative_output += f"\n\n### Micro {iteration+1} ({agent_name})\n{current_output[:1500]}"
            if len(cumulative_output) > 8000:
                cumulative_output = cumulative_output[-6000:]

            results[f"{agent_name}_{iteration}"] = current_output
            phase_outputs[agent_name] = current_output
            current_phase = agent_name
            iteration += 1

            # Check if this was a synthesis validation task that FAILED
            if "[SYNTHESIS VALIDATION:" in decision.task:
                validation_failed_keywords = [
                    "validation fail", "assumption broke", "does not work",
                    "access denied", "not found", "error", "failed",
                    "cannot", "unable", "blocked",
                ]
                output_lower = current_output.lower()
                validation_failed = any(kw in output_lower for kw in validation_failed_keywords)

                if validation_failed:
                    if on_status:
                        on_status("[orchestrator] Synthesis validation FAILED — downgrading chain, re-triggering synthesis")
                    # Downgrade the synthesis path
                    for path in self.attack_plan.paths:
                        if (path.get("source") == "synthesis" and
                                path.get("status") == "active"):
                            path["status"] = "blocked"
                            path["blocked_reason"] = f"Validation failed: {current_output[:200]}"
                    self.attack_plan.add_lesson(
                        f"[synthesis-feedback] Chain validation failed: {current_output[:300]}"
                    )
                    self.attack_plan.save()
                    # Clear remaining synthesis tasks — they depend on validation
                    task_queue.clear()
                    # Force re-plan (synthesis will trigger again next iteration
                    # because active paths are now empty and we have the failure
                    # as a new constraint in lessons)
                    continue

            # Check if milestone was hit or agent was stuck-killed → force re-plan
            agent_obj = self._get_agent(agent_name)
            was_stuck = bool(agent_obj and agent_obj.results and agent_obj.results[-1].get("stuck_killed"))
            # Milestone keywords that indicate real progress (not just enumeration mentions).
            # "domain admin" excluded — too many false positives from group name listings.
            # Use action phrases instead.
            milestone_keywords = ["rce confirm", "shell obtained", "uid=0", "flag{",
                                  "credentials found", "password crack", "privilege escalat",
                                  "domain admin achieved", "domain admin access", "da access"]
            _output_lower = current_output.lower()
            hit_milestone = any(kw in _output_lower for kw in milestone_keywords)
            # Also check for CTF flag pattern (32-char hex)
            if not hit_milestone:
                import re as _re
                hit_milestone = bool(_re.search(r'\b[a-f0-9]{32}\b', _output_lower)
                                     and ("root.txt" in _output_lower or "user.txt" in _output_lower))

            if was_stuck or hit_milestone:
                # Clear remaining batch — force re-planning with new context
                if was_stuck and on_status:
                    on_status(f"[orchestrator] Agent stuck-killed — re-planning batch")
                if hit_milestone and on_status:
                    on_status(f"[orchestrator] Milestone detected — re-planning batch")
                task_queue.clear()

            # Checkpoint after each micro-dispatch
            self._save_checkpoint(results, current_phase, current_output, iteration)

        return self._finalize_report(results, on_status)

    def _finalize_report(self, results: dict, on_status=None) -> str:
        """Generate final report, save it, and clean up."""
        # Include findings DB export in the report
        summary = self._generate_summary(results)

        # Append structured findings from DB
        db_report = self.findings_db.export_markdown()
        if db_report and db_report != "No findings recorded.":
            summary += f"\n\n---\n\n{db_report}"

        report_path = (
            FINDINGS_DIR
            / f"engagement_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )
        report_path.write_text(summary)
        self._clear_checkpoint()

        if on_status:
            on_status(f"[orchestrator] Report saved: {report_path}")

        return summary

    def _apply_triage_rankings(self, triage_output: str, on_status=None):
        """Parse triage agent JSON output and update target manager priorities."""
        try:
            # Strip markdown fences
            text = triage_output.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
            text = text.strip()

            rankings = json.loads(text)
            if not isinstance(rankings, list):
                return

            tm = getattr(self.state, "target_manager", None)
            if not tm:
                return

            for entry in rankings:
                host = entry.get("host", "")
                priority = entry.get("priority", 5)
                reason = entry.get("reasoning", "")[:100]
                if host:
                    # Add host if not already tracked
                    tm.add_host(host, source="triage", priority=priority)
                    tm.update_priority(host, priority, reason)
                    tm.update_status(host, "triaged")
                    if on_status:
                        on_status(f"  [triage] {host}: priority {priority} — {reason[:60]}")

        except (json.JSONDecodeError, KeyError, TypeError):
            if on_status:
                on_status("[orchestrator] Could not parse triage rankings (non-JSON output)")

    def _parse_operator_input(self, text: str) -> Decision | None:
        """Parse operator input like 'recon: scan subnet 10.10.20.0/24'."""
        for agent_name in self.PHASES:
            prefix = f"{agent_name}:"
            if text.lower().startswith(prefix):
                task = text[len(prefix):].strip()
                if task:
                    return Decision({
                        "next_agent": agent_name,
                        "task": task,
                        "reasoning": "Operator override.",
                        "confidence": 100,
                    })
        return None

    # --- Default task builders (templates) ---

    def _build_default_recon_task(self) -> str:
        parts = [
            f"Conduct full reconnaissance against the target: {self.state.target}",
            f"Scope: {self.state.scope or 'As defined by target'}",
            f"ROE: {self.state.roe or 'Standard rules'}",
            "",
            "Start with passive OSINT and progress to active scanning.",
            "Enumerate:",
            "  - Subdomains and DNS records",
            "  - Email addresses and naming conventions",
            "  - Exposed services and technology stack",
            "  - Potential credentials from breach data",
            "  - Active Directory infrastructure if applicable",
            "",
            "Save all results to the evidence directory.",
            "Summarize findings with clear recommendations for exploitation.",
        ]
        return "\n".join(parts)

    def _build_default_exploit_task(self) -> str:
        parts = [
            f"Exploit vulnerabilities and gain initial access to: {self.state.target}",
            f"Scope: {self.state.scope or 'As defined by target'}",
            f"ROE: {self.state.roe or 'Standard rules'}",
        ]
        if self.recon.results:
            # Prefer summary over raw response for token efficiency
            recon_data = self.recon.results[-1].get("summary") or self.recon.results[-1]["response"][:3000]
            parts.append(f"\n## Recon Findings\n{recon_data}")

        # Inject parameter analysis attack plan if available
        if self.param_analyzer.results:
            param_data = (
                self.param_analyzer.results[-1].get("summary")
                or self.param_analyzer.results[-1]["response"][:4000]
            )
            parts.append(f"\n## Attack Surface Analysis (from parameter analyzer)\n{param_data}")
            parts.append(
                "\n**IMPORTANT:** Follow the attack plan above. It maps specific parameters "
                "to specific attack vectors with test commands. Work through the plan in "
                "priority order rather than guessing what to test."
            )

        if self.state.credentials:
            parts.append("\n## Available Credentials")
            for c in self.state.credentials:
                parts.append(f"  - {c['username']} : {c['secret']} [{c['type']}]")
        if self.state.discovered_hosts:
            parts.append(
                f"\n## Discovered Hosts: {', '.join(self.state.discovered_hosts[:20])}"
            )
        parts.append("\nPrioritize:")
        parts.append("  1. Quick wins identified by parameter analyzer")
        parts.append("  2. Credential reuse and spraying")
        parts.append("  3. Known vulnerability exploitation")
        parts.append("  4. Web application attacks per attack plan")
        parts.append("  5. Phishing with payload delivery (if in scope)")
        parts.append("\nRecord each compromised host and credential.")
        return "\n".join(parts)

    def _build_default_postex_task(self) -> str:
        parts = [
            f"Perform post-exploitation on compromised assets for: {self.state.target}",
            f"ROE: {self.state.roe or 'Standard rules'}",
        ]
        if self.state.compromised_hosts:
            parts.append("\n## Compromised Hosts")
            for h in self.state.compromised_hosts:
                parts.append(
                    f"  - {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]"
                )
        if self.state.credentials:
            parts.append("\n## Available Credentials")
            for c in self.state.credentials:
                parts.append(f"  - {c['username']} : {c['secret']} [{c['type']}]")
        if self.exploit.results:
            exploit_data = self.exploit.results[-1].get("summary") or self.exploit.results[-1]["response"][:3000]
            parts.append(f"\n## Exploitation Results\n{exploit_data}")
        parts.append("\nObjectives:")
        parts.append("  1. Situational awareness on each compromised host")
        parts.append("  2. Privilege escalation to local admin / SYSTEM")
        parts.append("  3. Credential harvesting from memory and stored creds")
        parts.append("  4. Lateral movement to additional hosts")
        parts.append("  5. Domain dominance if AD environment")
        parts.append("\nRecord every new credential and compromised host.")
        return "\n".join(parts)

    def _build_default_codereview_task(self) -> str:
        parts = [
            f"Review source code discovered during the engagement against: {self.state.target}",
            f"Scope: {self.state.scope or 'As defined by target'}",
            f"ROE: {self.state.roe or 'Standard rules'}",
        ]
        if self.state.compromised_hosts:
            parts.append("\n## Compromised Hosts (check for source code on these)")
            for h in self.state.compromised_hosts:
                parts.append(
                    f"  - {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]"
                )
        if self.recon.results:
            recon_data = self.recon.results[-1].get("summary") or self.recon.results[-1]["response"][:2000]
            parts.append(f"\n## Recon Findings (look for code repos, web apps)\n{recon_data}")
        parts.append("\nPrioritize:")
        parts.append("  1. Quick wins: .git dirs, .env files, config files, private keys")
        parts.append("  2. Hardcoded credentials and secrets in source code")
        parts.append("  3. Injection vulnerabilities (SQLi, command injection, SSTI)")
        parts.append("  4. Authentication and authorization flaws")
        parts.append("  5. Insecure deserialization and XXE")
        parts.append("\nSave findings to the evidence directory as codereview_findings.md.")
        parts.append("Flag any discovered credentials for the engagement state.")
        return "\n".join(parts)

    def _build_default_cvehunter_task(self) -> str:
        parts = [
            f"Scan for known CVEs affecting services discovered on: {self.state.target}",
            f"Scope: {self.state.scope or 'As defined by target'}",
            f"ROE: {self.state.roe or 'Standard rules'}",
        ]
        if self.recon.results:
            recon_data = self.recon.results[-1].get("summary") or self.recon.results[-1]["response"][:3000]
            parts.append(f"\n## Recon Findings (services and versions to check)\n{recon_data}")
        if self.state.discovered_hosts:
            parts.append(
                f"\n## Discovered Hosts: {', '.join(self.state.discovered_hosts[:20])}"
            )
        if self.state.compromised_hosts:
            parts.append("\n## Already Compromised (lower priority for CVE scanning)")
            for h in self.state.compromised_hosts:
                parts.append(
                    f"  - {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]"
                )
        parts.append("\nWorkflow:")
        parts.append("  1. Update searchsploit DB if internet is available")
        parts.append("  2. Run searchsploit against each discovered service+version")
        parts.append("  3. Run nmap vuln scripts against key ports")
        parts.append("  4. Check the high-value CVE list against target OS/services")
        parts.append("  5. For each confirmed CVE, search for and download PoCs")
        parts.append("  6. Read and adapt PoCs for this engagement")
        parts.append("\nSave findings to evidence/cve_findings.md and PoCs to evidence/pocs/.")
        return "\n".join(parts)

    # --- Reporting ---

    def _generate_summary(self, results: dict) -> str:
        lines = [
            "# Engagement Summary",
            f"**Target:** {self.state.target}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Scope:** {self.state.scope or 'N/A'}",
            "",
        ]

        if self.state.compromised_hosts:
            lines.append(f"## Compromised Hosts ({len(self.state.compromised_hosts)})")
            for h in self.state.compromised_hosts:
                lines.append(f"- {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]")
            lines.append("")

        if self.state.credentials:
            lines.append(f"## Harvested Credentials ({len(self.state.credentials)})")
            for c in self.state.credentials:
                lines.append(
                    f"- {c['username']} [{c['type']}] from {c.get('source', 'unknown')}"
                )
            lines.append("")

        # Orchestrator decisions
        if self.decisions:
            lines.append("## Orchestrator Decisions")
            for i, d in enumerate(self.decisions, 1):
                if d.should_stop:
                    lines.append(f"{i}. **STOP** — {d.stop_reason} (confidence: {d.confidence}%)")
                else:
                    lines.append(
                        f"{i}. **{d.next_agent}** — {d.reasoning[:120]} "
                        f"(confidence: {d.confidence}%)"
                    )
            lines.append("")

        for phase in self.PHASES:
            if phase in results:
                lines.append(f"## {phase.upper()} Phase")
                content = results[phase]
                if len(content) > 2000:
                    content = (
                        content[:2000]
                        + "\n\n... (truncated — see evidence directory for full output)"
                    )
                lines.append(content)
                lines.append("")

        # OPSEC summary
        all_opsec = []
        for agent in self._agents.values():
            all_opsec.extend(agent.opsec_log)
        if all_opsec:
            lines.append("## OPSEC Summary")
            counts = Counter(e["level"] for e in all_opsec)
            lines.append(f"Total commands scored: {len(all_opsec)}")
            for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                if counts.get(level):
                    lines.append(f"- {level}: {counts[level]}")
            risky = [e for e in all_opsec if e["score"] >= 3]
            if risky:
                lines.append("\n**High-risk commands executed:**")
                for e in risky:
                    lines.append(f"- [{e['level']}] [{e['agent']}] {e['command']}")
            lines.append("")

        total_cost = sum(a._last_cost for a in self._agents.values())
        total_turns = sum(a._last_turns for a in self._agents.values())
        total_seconds = sum(e.get("elapsed_seconds", 0) for e in self.phase_log)
        total_time = f"{int(total_seconds // 60):02d}:{int(total_seconds % 60):02d}"
        lines.append(f"## Timing: {total_time} total | ${total_cost:.4f} | {total_turns} turns")
        if self.phase_log:
            lines.append("\n**Per-phase timing:**")
            for entry in self.phase_log:
                elapsed = entry.get("elapsed", "??:??")
                lines.append(f"- {entry['agent']}: {elapsed} ({entry['turns']} turns, ${entry['cost']:.4f})")

        return "\n".join(lines)

    # --- Bounty Monitor Integration ---

    def setup_bounty_monitor(self, on_status=None, on_new_engagement=None):
        """Initialize the bounty platform monitor.

        Args:
            on_status: Status message callback for UI updates.
            on_new_engagement: Callback(engagement, targets) when a new LE engagement
                is auto-created from a discovered program. The caller (main.py) should
                wire this to switch context or queue recon.
        """
        from bounty_monitor import BountyMonitor, BountyFilter
        from config import (BOUNTY_POLL_INTERVAL, BOUNTY_MIN_PAYOUT,
                            BOUNTY_PAID_ONLY, BOUNTY_PLATFORMS,
                            H1_API_USERNAME, H1_API_TOKEN, DATA_DIR)

        bounty_filter = BountyFilter(
            min_bounty=BOUNTY_MIN_PAYOUT,
            paid_only=BOUNTY_PAID_ONLY,
            platforms=BOUNTY_PLATFORMS,
        )

        self._bounty_on_status = on_status
        self._bounty_on_new_engagement = on_new_engagement

        self.bounty_monitor = BountyMonitor(
            data_dir=DATA_DIR / "bounty_monitor",
            on_new_program=self._on_new_bounty_program,
            on_scope_change=self._on_bounty_scope_change,
            on_status=on_status,
            bounty_filter=bounty_filter,
            h1_username=H1_API_USERNAME,
            h1_token=H1_API_TOKEN,
        )
        self.bounty_monitor._interval = BOUNTY_POLL_INTERVAL
        self.bounty_monitor.load_filter()
        return self.bounty_monitor

    def _on_new_bounty_program(self, program):
        """Callback: new bug bounty program detected.

        Creates an LE engagement for the program's web targets and notifies
        the caller to dispatch recon.
        """
        targets = program.web_targets or program.all_targets
        if not targets:
            if self._bounty_on_status:
                self._bounty_on_status(
                    f"[bounty] New program {program.name} has no scannable targets — skipping"
                )
            return

        if self._bounty_on_status:
            self._bounty_on_status(
                f"[bounty] NEW PROGRAM: {program.name} ({program.platform}) — "
                f"{len(targets)} targets, bounty up to ${program.bounty_max:.0f}"
            )

        if self._bounty_on_new_engagement:
            self._bounty_on_new_engagement(program, targets)

    def _on_bounty_scope_change(self, program, new_scopes):
        """Callback: existing program's scope expanded with new assets."""
        from bounty_monitor import ScopeAsset
        new_targets = []
        for s in new_scopes:
            asset = ScopeAsset(**s) if isinstance(s, dict) else s
            t = asset.recon_target()
            if t:
                new_targets.append(t)

        if not new_targets:
            return

        if self._bounty_on_status:
            self._bounty_on_status(
                f"[bounty] SCOPE EXPANSION: {program.name} — "
                f"+{len(new_targets)} new targets: {', '.join(new_targets[:5])}"
            )

        if self._bounty_on_new_engagement:
            self._bounty_on_new_engagement(program, new_targets)

    def status(self) -> str:
        lines = ["## Orchestrator Status"]
        lines.append(f"Target: {self.state.target or 'Not set'}")
        lines.append(f"Mode: {'AUTONOMOUS' if self.autonomous else 'Interactive'}")
        lines.append(f"Confidence threshold: {self.confidence_threshold}%")
        lines.append("")

        for name, agent in self._agents.items():
            task_count = len(agent.results)
            opsec_count = len(agent.opsec_log)
            cost = sum(r["cost"] for r in agent.results)
            status_str = (
                "idle" if not agent.results else f"{task_count} tasks, ${cost:.4f}"
            )
            lines.append(f"- **{name}**: {status_str} ({opsec_count} commands scored)")

        if self.decisions:
            lines.append(f"\nDecisions made: {len(self.decisions)}")
            last = self.decisions[-1]
            lines.append(
                f"Last decision: {last.next_agent} (confidence: {last.confidence}%)"
            )

        lines.append(f"\nPhases completed: {len(self.phase_log)}")
        lines.append(f"Compromised hosts: {len(self.state.compromised_hosts)}")
        lines.append(f"Credentials: {len(self.state.credentials)}")

        # Attack plan summary
        if self.attack_plan.objective:
            lines.append(f"\n## Attack Plan")
            lines.append(f"Objective: {self.attack_plan.objective}")
            for p in self.attack_plan.paths[:5]:
                status = p.get("status", "active")
                icon = "→" if status == "active" else "✗"
                lines.append(f"  {icon} {p.get('name', '?')} [{status}]")

        # Cost-of-pass efficiency metrics
        if self.cost_tracker.total_cost > 0:
            lines.append(f"\n{self.cost_tracker.summary()}")

        # Bounty monitor
        if self.bounty_monitor:
            bm = self.bounty_monitor
            running = "ACTIVE" if bm.is_running() else "STOPPED"
            lines.append(f"\n## Bounty Monitor: {running}")
            lines.append(
                f"Programs tracked: {bm.program_count} | "
                f"New: {bm._new_program_count} | "
                f"Scope changes: {bm._scope_change_count} | "
                f"Interval: {bm._interval}s"
            )

        return "\n".join(lines)
