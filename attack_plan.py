"""Attack Plan — persistent strategic goal tree for the orchestrator.

Maintains a structured attack plan across micro-dispatches and sessions:
- Ultimate objective (DA, root, flag)
- Ranked attack paths with status (active/blocked/exhausted)
- Known blockers that must be fixed before retrying paths
- High-value targets that should receive priority focus
- Lessons learned (what failed and why)

The batch planner consults this plan instead of planning from scratch.
Updated by LLM (haiku) after each batch completes.
"""

import json
import subprocess

import claude_client
from datetime import datetime
from pathlib import Path

from config import MODEL_FAST, ENGAGEMENTS_DIR


class AttackPlan:
    """Persistent attack plan that guides the orchestrator's decision-making."""

    def __init__(self, target: str = ""):
        self.target = target
        self.objective = ""          # "Compromise toby.brynleigh (Domain Admin) → root flag"
        self.paths: list[dict] = []  # Ranked attack paths
        self.blockers: list[dict] = []  # Known blockers to fix
        self.priority_targets: list[dict] = []  # High-value targets
        self.lessons: list[str] = []  # What failed and why
        self.last_updated = ""
        # Per-engagement plan path override (set by orchestrator)
        self._plan_path_override: Path | None = None

    def _plan_path(self) -> Path:
        """Path to persisted plan file. Uses per-engagement path if set."""
        if self._plan_path_override:
            return self._plan_path_override
        if self.target:
            safe = self.target.replace(".", "_").replace("/", "_").replace(":", "_")
            return ENGAGEMENTS_DIR / f"_plan_{safe}.json"
        return ENGAGEMENTS_DIR / "_plan_default.json"

    def save(self) -> None:
        """Persist the plan to disk."""
        data = {
            "target": self.target,
            "objective": self.objective,
            "paths": self.paths,
            "blockers": self.blockers,
            "priority_targets": self.priority_targets,
            "lessons": self.lessons[-20:],  # Cap lessons
            "last_updated": datetime.now().isoformat(),
        }
        try:
            self._plan_path().write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def load(self) -> bool:
        """Load plan from disk. Returns True if loaded."""
        path = self._plan_path()
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            self.target = data.get("target", self.target)
            self.objective = data.get("objective", "")
            self.paths = data.get("paths", [])
            self.blockers = data.get("blockers", [])
            self.priority_targets = data.get("priority_targets", [])
            self.lessons = data.get("lessons", [])
            self.last_updated = data.get("last_updated", "")
            return True
        except Exception:
            return False

    def add_lesson(self, lesson: str) -> None:
        """Record what failed and why."""
        if lesson and lesson not in self.lessons:
            self.lessons.append(lesson)

    def block_path(self, path_name: str, reason: str) -> None:
        """Mark a path as blocked with reason."""
        for p in self.paths:
            if p.get("name", "").lower() == path_name.lower():
                p["status"] = "blocked"
                p["blocked_reason"] = reason
                return

    def for_prompt(self) -> str:
        """Format the plan for injection into the batch planner prompt."""
        if not self.objective and not self.paths:
            return ""

        lines = ["## ATTACK PLAN (strategic context — plan your tasks to serve this)"]

        if self.objective:
            lines.append(f"**Objective:** {self.objective}")

        if self.priority_targets:
            targets = "; ".join(
                f"{t['name']} ({t.get('reason', '')})"
                for t in self.priority_targets[:3]
            )
            lines.append(f"**Priority targets:** {targets}")

        if self.paths:
            lines.append("\n**Attack paths (ranked):**")
            for i, p in enumerate(self.paths[:5], 1):
                status = p.get("status", "active")
                name = p.get("name", "?")
                steps = p.get("steps", "")
                source = p.get("source", "")
                if status == "blocked":
                    reason = p.get("blocked_reason", "")
                    lines.append(f"  {i}. ~~{name}~~ [BLOCKED: {reason}] — do NOT retry")
                elif status in ("exhausted", "superseded"):
                    reason = p.get("blocked_reason", "")
                    lines.append(f"  {i}. ~~{name}~~ [{status.upper()}] — do NOT retry. {reason}")
                elif source == "synthesis":
                    # Synthesis chains are visually dominant
                    lines.append(f"  {i}. >>> **{name}** [ACTIVE — SYNTHESIS CHAIN] — {steps}")
                    next_step = p.get("next_step", "")
                    if next_step:
                        lines.append(f"     >>> EXECUTE: {next_step}")
                    cmds = p.get("commands", [])
                    if cmds:
                        lines.append(f"     >>> Full sequence: {' → '.join(cmds[:5])}")
                else:
                    next_step = p.get("next_step", "")
                    lines.append(f"  {i}. **{name}** [{status}] — {steps}")
                    if next_step:
                        lines.append(f"     → Next: {next_step}")

        if self.blockers:
            lines.append("\n**Fix these BEFORE retrying blocked paths:**")
            for b in self.blockers[:5]:
                name = b.get("name", "?")
                fix = b.get("fix", "?")
                fixed = b.get("fixed", False)
                if not fixed:
                    lines.append(f"  - {name}: {fix}")

        if self.lessons:
            lines.append(f"\n**Lessons (do NOT repeat):** {'; '.join(self.lessons[-5:])}")

        return "\n".join(lines)

    def generate(self, engagement_state, findings_summary: str = "",
                 recon_output: str = "", on_status=None) -> None:
        """Generate or update the attack plan using LLM analysis.

        Called after recon completes and after each batch of micro-dispatches.
        """
        if on_status:
            on_status("[orchestrator] Generating/updating attack plan...")

        # Build context for the planner
        state_parts = []
        if engagement_state.target:
            state_parts.append(f"Target: {engagement_state.target}")
        if engagement_state.credentials:
            creds = "; ".join(
                f"{c['username']}:{c['secret']}[{c['type']}]"
                for c in engagement_state.credentials[:8]
            )
            state_parts.append(f"Credentials: {creds}")
        if engagement_state.compromised_hosts:
            hosts = "; ".join(
                f"{h['hostname']}[{h['access_level']}]"
                for h in engagement_state.compromised_hosts[:5]
            )
            state_parts.append(f"Compromised: {hosts}")
        if engagement_state.notes:
            state_parts.append(f"Notes: {'; '.join(engagement_state.notes[-10:])}")
        if engagement_state.defenses:
            state_parts.append(f"Defenses: {engagement_state.defenses}")

        state_str = "\n".join(state_parts)

        # Include existing plan for update
        existing = ""
        if self.objective:
            existing = f"\n\nCurrent plan:\n{self.for_prompt()}"

        prompt = f"""You are a red team strategist. Analyze the engagement state and create/update
a structured attack plan. This plan guides ALL subsequent micro-task dispatches.

## Engagement State
{state_str}

{f"## Recon/Exploit Output (recent){chr(10)}{recon_output[:3000]}" if recon_output else ""}
{f"## Findings{chr(10)}{findings_summary[:1500]}" if findings_summary else ""}
{existing}

Respond with ONLY valid JSON (no markdown, no fences):
{{
    "objective": "The ultimate goal — be specific (e.g., 'Compromise toby.brynleigh (Domain Admin) to get root flag on DC01')",
    "priority_targets": [
        {{"name": "username or host", "reason": "why this target matters"}}
    ],
    "paths": [
        {{
            "name": "Short path name (e.g., 'NTLM relay to LDAPS')",
            "status": "active|blocked|exhausted",
            "steps": "Brief chain: step1 → step2 → step3",
            "next_step": "The specific next action to take on this path",
            "blocked_reason": "If blocked, why (e.g., 'SMB signing enforced')"
        }}
    ],
    "blockers": [
        {{
            "name": "What's blocking progress",
            "fix": "Specific fix command or action",
            "fixed": false
        }}
    ],
    "lessons": ["What failed and why — one line each, max 5 new lessons"]
}}

Rules:
- Rank paths by likelihood of success (most promising first)
- Mark paths as blocked if a known defense prevents them — don't leave them active
- The batch planner will generate tasks from the TOP active path's next_step
- Include at most 5 paths, 3 priority targets, 5 blockers
- If a path has been tried 3+ times without progress, mark it exhausted
- Be concrete: "run sudo ntpdate DC_IP" not "fix clock skew"
- If the objective changed (new DA found, new access gained), update it"""

        try:
            result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=90)
            if result.returncode != 0 or not result.stdout.strip():
                return

            text = result.stdout.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]

            data = json.loads(text.strip())

            self.objective = data.get("objective", self.objective)
            if data.get("paths"):
                self.paths = data["paths"][:5]
            if data.get("priority_targets"):
                self.priority_targets = data["priority_targets"][:3]
            if data.get("blockers"):
                # Merge new blockers, don't overwrite fixed ones
                new_blockers = {b["name"]: b for b in data["blockers"]}
                for existing_b in self.blockers:
                    if existing_b.get("fixed") and existing_b["name"] in new_blockers:
                        new_blockers[existing_b["name"]]["fixed"] = True
                self.blockers = list(new_blockers.values())[:5]
            if data.get("lessons"):
                for lesson in data["lessons"]:
                    self.add_lesson(lesson)

            self.save()

        except (json.JSONDecodeError, Exception):
            pass

    def apply_synthesis(self, synth_output: str, on_status=None) -> bool:
        """Parse synthesis agent output and rewrite the attack plan.

        When synthesis produces HIGH viability chains, they become the new
        authoritative plan. Competing paths get killed. This is NOT advisory —
        it's a hard override.

        Returns True if the plan was rewritten (HIGH chain found).
        """
        import re

        # Extract JSON block from synthesis output
        json_match = re.search(r'```json\s*\n(.*?)\n```', synth_output, re.DOTALL)
        if not json_match:
            # Try without fences — synthesis might emit raw JSON at end
            json_match = re.search(
                r'\{\s*"chains"\s*:.*?"critical_insight"\s*:.*?\}',
                synth_output, re.DOTALL
            )
            if not json_match:
                if on_status:
                    on_status("[synthesis] No structured JSON found — output is advisory only")
                return False

        try:
            data = json.loads(json_match.group(1) if '```' in synth_output else json_match.group(0))
        except (json.JSONDecodeError, IndexError):
            if on_status:
                on_status("[synthesis] Failed to parse structured output — advisory only")
            return False

        chains = data.get("chains", [])
        kill_paths = data.get("kill_paths", [])
        critical_insight = data.get("critical_insight", "")

        if not chains:
            # Synthesis found nothing — record the insight as a lesson
            if critical_insight:
                self.add_lesson(f"[synthesis] {critical_insight}")
                self.save()
            return False

        # Find HIGH viability chains
        high_chains = [c for c in chains if c.get("viability") == "HIGH"]
        if not high_chains:
            # MEDIUM chains are advisory — add as paths but don't kill existing
            for chain in chains:
                if chain.get("viability") == "MEDIUM":
                    steps = chain.get("steps", [])
                    step_descs = [s.get("action", str(s)) if isinstance(s, dict) else s for s in steps]
                    self.paths.insert(0, {
                        "name": f"[SYNTHESIS] {chain['name']}",
                        "status": "active",
                        "steps": " → ".join(step_descs),
                        "next_step": chain.get("commands", chain.get("execution_commands", [""]))[0] if chain.get("commands") or chain.get("execution_commands") else "",
                        "source": "synthesis",
                        "agent": chain.get("agent", "exploit"),
                        "commands": chain.get("execution_commands", chain.get("commands", [])),
                    })
            if critical_insight:
                self.add_lesson(f"[synthesis] {critical_insight}")
            self.save()
            if on_status:
                on_status(f"[synthesis] Added {len(chains)} MEDIUM chains as candidates")
            return False

        # === HIGH VIABILITY: HARD OVERRIDE ===
        if on_status:
            on_status(
                f"[synthesis] AUTHORITATIVE REWRITE: {len(high_chains)} HIGH chain(s) found — "
                f"killing {len(kill_paths)} competing paths"
            )

        # Kill paths explicitly named
        kill_set = set(p.lower() for p in kill_paths)
        # Also kill paths superseded by any HIGH chain
        for chain in high_chains:
            for s in chain.get("supersedes", []):
                kill_set.add(s.lower())

        for path in self.paths:
            path_name = path.get("name", "").lower()
            # Strip [SYNTHESIS] prefix for matching
            clean_name = path_name.replace("[synthesis] ", "")
            if clean_name in kill_set or path_name in kill_set:
                path["status"] = "exhausted"
                path["blocked_reason"] = f"Superseded by synthesis chain"

        # Also kill any active path not explicitly needed by the new chains
        # (HIGH synthesis = we're confident, stop wasting turns on old approaches)
        for path in self.paths:
            if path.get("status") == "active" and path.get("source") != "synthesis":
                path["status"] = "superseded"
                path["blocked_reason"] = "Synthesis identified superior chain — paused"

        # Insert HIGH chains at top as the new active paths
        for i, chain in enumerate(high_chains):
            # Extract step descriptions
            steps = chain.get("steps", [])
            if steps and isinstance(steps[0], dict):
                step_descs = [s.get("action", str(s)) for s in steps]
                assumed_steps = [s for s in steps if s.get("evidence") == "ASSUMED"]
            else:
                step_descs = steps
                assumed_steps = []

            # Validation commands run first, then execution
            validation_cmds = chain.get("validation_commands", [])
            execution_cmds = chain.get("execution_commands", [])
            # Fallback to old "commands" field
            if not execution_cmds:
                execution_cmds = chain.get("commands", [])

            all_cmds = validation_cmds + execution_cmds

            self.paths.insert(i, {
                "name": f"[SYNTHESIS] {chain['name']}",
                "status": "active",
                "steps": " → ".join(step_descs),
                "next_step": (validation_cmds[0] if validation_cmds
                              else execution_cmds[0] if execution_cmds else ""),
                "source": "synthesis",
                "agent": chain.get("agent", "exploit"),
                "commands": all_cmds,
                "validation_commands": validation_cmds,
                "execution_commands": execution_cmds,
                "assumed_steps": [s.get("action", "") for s in assumed_steps],
                "viability": "HIGH",
            })

        # Cap total paths
        self.paths = self.paths[:8]

        # Record insight
        if critical_insight:
            self.add_lesson(f"[synthesis] {critical_insight}")

        self.save()
        return True

    def get_synthesis_commands(self) -> list[dict]:
        """Get pending synthesis-sourced commands for the batch planner.

        Returns list of {agent, task} dicts ready for dispatch.
        Validation commands are emitted as a separate first task — if they fail,
        the chain should be downgraded, not retried blindly.
        """
        commands = []
        for path in self.paths:
            if path.get("source") == "synthesis" and path.get("status") == "active":
                agent = path.get("agent", "exploit")
                chain_name = path['name'].replace('[SYNTHESIS] ', '')
                val_cmds = path.get("validation_commands", [])
                exec_cmds = path.get("execution_commands", [])
                assumed = path.get("assumed_steps", [])

                # Emit validation task first if there are assumptions to verify
                if val_cmds:
                    val_task = (
                        f"[SYNTHESIS VALIDATION: {chain_name}] "
                        f"Verify these assumptions BEFORE executing the chain:\n"
                        f"Assumed steps: {', '.join(assumed) if assumed else 'see below'}\n"
                        f"Run these validation commands:\n" +
                        "\n".join(f"  {i+1}. {c}" for i, c in enumerate(val_cmds)) +
                        "\n\nIF ANY VALIDATION FAILS: report which assumption broke. "
                        "Do NOT proceed to execution. The chain may need adjustment."
                    )
                    commands.append({"agent": agent, "task": val_task})

                # Then emit the execution task
                if exec_cmds:
                    exec_task = (
                        f"[SYNTHESIS CHAIN: {chain_name}] "
                        f"Execute these steps IN ORDER (assumptions validated):\n" +
                        "\n".join(f"  {i+1}. {c}" for i, c in enumerate(exec_cmds))
                    )
                    commands.append({"agent": agent, "task": exec_task})
                elif not val_cmds:
                    # Fallback: old-style commands field
                    cmds = path.get("commands", [])
                    if cmds:
                        task = (
                            f"[SYNTHESIS CHAIN: {chain_name}] "
                            f"Execute these steps IN ORDER:\n" +
                            "\n".join(f"  {i+1}. {c}" for i, c in enumerate(cmds))
                        )
                        commands.append({"agent": agent, "task": task})
        return commands

    def update_after_batch(self, batch_output: str, engagement_state,
                           on_status=None) -> None:
        """Lightweight update after a batch of micro-dispatches completes.

        Checks if any paths should be blocked/exhausted based on output,
        and updates next_step for active paths.

        CRITICAL: If synthesis paths are active, do NOT let haiku overwrite them.
        Haiku's generate() will replace synthesis chains with its own ideas (often CNG/garbage).
        Only update lessons and blockers — leave paths untouched when synthesis is in control.
        """
        # If synthesis paths are active, protect them from haiku overwrite
        has_synthesis_paths = any(
            p.get("source") == "synthesis" and p.get("status") == "active"
            for p in self.paths
        )
        if has_synthesis_paths:
            # Only extract lessons from the batch output — don't regenerate paths
            if on_status:
                on_status("[orchestrator] Synthesis paths active — skipping plan regeneration")
            # Still save in case lessons were added elsewhere
            self.save()
            return

        self.generate(engagement_state, recon_output=batch_output, on_status=on_status)
