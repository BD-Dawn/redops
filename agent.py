"""Core REDOPS Red Team Agent using Claude Code CLI as the LLM backend."""

import json
import os
import re
import subprocess
import threading
from datetime import datetime

from config import MODEL, MODEL_EXPLOIT, MODEL_FAST, SYSTEM_PROMPT, MAX_TURNS, TIMEOUT, FINDINGS_DIR, ENGAGEMENTS_DIR
from config import CTF_SYSTEM_PROMPT, CTF_AUTHORIZATION_HEADER
import config as _config
from retriever import KnowledgeBase
from opsec import score_command, LEVEL_HIGH, LEVEL_CRITICAL
from engagement import Engagement, EngagementManager, EngagementStatus
from engagement_logger import EngagementLogger
from secret_vault import SecretVault

_kb = None

def _get_kb():
    """Lazy-load the knowledge base on first use."""
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb


class RedTeamAgent:
    """Interactive red team operator agent using Claude Code CLI."""

    def __init__(self, engagement: Engagement | None = None):
        self.conversation_history: list[dict] = []
        # When an explicit engagement is provided (e.g. blitz workers),
        # skip EngagementManager entirely — the caller owns lifecycle.
        self._standalone = engagement is not None
        if self._standalone:
            self._engagement_mgr = None
            self.state = engagement
        else:
            # Use EngagementManager for proper lifecycle management
            self._engagement_mgr = EngagementManager()
            # self.state points to the current engagement (or a blank one)
            if self._engagement_mgr.current:
                self.state = self._engagement_mgr.current
            else:
                self.state = Engagement()
                self._engagement_mgr.current = self.state
        # Restore the Claude CLI conversation id from the loaded engagement so a
        # process restart (e.g. after Ctrl+C on --auto) resumes the same session
        # instead of starting a fresh one and losing in-session context.
        self._session_id: str = getattr(self.state, "session_id", "") or ""
        self._last_cost: float = 0
        self._last_turns: int = 0
        self._turn_count: int = 0
        self.fast_mode: bool = False  # Use MODEL_EXPLOIT (sonnet) instead of MODEL (opus)
        self.stop_event: threading.Event | None = None  # External stop signal (blitz mode)
        self.opsec_log: list[dict] = []  # Track OPSEC scores for commands
        # Stuck detection for interactive mode -- persists across chat() calls
        from agents.base import StuckDetector
        self._stuck = StuckDetector.load("interactive", self.state.dir)
        self._verify_claude_cli()
        # Per-engagement logger
        self._log = EngagementLogger(self.state.dir, self.state.engagement_mode)
        # Secret vault — tokenizes sensitive data before it reaches the API.
        # Active in LE/RT modes. CTF mode disables (synthetic data).
        _vault_enabled = self.state.engagement_mode in ("le", "redteam")
        self._vault = SecretVault(self.state.dir, enabled=_vault_enabled)
        if _vault_enabled and self.state.target:
            self._vault.register_from_engagement(self.state)
        # Sync evidence dir from engagement (skip for standalone — no global mutation)
        if not self._standalone and self.state.target:
            _config.EVIDENCE_DIR = self.state.evidence_dir

    def _verify_claude_cli(self):
        """Check that the claude CLI is available."""
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError("claude CLI returned non-zero exit code")
        except FileNotFoundError:
            raise RuntimeError(
                "claude CLI not found. Install it: https://docs.anthropic.com/en/docs/claude-code"
            )

    # Cached synthesis analysis — runs once per session, not per chat() call
    _synthesis_cache: str = ""
    _synthesis_ran: bool = False

    def reset_for_new_engagement(self):
        """Wipe all session state that could bleed between engagements.

        Called when switching to a genuinely new target. Leaves self.state
        alone — the caller must set that before or after this call.
        """
        from agents.base import StuckDetector
        self._session_id = ""
        self.conversation_history = []
        self.opsec_log = []
        self._synthesis_cache = ""
        self._synthesis_ran = False
        self._turn_count = 0
        self._last_session_output = []
        self._hud_last_cmd = ""
        self._hud_phase = "recon"
        self._hud_cumulative_cost = 0.0
        self._hud_session_num = 0
        self._stuck = StuckDetector.load("interactive", self.state.dir)
        self._log = EngagementLogger(self.state.dir, self.state.engagement_mode)
        _vault_enabled = self.state.engagement_mode in ("le", "redteam")
        self._vault = SecretVault(self.state.dir, enabled=_vault_enabled)
        if _vault_enabled and self.state.target:
            self._vault.register_from_engagement(self.state)

    def _run_synthesis_preflight(self) -> str:
        """Run synthesis agent to find combinatorial attack paths.

        Called once on first chat() of a session when the engagement has
        findings, defenses, and notes to analyze. Returns cached result
        on subsequent calls.
        """
        if self._synthesis_ran:
            return self._synthesis_cache

        self._synthesis_ran = True

        # Only run if we have meaningful engagement data to analyze
        if not self.state.target or not self.state.notes or len(self.state.notes) < 3:
            return ""

        try:
            import json as _json
            from agents.synthesis import SynthesisAgent
            synth = SynthesisAgent(self.state, autonomous=True)

            # Build comprehensive context including all attack primitives
            context = f"Analyze ALL findings for {self.state.target}. DO NOT RUN COMMANDS.\n\n"
            context += self.state.summary() + "\n\n"

            if self.state.notes:
                context += "## Notes\n" + "\n".join(f"- {n}" for n in self.state.notes[-20:])

            if getattr(self.state, "attack_surfaces", []):
                context += "\n\n## Attack Surfaces\n"
                for s in self.state.attack_surfaces:
                    context += f"- [{s.get('type','')}] {s.get('target','')}: {s.get('detail','')} (access: {s.get('access','')})\n"

            if getattr(self.state, "trust_relationships", []):
                context += "\n## Trust Relationships\n"
                for t in self.state.trust_relationships:
                    context += f"- {t.get('source','')} trusts {t.get('target','')} [{t.get('type','')}]: {t.get('detail','')}\n"

            if getattr(self.state, "capabilities", []):
                context += "\n## Owned Account Capabilities\n"
                for c in self.state.capabilities:
                    context += f"- {c.get('account','')}: {c.get('capability','')} on {c.get('target','')} — {c.get('detail','')}\n"

            if getattr(self.state, "service_configs", []):
                context += "\n## Service Configurations\n"
                for sc in self.state.service_configs:
                    context += f"- [{sc.get('service','')}] {sc.get('key','')}: {sc.get('value','')} — {sc.get('implication','')}\n"

            if getattr(self.state, "defenses", {}):
                context += f"\n## Defenses: {_json.dumps(self.state.defenses)}"

            result = synth.run(context, max_turns=3, skip_rag=False)
            self._synthesis_cache = result[:2000] if result else ""
            return self._synthesis_cache
        except Exception:
            return ""

    def _build_system_prompt(self, rag_context: str = "") -> str:
        """Build the full system prompt with RAG context and engagement state.

        Follows simple memory principle: minimal context, maximum action.
        In CTF mode, uses a leaner prompt that avoids opsec/stealth language
        to prevent policy filter accumulation over long sessions.
        """
        from agents.base import BaseAgent
        mode = getattr(self.state, "engagement_mode", "ctf")

        if mode == "ctf":
            # CTF mode: authorization header + lean system prompt (no opsec language)
            platform = getattr(self.state, "ctf_platform", "")
            platform_clause = f" hosted on {platform}" if platform else ""
            target = self.state.target or "target"
            auth_header = CTF_AUTHORIZATION_HEADER.format(platform_clause=platform_clause, target=target)
            parts = [auth_header, CTF_SYSTEM_PROMPT]
        else:
            parts = [SYSTEM_PROMPT]

        # Engagement mode rules
        if mode == "ctf":
            parts.append(BaseAgent._CTF_MODE_PROMPT)
        elif mode == "le":
            parts.append(BaseAgent._LE_MODE_PROMPT)
        elif mode == "redteam":
            parts.append(BaseAgent._REDTEAM_MODE_PROMPT)

        # Anti-stuck rules
        parts.append(self._ANTI_STUCK_PROMPT)

        # RAG — capped to avoid prompt bloat
        if rag_context:
            parts.append(f"\n\n## Reference Material\n{rag_context[:2000]}")

        # Lean state: resume point + target + creds only (not full summary)
        lean = []
        if getattr(self.state, "resume_point", ""):
            lean.append(f"**RESUME:** {self.state.resume_point}")
        if self.state.target:
            lean.append(f"Target: {self.state.target}")
        if self.state.credentials:
            creds = "; ".join(
                f"{c['username']}:{c['secret']}[{c['type']}]"
                for c in self.state.credentials[:5]
            )
            lean.append(f"Creds: {creds}")
        if self.state.compromised_hosts:
            hosts = ", ".join(
                f"{h['hostname']}[{h['access_level']}]"
                for h in self.state.compromised_hosts[:5]
            )
            lean.append(f"Compromised: {hosts}")
        if lean:
            parts.append("\n## State\n" + "\n".join(lean))

        # Cloud state — inject when cloud credentials/identities are present
        cloud_state = getattr(self.state, "cloud_state", None)
        if cloud_state:
            cloud_section = cloud_state.for_prompt()
            if cloud_section:
                parts.append(f"\n## Cloud State\n{cloud_section}")
            warnings = cloud_state.expiry_warnings()
            if warnings:
                parts.append("\n".join(f"⚠ {w}" for w in warnings))
            cloud_state.evaluate_escalation_paths()
            viable = cloud_state.viable_paths()
            if viable:
                esc_block = "\n## VIABLE CLOUD ESCALATION PATHS\n"
                for p in viable[:5]:
                    esc_block += f"### {p.name}\n{p.description}\n"
                    for cmd in p.commands[:3]:
                        esc_block += f"  $ {cmd}\n"
                    esc_block += "\n"
                parts.append(esc_block)

        # Operator directives — user corrections/context provided after interrupt
        directives = [n for n in self.state.notes if n.startswith("[operator directive]")]
        if directives:
            parts.append("\n## ⚠ OPERATOR DIRECTIVES (follow these)")
            for d in directives[-5:]:
                parts.append(f"- {d.replace('[operator directive] ', '')}")

        # Operator context notes
        op_notes = [n for n in self.state.notes if n.startswith("[operator]") and not n.startswith("[operator directive]")]
        if op_notes:
            parts.append("\n## Operator Context")
            for n in op_notes[-5:]:
                parts.append(f"- {n.replace('[operator] ', '')}")

        # Approach history — compact: just blocked + required
        self._inject_approach_history(parts)

        # Synthesis analysis — combinatorial attack paths (runs once per session)
        if self.state.autonomous and self.state.target:
            synth = self._run_synthesis_preflight()
            if synth:
                parts.append(f"\n## SYNTHESIS ANALYSIS (combinatorial attack paths)\n{synth}")

        # Secret vault — instructs agent to use $TOKEN variables in commands
        vault_section = self._vault.prompt_section()
        if vault_section:
            parts.append(vault_section)

        evidence_dir = self.state.evidence_dir if self.state.target else _config.EVIDENCE_DIR
        parts.append(f"\nEvidence: {evidence_dir} | Findings: {FINDINGS_DIR}")
        parts.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return "\n".join(parts)

    _ANTI_STUCK_PROMPT = """
## Execution Rules
- **Diagnose before pivoting.** If a technique fails, determine if the error is fixable
  (clock skew, permissions, wrong port) or policy-based (access denied). Fix and retry fixable errors.
- **Confirmed RCE = USE IT.** Don't refine the exploit. Write a webshell or get a reverse shell.
- **Verify access with commands.** evil-winrm shows PS prompt before auth completes — run `whoami` to confirm.
- **Enumerate before exploiting.** Vhost enum, parameter discovery, value manipulation BEFORE injection.
- **Parameter manipulation first.** Change values (`?id=2`, `?token=0`, `?file=../../etc/passwd`) before sqlmap.
- **Same category = same category.** sqlmap with different flags is still sqli. Different wordlist is still brute_force.
- **Batch indirect execution.** If using DLL hijack/scheduled tasks with wait cycles, run ALL checks
  in ONE payload (whoami + dir + query > output files) instead of one check per deployment cycle.
- **You have full sudo on Kali.** Use it. Don't pivot to alternative tools for permission errors.

## Depth-First Exploitation (CRITICAL — read before every turn)
A vulnerability scanner finds issues. A penetration tester PROVES them. You are a penetration tester.

**The rule: EXPLOIT before you ENUMERATE more.**
- If you have identified a potential vulnerability (subdomain takeover, open redirect, auth bypass,
  injection, IDOR, etc.) you MUST attempt to exploit it to proof BEFORE scanning new targets.
- "Found a Fastly dangling CNAME" → CLAIM IT on Fastly before scanning the next subdomain.
- "Found open redirect on OAuth" → CAPTURE a token via the redirect before probing other endpoints.
- "Found missing X-Frame-Options" → CREATE and TEST a clickjacking PoC before moving on.
- "Found exposed API endpoint" → EXTRACT data or demonstrate impact before enumerating more endpoints.

**What counts as proof:**
- Subdomain takeover: you control the content served (or screenshot showing claim was accepted)
- Open redirect: user LANDS on attacker URL after completing the flow (not just parameter in URL bar)
- Injection: extract data, not just trigger an error
- Auth bypass: access protected resources, not just get past the login form
- IDOR: access another user's data, not just get a 200 response
- SSRF: your listener receives a callback (not just parameter reflection)

**What does NOT count:**
- "Let me write the finding and continue scanning" — NO. Prove it first.
- "This is a confirmed vulnerability" without exploitation output — NOT confirmed.
- "Let me enumerate more while this runs" — ONLY if exploitation is actually running in background.
- "redirect_uri is preserved/passed through" — that's parameter REFLECTION, not a redirect.
  Complete the flow and show the user lands on evil.com. Parameter present ≠ parameter consumed.
- "SSRF parameter reflects our URL" — check your listener. Reflection ≠ server-side request.
- "Header is reflected in response" — check for behavior change. Reflection ≠ injection.

If you catch yourself doing recon after finding something exploitable, STOP and go back to exploit it.
"""

    def _inject_approach_history(self, parts: list[str]) -> None:
        """Inject persisted approach tracking into prompt parts."""
        from agents.base import StuckDetector

        # Check all agent stuck states, not just one — the interactive agent
        # can be doing recon, exploit, etc. depending on the conversation
        all_exhausted = set()
        all_categories = {}
        for agent_name in ("recon", "exploit", "postex", "interactive"):
            prior = StuckDetector.load(agent_name, self.state.dir)
            all_exhausted.update(prior.exhausted_categories)
            for cat, turns in prior.category_turns.items():
                all_categories.setdefault(cat, 0)
                all_categories[cat] += len(turns)

        if all_categories:
            lines = ["\n## Approaches Previously Tried (across all sessions)"]
            for cat, count in sorted(all_categories.items(), key=lambda x: -x[1]):
                exhausted = " [EXHAUSTED — DO NOT RETRY]" if cat in all_exhausted else ""
                lines.append(f"- {cat}: {count} turns{exhausted}")
            parts.append("\n".join(lines))

        if all_exhausted:
            blacklist = ", ".join(sorted(all_exhausted))
            parts.append(
                f"\n**BLOCKED CATEGORIES (will be terminated if attempted):** {blacklist}\n"
                f"These were tried extensively and failed. This includes ALL variations "
                f"(different tools, flags, endpoints, wordlists — same category = blocked)."
            )

        # Prescriptive: tell the agent what it SHOULD do next
        all_known = {cat for cat, _ in StuckDetector._ATTACK_CATEGORIES}
        tried = set(all_categories.keys())
        untried = all_known - tried - all_exhausted
        required_missing = StuckDetector._RECON_CATEGORIES - tried

        if required_missing or untried:
            lines = ["\n## WHAT YOU SHOULD DO NEXT"]
            if required_missing:
                lines.append(f"**REQUIRED (not yet attempted):** {', '.join(sorted(required_missing))}")
                if "subdomain_enum" in required_missing:
                    lines.append('  → Run: ffuf -u http://TARGET_IP -H "Host: FUZZ.DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs BASELINE')
                if "param_tamper" in required_missing:
                    lines.append("  → Probe each discovered endpoint's parameters with simple value changes (IDOR, path traversal, SSRF)")
                if "web_enum" in required_missing:
                    lines.append("  → Run: ffuf/gobuster directory enumeration on each vhost")
            if untried:
                lines.append(f"**Available (not yet tried):** {', '.join(sorted(untried))}")
            parts.append("\n".join(lines))

    def _build_prompt(self, user_message: str) -> str:
        """Build the full prompt including conversation history."""
        parts = []

        # Only inject history when there's no active session to resume,
        # since --resume already carries the full conversation context.
        if self.conversation_history and not self._session_id:
            parts.append("## Previous conversation context:")
            for entry in self.conversation_history[-10:]:
                role = entry["role"].upper()
                parts.append(f"\n{role}: {entry['content']}")
            parts.append("\n---\n")

        parts.append(user_message)
        return "\n".join(parts)

    @staticmethod
    def _sanitize(text: str) -> str:
        """Remove null bytes and non-printable characters that break CLI piping."""
        # Strip null bytes
        text = text.replace("\x00", "")
        # Remove other non-printable chars except common whitespace
        return "".join(
            ch for ch in text
            if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127)
        )

    @staticmethod
    def _needs_rag(message: str) -> bool:
        """Determine if a message warrants a knowledge base search."""
        stripped = message.strip().lower()
        # Skip RAG for very short confirmations / simple commands
        if len(stripped) < 15:
            return False
        skip_patterns = (
            "yes", "no", "ok", "continue", "proceed", "confirm", "check again",
            "check for beacon", "check for callback", "try again", "run it",
            "approved", "i approve", "quit", "exit", "help",
        )
        for pat in skip_patterns:
            if stripped == pat or stripped.startswith(pat + " "):
                return False
        return True

    _CLOUD_RAG_QUERIES = [
        "AWS IAM privilege escalation PassRole AssumeRole CreatePolicyVersion",
        "cloud SSRF IMDS metadata credential theft EC2 instance role",
        "AWS SQS Lambda CodeBuild container escape privilegedMode",
    ]

    def _has_cloud_context(self) -> bool:
        """Detect cloud signals in engagement state (mirrors orchestrator._detect_cloud)."""
        cloud_state = getattr(self.state, "cloud_state", None)
        if cloud_state and (cloud_state.credentials or cloud_state.identities):
            return True
        combined = " ".join(self.state.notes).lower()
        signals = ["aws", "iam", "s3", "lambda", "ec2", "sqs", "sts",
                    "169.254.169.254", "imds", "localstack", "gcloud", "azure", "kubectl"]
        return sum(1 for s in signals if s in combined) >= 2

    def _retrieve_context(self, message: str) -> str:
        """Search the knowledge base for relevant material.

        Uses multi-query decomposition so complex questions retrieve
        chunks for each sub-topic independently. Supplements with
        cloud-specific queries when cloud context is detected.
        """
        if not self._needs_rag(message):
            return ""
        try:
            kb = _get_kb()
            scope = getattr(self.state, "engagement_id", None)
            mode = getattr(self.state, "engagement_mode", None)
            hits = kb.multi_search(message, scope=scope, mode=mode)
            if self._has_cloud_context():
                for cq in self._CLOUD_RAG_QUERIES:
                    cloud_hits = kb.search(cq, scope=scope, mode=mode)
                    hits.extend(cloud_hits)
            if hits:
                return self._sanitize(kb.format_context(hits))
        except Exception:
            pass
        return ""

    # Max auto-continuations before requiring user input (prevents infinite loops).
    # CTF mode uses a higher limit since the objective is clear (capture flags)
    # and the operator can Ctrl+C at any time.
    MAX_AUTO_CONTINUES = _config.MAX_AUTO_CONTINUES          # non-CTF (config/env)
    MAX_AUTO_CONTINUES_CTF = _config.MAX_AUTO_CONTINUES_CTF  # CTF (config/env; lowered from 40)

    # --- HUD state (compact operator display) ---
    _hud_last_cmd: str = ""
    _hud_phase: str = "recon"
    _hud_cumulative_cost: float = 0.0
    _hud_session_num: int = 0     # increments on each auto-continue / stuck-restart
    _last_session_output: list[str] = []  # preserved across auto-continues for compaction

    @property
    def _should_stop(self) -> bool:
        """Check if an external stop signal has been set (blitz mode)."""
        return self.stop_event is not None and self.stop_event.is_set()

    # Phase detection patterns (order matters — first match wins)
    _PHASE_PATTERNS = [
        ("privesc", re.compile(r"(privesc|privilege.escalat|suid|sudo -l|linpeas|winpeas|getcap|/etc/passwd)", re.I)),
        ("lateral", re.compile(r"(lateral|pivot|psexec|wmiexec|evil-winrm|ssh\s+\w+@)", re.I)),
        ("postex", re.compile(r"(post.exploit|whoami|id\b|systeminfo|ipconfig|ifconfig|hostname)", re.I)),
        ("exploit", re.compile(r"(exploit|rce|reverse.shell|payload|webshell|injection|sqlmap|upload)", re.I)),
        ("enum", re.compile(r"(enum|gobuster|ffuf|nikto|nuclei|ferox|dirsearch|wfuzz)", re.I)),
        ("recon", re.compile(r"(nmap|scan|recon|discovery|masscan)", re.I)),
    ]

    def _detect_phase(self, cmd: str) -> str:
        """Classify a command into an engagement phase for HUD display."""
        for phase, pattern in self._PHASE_PATTERNS:
            if pattern.search(cmd):
                return phase
        return self._hud_phase  # keep current if unclassifiable

    def _format_hud(self, turn: int, extra: str = "") -> str:
        """Build compact one-line HUD string for operator display."""
        cost_str = f"${getattr(self.state, 'total_cost', 0.0):.2f}"
        total_secs = getattr(self.state, "total_time_secs", 0.0)
        mins, secs = divmod(int(total_secs), 60)
        time_str = f"{mins}m{secs:02d}s" if mins < 60 else f"{mins // 60}h{mins % 60:02d}m"
        session_str = f"S{self._hud_session_num}" if self._hud_session_num > 0 else ""
        cmd_short = self._hud_last_cmd[:45]
        parts = [f"T{turn}/{MAX_TURNS}"]
        if session_str:
            parts.append(session_str)
        parts.append(cost_str)
        parts.append(time_str)
        parts.append(self._hud_phase)
        if extra:
            parts.append(extra)
        elif cmd_short:
            parts.append(cmd_short)
        return " │ ".join(parts)

    def _build_continue_prompt(self, reason: str = "turn_limit", on_status=None) -> str:
        """Build a structured debrief prompt for auto-continuation.

        Instead of 'continue from where you left off', gives the agent a
        compressed summary of what happened, what failed, and what to try next.
        Uses Haiku to compact raw session output into structured intel so
        Opus doesn't waste turns re-discovering known facts.
        """
        parts = []

        # Reason header
        if reason == "turn_limit":
            parts.append("Session hit turn limit. Continuing with fresh turn budget.")
        elif reason == "context_overflow":
            parts.append("Session hit context limit. Starting fresh session with saved state.")
        elif reason == "stuck_restart":
            parts.append("Previous approach was terminated — it was not making progress. "
                        "You MUST use a fundamentally different technique.")
        elif reason == "execution_error":
            parts.append("Previous session hit an execution error and was discarded. "
                        "Starting fresh session with saved state. Continue from where you left off.")

        # Resume point (the most important piece of state)
        if getattr(self.state, "resume_point", ""):
            parts.append(f"\n**CURRENT POSITION:** {self.state.resume_point}")

        # Compacted session intel (Haiku extracts structured facts from raw output)
        if self._last_session_output:
            compacted = self._compact_session(self._last_session_output, on_status=on_status)
            if compacted:
                parts.append(f"\n## INTEL FROM PREVIOUS SESSION\n{compacted}")

        # What we have (structured, not prose)
        assets = []
        if self.state.credentials:
            creds = "; ".join(
                f"{c['username']}:{c['secret']}[{c['type']}]"
                for c in self.state.credentials[:5]
            )
            assets.append(f"Creds: {creds}")
        if self.state.compromised_hosts:
            hosts = ", ".join(
                f"{h['hostname']}[{h['access_level']}]"
                for h in self.state.compromised_hosts[:5]
            )
            assets.append(f"Access: {hosts}")
        if assets:
            parts.append("\n**ASSETS:** " + " | ".join(assets))

        # What was tried and what's exhausted (from stuck detector)
        if self._stuck.category_turns:
            tried = ", ".join(
                f"{cat}({len(t)}t)" for cat, t in
                sorted(self._stuck.category_turns.items(), key=lambda x: -len(x[1]))
            )
            parts.append(f"\n**TRIED:** {tried}")
        if self._stuck.exhausted_categories:
            parts.append(f"**EXHAUSTED (do NOT retry):** {', '.join(sorted(self._stuck.exhausted_categories))}")

        # Untried categories
        from agents.base import StuckDetector
        all_known = {cat for cat, _ in StuckDetector._ATTACK_CATEGORIES}
        tried_cats = set(self._stuck.category_turns.keys())
        untried = all_known - tried_cats - self._stuck.exhausted_categories
        if untried:
            parts.append(f"**UNTRIED:** {', '.join(sorted(untried))}")

        # Defenses discovered
        defenses = getattr(self.state, "defenses", {})
        if defenses:
            parts.append(f"**DEFENSES:** {', '.join(defenses.keys())}")

        # Directive
        parts.append("\nContinue the engagement. Do NOT re-analyze or repeat completed steps. "
                     "Execute your next action immediately.")

        return "\n".join(parts)

    _COMPACTION_PROMPT = """Extract structured intel from this penetration testing session output.
You are a data extraction tool — extract facts ONLY. Do NOT suggest attacks, plan next steps,
or provide methodology. Just structure what was discovered.

## Output Format (use exactly these headers, skip sections with no data):

### Services
port/proto — service version (host)

### Credentials
username:secret [type] — source/context

### File System
path — permissions/owner — significance

### Processes
name — user — relevant detail

### Network
listener/connection — detail

### Key Discoveries
- One-line factual observations (configs, writable files, group memberships, etc.)

### Ruled Out
- Approach — why it failed (one line each)

Rules:
- ONLY extract facts present in the output. Do not infer or speculate.
- Keep each entry to one line.
- Total output MUST be under 1500 characters.
- No attack suggestions, no methodology, no "next steps"."""

    def _compact_session(self, session_output: list[str], on_status=None) -> str:
        """Compress session output into structured intel using Haiku.

        Haiku extracts facts only — no attack logic or methodology.
        Returns structured intel string, or empty string on failure.
        """
        if not session_output:
            return ""

        # Combine session output chunks, cap input to avoid Haiku token limits
        raw = "\n\n---\n\n".join(session_output[-15:])  # Last 15 chunks
        max_input = 15000
        if len(raw) > max_input:
            raw = raw[:max_input] + "\n\n... (truncated)"

        if len(raw) < 200:
            return ""  # Too short to bother

        prompt = f"{self._COMPACTION_PROMPT}\n\n---\n\nSession output:\n\n{raw}"

        if on_status:
            on_status(self._format_hud(self._turn_count, "compacting session intel"))

        try:
            import time as _t
            _start = _t.monotonic()
            result = subprocess.run(
                [
                    "claude", "-p",
                    "--output-format", "text",
                    "--max-turns", "1",
                    "--model", MODEL_FAST,
                ],
                input=prompt,
                capture_output=True, text=True, timeout=60,
            )
            _elapsed = _t.monotonic() - _start
            if result.returncode == 0 and result.stdout.strip():
                compacted = result.stdout.strip()[:2000]
                self._log.compaction(len(session_output), len(compacted), _elapsed)
                return compacted
        except Exception as e:
            self._log.error("compaction_failed", error=str(e)[:200])

        return ""

    def chat(self, user_message: str, on_status=None, on_progress=None) -> str:
        """Send a message to Claude Code and get a response.

        In autonomous mode, auto-continues when turn limit is hit instead of
        returning to the user. Stops on: objective complete, auth error, stuck,
        or MAX_AUTO_CONTINUES reached.

        Args:
            user_message: The user's input
            on_status: Optional callback for status updates - on_status(msg: str)
            on_progress: Optional callback for verbose progress events - on_progress(event: dict)
                         Event types: "command", "output", "reasoning", "tool_use", "phase", "error"

        Returns:
            Claude's response text
        """
        # Reset auto-continue counter on fresh user messages (not auto-continuations)
        if not user_message.startswith(("Session hit turn limit",
                                        "Session hit context limit",
                                        "Previous approach was terminated",
                                        "Previous session hit an execution error")):
            self._auto_continue_count = 0
            self._exec_error_retries = 0

        # Step 1: RAG retrieval (skipped for simple messages and auto-continues)
        _is_auto_continue = user_message.startswith(("Session hit turn limit",
                                                      "Session hit context limit",
                                                      "Previous approach was terminated",
                                                      "Previous session hit an execution error"))
        if not _is_auto_continue and self._needs_rag(user_message):
            if on_status:
                on_status("Searching knowledge base...")
        rag_context = "" if _is_auto_continue else self._retrieve_context(user_message)

        # Step 2: Build prompts
        system_prompt = self._sanitize(self._build_system_prompt(rag_context))
        full_prompt = self._sanitize(self._build_prompt(user_message))

        # Step 3: Write system prompt to a temp file to avoid arg length / encoding issues
        if on_status:
            on_status("Thinking...")

        try:
            # Combine system context into the user prompt sent via stdin
            # to avoid ARG_MAX limits on --append-system-prompt.
            combined_prompt = (
                f"## System Context\n{system_prompt}\n\n"
                f"## User Request\n{full_prompt}"
            )

            _model = MODEL_EXPLOIT if self.fast_mode else MODEL
            _turns = MAX_TURNS * 2 if self.fast_mode else MAX_TURNS  # Sonnet is cheaper — double budget
            cmd = [
                "claude",
                "-p",
                "--output-format", "stream-json",
                "--verbose",
                "--model", _model,
                "--max-turns", str(_turns),
                "--permission-mode", "auto",
                "--allowedTools", "Edit,Write,Read,Bash,Glob,Grep",
            ]

            # Resume a previous session if available
            if self._session_id:
                cmd.extend(["--resume", self._session_id])

            # In autonomous / CTF mode, skip permission prompts
            _is_ctf = getattr(self.state, "engagement_mode", "ctf") == "ctf"
            if self.state.autonomous or _is_ctf:
                cmd.append("--dangerously-skip-permissions")

            # Inherit full environment so claude picks up OAuth auth
            env = os.environ.copy()
            env["HOME"] = os.path.expanduser("~")
            env["EVIDENCE_DIR"] = str(self.state.evidence_dir if self.state.target else _config.EVIDENCE_DIR)

            # Write vault deref script and set env var so agent can source it
            vault_script = self._vault.write_deref_script()
            if vault_script:
                env["VAULT_ENV"] = str(vault_script)

            cwd_dir = self.state.evidence_dir if self.state.target else _config.EVIDENCE_DIR
            import time as _time
            _session_start = _time.monotonic()
            self._log.session_start(
                agent="redops", session_id=self._session_id,
                turns=MAX_TURNS, model=MODEL, resumed=bool(self._session_id),
            )
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=str(cwd_dir),
            )

            # Tokenize secrets before sending to API (LE/RT mode)
            combined_prompt = self._vault.tokenize(combined_prompt)

            # Send prompt via stdin and close to signal EOF
            proc.stdin.write(combined_prompt)
            proc.stdin.close()

            # Stream stdout line by line, collecting the final result message
            response_text = ""
            last_result = None
            self._turn_count = 0
            _session_output = []  # Accumulates tool results + thinking for primitive extractor
            _STALL_TIMEOUT = None  # Disabled — user has Ctrl+C for interactive agent

            try:
                import threading
                import queue as _queue

                # Non-blocking line reader — detects stalled commands
                _line_queue = _queue.Queue()
                def _reader_thread():
                    try:
                        for ln in proc.stdout:
                            _line_queue.put(ln)
                    except (ValueError, OSError):
                        pass
                    _line_queue.put(None)  # Sentinel

                _reader = threading.Thread(target=_reader_thread, daemon=True)
                _reader.start()

                while True:
                    try:
                        line = _line_queue.get(timeout=_STALL_TIMEOUT)
                    except _queue.Empty:
                        # No output for _STALL_TIMEOUT seconds — command is hanging
                        if on_status:
                            on_status(f"[WATCHDOG] No output for {_STALL_TIMEOUT}s — killing stalled command")
                        proc.kill()
                        if response_text:
                            response_text += "\n\n*[Killed — command hung with no output. A listener or blocking command was likely run without backgrounding.]*"
                        break

                    if line is None:
                        break  # Process ended

                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    etype = event.get("type", "")

                    # Capture the live session id as soon as it appears (the init
                    # event carries it up front). Without this, an interrupt before
                    # the final result event leaves no id to resume from. Mirror it
                    # onto the engagement so a save() during Ctrl+C persists it.
                    _sid = event.get("session_id")
                    if _sid:
                        self._session_id = _sid
                        try:
                            self.state.session_id = _sid
                        except Exception:
                            pass

                    # Accumulate all output for the primitive extractor.
                    # response_text only captures the final result/last thinking block,
                    # but tool results contain the actual findings (nmap, LDAP, ACLs).
                    # In LE/RT mode, tokenize output before accumulation so secrets
                    # don't leak into compaction prompts sent to the API.
                    if etype == "tool_result":
                        _content = ""
                        if "content" in event:
                            for _blk in event.get("content", []):
                                if isinstance(_blk, dict) and _blk.get("type") == "text":
                                    _content = _blk.get("text", "")
                                elif isinstance(_blk, str):
                                    _content = _blk
                        elif "result" in event:
                            _content = str(event["result"])
                        if _content and len(_content) > 20:
                            _session_output.append(self._vault.tokenize(_content[:2000]))
                    elif etype == "assistant" and "message" in event:
                        for _blk in event.get("message", {}).get("content", []):
                            if isinstance(_blk, dict) and _blk.get("type") == "text":
                                _text = _blk.get("text", "")
                                if len(_text) > 50:
                                    _session_output.append(self._vault.tokenize(_text[:1500]))

                    # Track tool usage for live HUD + OPSEC scoring
                    if etype == "tool_use":
                        tool_name = event.get("tool", {}).get("name", event.get("name", ""))
                        tool_input = event.get("tool", {}).get("input", {})
                        if tool_name == "Bash":
                            cmd_str = tool_input.get("command", "")
                            # Update HUD state
                            self._hud_last_cmd = cmd_str
                            self._hud_phase = self._detect_phase(cmd_str)
                            # Track for stuck detection
                            self._stuck.record_command(cmd_str)
                            _is_ctf = getattr(self.state, "engagement_mode", "ctf") == "ctf"
                            if not _is_ctf:
                                # Full OPSEC scoring for LE/Red Team modes
                                opsec_result = score_command(cmd_str)
                                self.opsec_log.append({
                                    "command": cmd_str[:200],
                                    "score": opsec_result.score,
                                    "level": opsec_result.level_name,
                                    "reasons": opsec_result.reasons,
                                    "time": datetime.now().isoformat(),
                                })
                                if opsec_result.score >= LEVEL_HIGH:
                                    if on_status:
                                        on_status(self._format_hud(
                                            self._turn_count,
                                            f"OPSEC:{opsec_result.level_name} {cmd_str[:40]}"
                                        ))
                                else:
                                    if on_status:
                                        on_status(self._format_hud(self._turn_count))
                                if on_progress:
                                    on_progress({
                                        "type": "command",
                                        "agent": "redops",
                                        "command": cmd_str,
                                        "opsec_score": opsec_result.score,
                                        "opsec_level": opsec_result.level_name,
                                        "opsec_reasons": opsec_result.reasons,
                                    })
                            else:
                                # CTF mode: anti-cheat only, no stealth scoring
                                opsec_result = score_command(cmd_str, ctf_mode=True)
                                if opsec_result.ctf_blocked:
                                    self.opsec_log.append({
                                        "command": cmd_str[:200],
                                        "score": opsec_result.score,
                                        "level": opsec_result.level_name,
                                        "reasons": opsec_result.reasons,
                                        "time": datetime.now().isoformat(),
                                        "action": "killed",
                                    })
                                    if on_status:
                                        on_status(self._format_hud(
                                            self._turn_count,
                                            f"ANTI-CHEAT VIOLATION — {opsec_result.reasons[0]}"
                                        ))
                                    if on_progress:
                                        on_progress({
                                            "type": "ctf_anticheat",
                                            "agent": "redops",
                                            "command": cmd_str,
                                            "reasons": opsec_result.reasons,
                                        })
                                    proc.kill()
                                    response_text += (
                                        f"\n\n*[SESSION KILLED — CTF anti-cheat violation: "
                                        f"{opsec_result.reasons[0]}. "
                                        f"Solve the box using your own methodology.]*"
                                    )
                                    break
                                if on_status:
                                    on_status(self._format_hud(self._turn_count))
                                if on_progress:
                                    on_progress({
                                        "type": "command",
                                        "agent": "redops",
                                        "command": cmd_str,
                                    })
                        elif tool_name in ("Write", "Edit"):
                            fpath = tool_input.get("file_path", "")
                            self._hud_last_cmd = f"write:{os.path.basename(fpath)}"
                            if on_status:
                                on_status(self._format_hud(self._turn_count))
                            if on_progress:
                                on_progress({
                                    "type": "tool_use",
                                    "agent": "redops",
                                    "tool": tool_name,
                                    "input": {"file_path": fpath},
                                })
                        else:
                            self._hud_last_cmd = f"{tool_name}"
                            if on_status:
                                on_status(self._format_hud(self._turn_count))
                            if on_progress:
                                on_progress({
                                    "type": "tool_use",
                                    "agent": "redops",
                                    "tool": tool_name,
                                    "input": {k: str(v)[:300] for k, v in tool_input.items()},
                                })

                    elif etype == "tool_result":
                        self._turn_count += 1
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

                        # Feed errors to stuck detector
                        if event.get("is_error") and result_content:
                            self._stuck.record_error(result_content)
                            self._log.command_error("redops", self._hud_last_cmd, result_content[:300])

                        # Check for milestones in tool output to inform stuck detector
                        if result_content and len(result_content) > 20:
                            import re as _ms_re
                            _rc_lower = result_content.lower()
                            for _milestone_entry in self._MILESTONES:
                                _mpat = _milestone_entry[1]
                                if _ms_re.search(_mpat, _rc_lower):
                                    self._stuck.record_milestone()
                                    break

                        # Stuck detection — kill on strategic loop
                        stuck_msg = self._stuck.check(self._turn_count)
                        if stuck_msg:
                            is_strategic = "STRATEGIC LOOP" in stuck_msg or "RECON INCOMPLETE" in stuck_msg
                            if self._stuck.pivot_warnings_sent >= 2 or is_strategic:
                                if on_status:
                                    on_status(self._format_hud(
                                        self._turn_count, f"STUCK: {stuck_msg[:50]}"
                                    ))
                                if on_progress:
                                    on_progress({"type": "error", "agent": "redops",
                                                 "text": f"TERMINATED — {stuck_msg}"})
                                proc.kill()
                                self._stuck.save()
                                exhausted = ", ".join(sorted(self._stuck.exhausted_categories)) or "none"
                                self._log.stuck_detected(
                                    "redops", stuck_msg, exhausted,
                                    auto_restart=getattr(self.state, "engagement_mode", "ctf") == "ctf",
                                )
                                # Auto-learn: record what failed so RAG warns against it
                                try:
                                    from learner import learn_from_stuck_async
                                    learn_from_stuck_async(
                                        stuck_msg, self._stuck.approach_summary(), "interactive",
                                        engagement_id=getattr(self.state, "engagement_id", ""),
                                        mode=getattr(self.state, "engagement_mode", ""))
                                except Exception:
                                    pass
                                # CTF mode: auto-restart with different approach
                                # Non-CTF: return to operator
                                _is_ctf_stuck = getattr(self.state, "engagement_mode", "ctf") == "ctf"
                                if _is_ctf_stuck and not self._should_stop:
                                    self._session_id = ""  # fresh session
                                    self._hud_session_num += 1
                                    self._hud_cumulative_cost += self._last_cost
                                    self._last_session_output = _session_output
                                    self._auto_save()
                                    if on_status:
                                        on_status(self._format_hud(
                                            self._turn_count, "stuck → auto-restarting with new approach"
                                        ))
                                    return self.chat(
                                        self._build_continue_prompt("stuck_restart", on_status=on_status),
                                        on_status=on_status,
                                        on_progress=on_progress,
                                    )
                                response_text = (
                                    f"**[TERMINATED — STUCK DETECTED]**\n{stuck_msg}\n\n"
                                    f"{self._stuck.approach_summary()}\n\n"
                                    f"Restate your task and I will use a different approach."
                                )
                                break
                            else:
                                if on_status:
                                    on_status(self._format_hud(
                                        self._turn_count, f"WARNING: {stuck_msg[:50]}"
                                    ))

                        if on_status:
                            on_status(self._format_hud(self._turn_count))
                        if on_progress and result_content:
                            on_progress({
                                "type": "output",
                                "agent": "redops",
                                "turn": self._turn_count,
                                "content": result_content[:2000],
                            })

                    # Capture assistant text as it streams
                    elif etype == "assistant" and "message" in event:
                        content_blocks = event["message"].get("content", [])
                        for block in content_blocks:
                            if block.get("type") == "text":
                                response_text = block["text"]
                                # NOTE: Do NOT run milestone detection on thinking blocks.
                                # Thinking text contains enumeration data ("Domain Admins" group
                                # listing etc.) which triggers false positive milestones.
                                # Milestones are checked on the final response text at line 669.
                                if on_progress:
                                    on_progress({
                                        "type": "reasoning",
                                        "agent": "redops",
                                        "text": block["text"][:1500],
                                    })
                        if on_status:
                            on_status(self._format_hud(self._turn_count, "thinking"))

                    # The final result event
                    if etype == "result":
                        last_result = event
                        if event.get("result"):
                            response_text = event["result"]

                proc.wait(timeout=TIMEOUT)

            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                _elapsed = _time.monotonic() - _session_start
                self._log.error("timeout", agent="redops", elapsed=f"{_elapsed:.0f}s",
                                turns=self._turn_count, timeout=TIMEOUT)
                if response_text:
                    return f"{response_text}\n\n*[Timed out after {TIMEOUT // 60} min — partial output above. Send a follow-up to continue.]*"
                return f"[Agent Error] Command timed out after {TIMEOUT // 60} minutes with no output."

            # Extract session ID for future --resume
            # Only update if we got a valid session ID — don't overwrite with empty on errors
            if last_result:
                new_session = last_result.get("session_id", "")
                if new_session:
                    self._session_id = new_session
                self._last_cost = last_result.get("total_cost_usd", 0)
                self._last_turns = last_result.get("num_turns", 1)
                # Accumulate cost + time on engagement state (persisted)
                _elapsed = _time.monotonic() - _session_start
                if self.state.target:
                    if self._last_cost:
                        self.state.total_cost = getattr(self.state, "total_cost", 0.0) + self._last_cost
                    self.state.total_time_secs = getattr(self.state, "total_time_secs", 0.0) + _elapsed
                self._log.session_end("redops", self._last_cost, self._last_turns,
                                      _elapsed, self._session_id)

                if last_result.get("is_error"):
                    subtype = last_result.get("subtype", "")
                    error_text = last_result.get("result", "")

                    # Detect auth expiry in error response
                    if "authentication_error" in str(error_text) or "401" in str(subtype):
                        # PRESERVE session ID — the conversation still exists server-side.
                        # Don't overwrite with empty/error session. Save state so any
                        # milestones captured from thinking blocks survive.
                        self._log.auth_failure(f"subtype={subtype}, text={str(error_text)[:200]}")
                        self._auto_save()
                        self._stuck.save()
                        return (
                            "[Agent Error] Claude Code authentication expired. "
                            "Run `/login` to re-authenticate, then retry your message. "
                            "Your session has been preserved."
                        )

                    if subtype == "error_max_turns":
                        num = last_result.get("num_turns", "?")
                        # CTF mode is autonomous by default — run until flags or Ctrl+C
                        _is_ctf = getattr(self.state, "engagement_mode", "ctf") == "ctf"
                        is_autonomous = self.state.autonomous or _is_ctf
                        max_continues = self.MAX_AUTO_CONTINUES_CTF if _is_ctf else self.MAX_AUTO_CONTINUES

                        auto_continues = getattr(self, "_auto_continue_count", 0)

                        # --- Hard stops that override the continuation budget ---
                        _cost = getattr(self.state, "total_cost", 0.0)
                        _cost_exceeded = _cost >= _config.MAX_ENGAGEMENT_COST
                        _objective_done = _is_ctf and self.state.ctf_objective_complete()
                        if is_autonomous and (_cost_exceeded or _objective_done):
                            reason = ("cost ceiling ${:.2f}".format(_config.MAX_ENGAGEMENT_COST)
                                      if _cost_exceeded else "objective complete")
                            self._auto_continue_count = 0
                            self._auto_save()
                            stop_msg = (
                                f"*[Autonomous run halted — {reason} reached "
                                f"(${_cost:.2f} spent, {self.state.flags and len(self.state.flags) or 0} flag(s)). "
                                f"Send a follow-up to resume manually.]*"
                            )
                            return f"{response_text}\n\n{stop_msg}" if response_text else stop_msg

                        if is_autonomous and auto_continues < max_continues and not self._should_stop:
                            self._auto_continue_count = auto_continues + 1
                            self._hud_session_num += 1
                            self._hud_cumulative_cost += self._last_cost
                            self._log.auto_continue(
                                "turn_limit", self._auto_continue_count, max_continues,
                                getattr(self.state, "total_cost", 0.0),
                            )
                            if on_status:
                                on_status(self._format_hud(
                                    self._turn_count,
                                    f"auto-continue {self._auto_continue_count}/{max_continues}"
                                ))
                            # Save state + session output for compaction
                            self._last_session_output = _session_output
                            self._auto_save()
                            self._stuck.save()
                            # Continue with structured debrief prompt
                            return self.chat(
                                self._build_continue_prompt("turn_limit", on_status=on_status),
                                on_status=on_status,
                                on_progress=on_progress,
                            )
                        # Not autonomous or max continues reached — return to user
                        self._auto_continue_count = 0
                        if response_text:
                            return f"{response_text}\n\n*[Hit turn limit ({num} turns) — send a follow-up to continue]*"
                        return f"*[Hit turn limit ({num} turns) — work in progress. Send a follow-up to continue.]*"

                    if not response_text:
                        # Log the error for debugging but provide actionable message
                        error_detail = error_text[:300] if error_text else subtype or "unknown error"
                        if "overloaded" in str(error_detail).lower():
                            self._log.error("overloaded", agent="redops")
                            return "[Agent Error] Model overloaded — retry in a moment."
                        elif "context" in str(error_detail).lower() or "token" in str(error_detail).lower():
                            # Context overflow — clear session and auto-continue
                            # with a fresh session that carries lean state
                            self._log.context_overflow("redops", self._turn_count)
                            self._session_id = ""
                            self._hud_session_num += 1
                            self._hud_cumulative_cost += self._last_cost
                            self._last_session_output = _session_output
                            self._auto_save()
                            _is_ctf = getattr(self.state, "engagement_mode", "ctf") == "ctf"
                            is_autonomous = self.state.autonomous or _is_ctf
                            if is_autonomous and not self._should_stop:
                                if on_status:
                                    on_status(self._format_hud(
                                        self._turn_count, "context overflow → fresh session"
                                    ))
                                return self.chat(
                                    self._build_continue_prompt("context_overflow", on_status=on_status),
                                    on_status=on_status,
                                    on_progress=on_progress,
                                )
                            return "[Agent Error] Context overflow — session reset. Retry your message."
                        elif subtype == "error_during_execution":
                            # Transient CLI execution error — session may be
                            # corrupted. Clear it and auto-retry in CTF/autonomous
                            # mode; otherwise surface to the operator.
                            _retries = getattr(self, "_exec_error_retries", 0)
                            self._log.error("error_during_execution", agent="redops",
                                            retries=_retries, detail=error_detail[:200])
                            self._session_id = ""  # force fresh session
                            _is_ctf = getattr(self.state, "engagement_mode", "ctf") == "ctf"
                            is_autonomous = self.state.autonomous or _is_ctf
                            if is_autonomous and _retries < 2 and not self._should_stop:
                                self._exec_error_retries = _retries + 1
                                self._hud_session_num += 1
                                self._hud_cumulative_cost += self._last_cost
                                self._last_session_output = _session_output
                                self._auto_save()
                                if on_status:
                                    on_status(self._format_hud(
                                        self._turn_count,
                                        f"execution error → retry {_retries + 1}/2"
                                    ))
                                return self.chat(
                                    self._build_continue_prompt("execution_error", on_status=on_status),
                                    on_status=on_status,
                                    on_progress=on_progress,
                                )
                            self._exec_error_retries = 0
                            return "[Agent Error] Execution error (retries exhausted) — type /new to start fresh."
                        return f"[Agent Error] {error_detail}\n[Tip: try a shorter message, or type /new to start a fresh agent session]"

            elif proc.returncode != 0 and not response_text:
                stderr = proc.stderr.read().strip() if proc.stderr else ""
                # Detect auth expiry — preserve session and prompt re-login
                if "authentication_error" in stderr or "401" in stderr:
                    self._log.auth_failure(f"stderr: {stderr[:200]}")
                    self._auto_save()
                    self._stuck.save()
                    return (
                        "[Agent Error] Claude Code authentication expired. "
                        "Run `/login` to re-authenticate, then retry your message. "
                        "Your session has been preserved."
                    )
                self._log.crash("redops", f"exit code {proc.returncode}", stderr[:300])
                return f"[Agent Error] exit code {proc.returncode}: {stderr[:500] or 'no output from CLI'}"

            if not response_text:
                response_text = "(No response text returned)"

            # Update conversation history
            self.conversation_history.append({"role": "user", "content": user_message})
            self.conversation_history.append({"role": "assistant", "content": response_text})

            if len(self.conversation_history) > 20:
                self.conversation_history = self.conversation_history[-20:]

            # Auto-update resume checkpoint based on milestones in the response.
            # Pass raw tool output for grounding — exploitation milestones (priority > 30)
            # must appear in actual tool output, not just the agent's narrative.
            _raw_tool_text = "\n".join(_session_output[-20:]) if _session_output else ""
            self._update_resume_point(response_text, raw_tool_output=_raw_tool_text)

            # Parse credentials into engagement state. Scan BOTH the narrative AND the
            # raw tool output — harvested creds (e.g. an AWS_ACCESS_KEY_ID/SECRET pair
            # from an env dump or callback) appear in tool results, not the agent's
            # summary, so narrative-only parsing silently dropped them.
            try:
                creds_before = len(self.state.credentials)
                self.state.parse_credentials_from_text(response_text, source="interactive")
                if _raw_tool_text:
                    self.state.parse_credentials_from_text(_raw_tool_text, source="tool_output")
                # Auto-register any new credentials in the vault
                if len(self.state.credentials) > creds_before:
                    self._vault.register_from_engagement(self.state)
                    self._vault.write_deref_script()
            except Exception:
                pass

            # Parse discovered hosts from agent output
            try:
                self.state.parse_hosts_from_text(response_text, source="interactive")
            except Exception:
                pass

            # CTF mode: detect flag capture and mark engagement SOLVED
            if self.state.engagement_mode == "ctf":
                self._check_ctf_flags(response_text, raw_tool_output=_raw_tool_text)

            # Record explicit dead-end conclusions so resumes don't re-derive them.
            try:
                self.state.scan_and_record_dead_ends(response_text)
            except Exception:
                pass

            # Auto-extract attack primitives from the full session output.
            # Use accumulated tool results + thinking (not just the final response text,
            # which is often a short summary missing the actual findings).
            try:
                from primitive_extractor import extract_primitives_async
                _full_output = "\n\n".join(_session_output[-20:])  # Last 20 chunks, ~40K chars max
                if len(_full_output) > len(response_text):
                    extract_primitives_async(_full_output, self.state)
                else:
                    extract_primitives_async(response_text, self.state)
            except Exception:
                pass

            # Auto-save engagement state, session ID, and stuck detector state
            self._auto_save()
            self._stuck.save()

            return response_text

        except Exception as e:
            import traceback
            self._log.crash("redops", str(e), traceback.format_exc()[-500:])
            return f"[Agent Error] {e}"

    # Milestone patterns in priority order (highest milestone wins).
    # Each: (priority, regex_pattern, resume_point_template)
    # Templates can use {target} and {match} placeholders.
    _MILESTONES = [
        (100, r"(root|system|nt authority).*(flag|proof|hash|txt)",
         "ROOT/SYSTEM access achieved on {target}. Capture flags and document the full attack chain."),
        (95, r"(dcsync|secretsdump.*completed|ntds\.dit|krbtgt.*hash)",
         "DCSync/NTDS dump completed. Domain fully compromised. Extract all hashes and document."),
        (90, r"((?:achieved|obtained|got|have|am|as)\s+domain\s*admin|domain\s*admin\s*(?:achieved|obtained|access|shell|compromise)|da\s+access\s+(?:achieved|obtained|confirmed))",
         "Domain Admin achieved. DCSync immediately, capture flags, document attack chain."),
        (80, r"(privilege\s*escalat|privesc|got\s*root|now\s*root|uid=0|nt authority\\\\system|system\s*shell)",
         "Privilege escalation successful on {target}. Enumerate from elevated context, capture root/system flag."),
        (70, r"(lateral\s*mov|pivot|moved\s*to|accessed\s*(another|new)\s*host)",
         "Lateral movement in progress. Continue pivoting and enumerate the new host."),
        (65, r"(user\.txt|user\s*flag|user\s*proof)",
         "User flag captured on {target}. Escalate privileges to root/SYSTEM."),
        (60, r"(reverse\s*shell|callback|shell\s*as\s*\w+|interactive\s*shell|meterpreter|beacon\s*check"
             r"|winrm.*(connect|shell|access|works)|evil-winrm\s*(connect|shell)"
             r"|crackmapexec.*(pwn3d|Pwn3d|owned|\(\+\))|cme.*(pwn3d|Pwn3d)"
             r"|impacket.*(shell|access)|psexec.*success|wmiexec.*success"
             r"|ssh\s+.*connect|got\s*a?\s*shell)",
         "Shell obtained on {target}. Enumerate the host, find privesc vectors, capture user flag."),
        (55, r"(webshell|web\s*shell|cmd\.php|shell\.php|system\(\$_GET)",
         "Webshell deployed on {target}. Use it to get a proper reverse shell or enumerate directly."),
        (50, r"(rce\s*confirm|confirmed\s*rce|code\s*execution\s*confirm|uid=\d+\("
             r"|command\s*execution\s*(work|success|confirm))",
         "RCE confirmed on {target}. Use the existing RCE immediately — do NOT refine the exploit."),
        (45, r"(credentials?\s*(found|discover|crack|dump|obtain|extract)\s*[:\-—]"
             r"|password\s*(hash|crack|found|dump|discover)\s*[:\-—]"
             r"|gmsa\s*(password|hash|secret)|ntlm\s*hash\s*(obtain|extract|read|dump)"
             r"|\.ccache\b|tgt\s*(obtain|extract|harvest))",
         "Credentials obtained. Try credential reuse across all services (WinRM, SSH, SMB, LDAP)."),
        (40, r"(logged\s*in\s*(as|to|successfully)|auth\s*bypass\s*(confirm|success|verified)"
             r"|valid\s*(session|token|cookie)\s*(obtain|got|have)"
             r"|login\s*(success|work)|access\s*grant\s*(confirm|verified|to\s+admin))",
         "Authenticated access obtained. Look for post-auth vulns (file upload, RCE, IDOR, admin functions)."),
        (30, r"(sqli\s*(confirm|found)|injection\s*(confirm|found)|union\s*select.*success"
             r"|data\s*(extract|dump|exfil)|type\s*juggl|idor\s*(confirm|found))",
         "Injection/IDOR confirmed. Extract credentials, secrets, or pivot to RCE."),
        (20, r"(subdomain\s*takeover\s*(confirm|verified|claimed))|"
             r"(vhost).*(found|discover).*(admin|internal|staging)",
         "New attack surface discovered. Enumerate the new endpoints/parameters before exploitation."),
    ]

    def _check_ctf_flags(self, response_text: str, raw_tool_output: str = "") -> None:
        """Detect CTF flag captures and persist them via the shared engagement logic.

        Delegates to Engagement.scan_and_record_flags(), which writes flags to the
        *serialized* ``flags`` field (the old code wrote a transient ``_ctf_flags``
        that never survived a save, leaving flags:{} on disk), grounds values against
        raw tool output, labels user/root conservatively (no more lone-hex→root
        mislabel), and marks the engagement solved only when the flag goal is met.
        """
        try:
            recorded = self.state.scan_and_record_flags(
                response_text, raw_output=raw_tool_output or "")
        except Exception:
            return
        for label, value in recorded.items():
            self._log.flag_captured(label, value)

    def _update_resume_point(self, response_text: str,
                             raw_tool_output: str = "") -> None:
        """Scan agent response for milestone indicators and update the resume checkpoint.

        Only updates if a HIGHER priority milestone is detected than the current one.
        This prevents regression (e.g., going from 'RCE confirmed' back to 'credentials found').

        For exploitation milestones (priority > 30), the pattern must ALSO match in
        raw_tool_output to prevent narrative-only false positives where the agent
        describes what it *expects* to see rather than what actually happened.
        """
        if not response_text or not self.state.target:
            return

        text_lower = response_text.lower()
        raw_lower = raw_tool_output.lower() if raw_tool_output else ""
        current_priority = self.state.resume_priority

        for priority, pattern, template in self._MILESTONES:
            if priority <= current_priority:
                continue  # Only upgrade, never downgrade
            if not re.search(pattern, text_lower):
                continue
            # Grounding check: exploitation milestones (priority > 30) must also
            # appear in raw tool output, not just the agent's narrative summary.
            # Recon milestones (priority <= 30) are allowed from narrative alone
            # since they describe discovery, not exploitation.
            if priority > 30 and raw_lower:
                if not re.search(pattern, raw_lower):
                    continue  # Agent claims milestone but tool output doesn't support it

            # State corroboration: terminal claims (root/DA/SYSTEM, priority >= 90)
            # must be backed by a recorded flag or compromised host — a narrative
            # "I have root" with empty state is a hallucination that would set a
            # false objective and spawn expensive autonomous cycles.
            if not self.state.milestone_corroborated(priority):
                continue

            new_point = template.format(
                target=self.state.target,
                match=pattern[:30],
            )
            # Preserve existing notes context by appending key details
            # from the response (first 200 chars of the matching section)
            match = re.search(pattern, text_lower)
            if match:
                # Extract surrounding context (±100 chars)
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 100)
                context = response_text[start:end].strip()
                # Only append if it adds useful detail
                if len(context) > 20:
                    new_point += f"\nContext: {context[:300]}"

            self.state.resume_point = new_point
            self.state.resume_priority = priority
            self._log.milestone("redops", priority, template.split(".")[0])

            # Corroborate access in typed state: a grounded shell/RCE/privesc milestone
            # means we hold a foothold. Recording it here is what later lets a genuine
            # root claim pass milestone_corroborated() instead of being rejected.
            if priority >= 50:
                try:
                    self.state.add_compromised_host(
                        self.state.target or "target", ip=self.state.target or "",
                        access_level=("root" if priority >= 80 else "user"))
                except Exception:
                    pass

            # Auto-learn: ingest successful technique into RAG (background)
            try:
                from learner import learn_from_milestone_async
                label = template.split(".")[0] if "." in template else template[:50]
                learn_from_milestone_async(
                    response_text, label, self.state.target,
                    engagement_id=getattr(self.state, "engagement_id", ""),
                    mode=getattr(self.state, "engagement_mode", ""))
            except Exception:
                pass  # Learning is best-effort, never block the agent

            break  # Highest matching milestone wins

    def _target_safe_name(self, target: str = "") -> str:
        """Convert a target to a safe filename component."""
        t = target or self.state.target
        return t.replace(".", "_").replace("/", "_").replace(":", "_").replace(" ", "_")

    def _auto_save(self):
        """Auto-save engagement state to its per-engagement directory.

        Delegates to the Engagement object's save() -- all state goes
        into data/engagements/<safe_target>/state.json. No more scattered files.
        """
        if self.state.target:
            try:
                # Keep the persisted session id in sync with the live one so a
                # restart can --resume the same Claude conversation thread.
                self.state.session_id = self._session_id
                self.state.save()
                self._engagement_mgr._set_active(self.state.target, self.state.engagement_mode)
            except Exception:
                pass

    def reset_conversation(self):
        """Clear conversation history but keep engagement state."""
        self.conversation_history = []
        self._session_id = ""
        try:
            self.state.session_id = ""
        except Exception:
            pass

    def compact_history(self, keep_last: int = 10):
        """Trim conversation history."""
        if len(self.conversation_history) > keep_last * 2:
            self.conversation_history = self.conversation_history[-(keep_last * 2):]
