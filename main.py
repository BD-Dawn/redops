#!/usr/bin/env python3
"""Red Team Agent - Interactive CLI with Sliver C2 integration."""

import argparse
import sys
import os
import time

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.theme import Theme
from rich.live import Live
from rich.spinner import Spinner
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion

# Ensure imports work regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import RedTeamAgent
from engagement import Engagement, EngagementManager, EngagementStatus
from sliver_c2 import SliverManager
from opsec import score_command, LEVEL_NAMES, LEVEL_COLORS, LEVEL_HIGH
from agents.orchestrator import Orchestrator
from pathlib import Path

class RedopsCompleter(Completer):
    """Tab completion for REDOPS slash commands."""

    # Top-level commands and their descriptions
    COMMANDS = {
        "/auto": "Autonomous agent dispatch",
        "/blitz": "Multi-target parallel CTF: /blitz <ips...> | status | stop",
        "/target": "Set engagement target",
        "/retarget": "Change target IP, keep all state (box reset): /retarget <new_ip>",
        "/scope": "Set engagement scope",
        "/roe": "Set rules of engagement",
        "/status": "Show engagement state",
        "/autonomous": "Toggle autonomous mode",
        "/ctf": "Switch to CTF mode (blocks writeups, stop at flag)",
        "/mode": "Set engagement mode: ctf | le | redteam",
        "/creds": "List discovered credentials",
        "/hosts": "List compromised hosts",
        "/addcred": "Add credential: <user> <secret> <type>",
        "/addhost": "Add host: <hostname> [ip] [level]",
        "/note": "Add a note to engagement state",
        "/c2": "Sliver C2 commands",
        "/plan": "Generate attack plan",
        "/opsec": "OPSEC log / score commands",
        "/save": "Save engagement state",
        "/load": "Switch to engagement: /load <target>",
        "/targets": "Show multi-target status table",
        "/findings": "Findings DB: summary | export | <host> | promote/note/cvss <id> | dupes | verify",
        "/engagements": "List all engagements with status",
        "/review": "Source code review: /review [path] [task]",
        "/research": "Research mode: /research <target|status|classify|bugs>",
        "/cve-sync": "Sync CVE intelligence: /cve-sync [--days N | --cve CVE-ID]",
        "/tasks": "Task ledger: add/start/done/fail/block/skip",
        "/ingest-url": "Fetch article and add to KB",
        "/report": "Review/rewrite findings, or export <platform> submission package",
        "/learn": "Learn from past engagements (retroactive RAG ingestion)",
        "/bounty": "Bounty monitor: start|stop|status|scan|filter|programs|history",
        "/quickstart": "Show the quick start guide",
        "/budget": "View or set engagement cost ceiling: /budget [amount]",
        "/fast": "Toggle fast mode (Sonnet for exploitation, Opus for planning)",
        "/verbose": "Toggle verbose progress mode",
        "/reset": "Clear conversation history",
        "/compact": "Trim old conversation history",
        "/help": "Show help",
        "/quit": "Exit",
        "/nuke": "Wipe engagement completely and start fresh: /nuke [target]",
        "/new": "Reset agent session (fresh context, keeps engagement state)",
        "/exit": "Exit",
    }

    # Subcommands for /c2
    C2_SUBCOMMANDS = {
        "start": "Start Sliver server daemon",
        "stop": "Stop Sliver server daemon",
        "status": "Full C2 status",
        "listen": "Start listener: <proto> [host] [port]",
        "jobs": "List active listeners",
        "kill": "Kill a listener: <job_id>",
        "generate": "Generate implant: <url> [options]",
        "builds": "List generated implants",
        "sessions": "List active sessions",
        "beacons": "List active beacons",
        "exec": "Execute on session: <id> <cmd>",
        "task": "Queue on beacon: <id> <cmd>",
        "screenshot": "Screenshot from session: <id>",
        "ps": "Process list from session: <id>",
        "upload": "Upload to session: <id> <local> <remote>",
        "download": "Download from session: <id> <remote>",
    }

    # Subcommands for /c2 listen
    C2_LISTEN_PROTOS = ["mtls", "http", "https", "dns", "wg"]

    # Subcommands for /auto
    AUTO_SUBCOMMANDS = {
        "recon": "Run recon agent (OSINT + scanning)",
        "exploit": "Run exploitation agent (initial access)",
        "postex": "Run post-exploitation agent",
        "chain": "Run full chain with LLM decisions + HITL",
        "triage": "Run triage agent (sonnet-powered target ranking)",
        "param_analyzer": "Run parameter analyzer (URL attack surface mapping)",
        "synthesis": "Run synthesis reasoning (combine findings into attack chains)",
        "linux_postex": "Run Linux post-exploitation (privesc, enumeration)",
        "windows_postex": "Run Windows post-exploitation (privesc, enumeration)",
        "linux_lateral": "Run Linux lateral movement (pivoting, tunneling)",
        "windows_lateral": "Run Windows/AD lateral movement (PTH, Kerberos, domain)",
        "codereview": "Run source code review agent (vuln analysis + scanners)",
        "cvehunter": "Run CVE hunter agent (CVE scanning + PoC research)",
        "continue": "Smart continuation — run synthesis, apply plan, execute (skip recon)",
        "resume": "Resume interrupted chain from checkpoint",
        "status": "Show orchestrator agent status",
        "threshold": "Set confidence threshold (0-100)",
    }

    # Subcommands for /opsec
    OPSEC_SUBCOMMANDS = {"score": "Score a command for OPSEC risk"}

    # Subcommands for /bounty
    BOUNTY_SUBCOMMANDS = {
        "start": "Start monitoring platforms for new programs/scope changes",
        "stop": "Stop monitoring",
        "status": "Show monitor status, filter, and recent activity",
        "scan": "Run one poll cycle immediately",
        "filter": "Show or update program filters",
        "programs": "List tracked programs",
        "history": "Show change detection history",
        "reset": "Clear all tracked program state",
    }

    # Subcommands for /c2 generate flags
    C2_GENERATE_FLAGS = ["--os", "--arch", "--type", "--format", "--name", "--interval", "--jitter"]

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        words = text.split()

        # Nothing typed or just starting a slash command
        if not text or (len(words) == 1 and text.startswith("/") and not text.endswith(" ")):
            prefix = words[0] if words else "/"
            for cmd, desc in self.COMMANDS.items():
                if cmd.startswith(prefix):
                    yield Completion(cmd, start_position=-len(prefix), display_meta=desc)
            return

        if not words or not words[0].startswith("/"):
            return

        base_cmd = words[0].lower()

        # /c2 subcommand completion
        if base_cmd == "/c2":
            if len(words) == 1 and text.endswith(" "):
                # Show all c2 subcommands
                for sub, desc in self.C2_SUBCOMMANDS.items():
                    yield Completion(sub, display_meta=desc)
            elif len(words) == 2 and not text.endswith(" "):
                # Partial c2 subcommand
                prefix = words[1]
                for sub, desc in self.C2_SUBCOMMANDS.items():
                    if sub.startswith(prefix):
                        yield Completion(sub, start_position=-len(prefix), display_meta=desc)
            elif len(words) >= 2:
                c2_sub = words[1].lower()
                # /c2 listen <proto>
                if c2_sub == "listen":
                    if (len(words) == 2 and text.endswith(" ")) or (len(words) == 3 and not text.endswith(" ")):
                        prefix = words[2] if len(words) == 3 else ""
                        for proto in self.C2_LISTEN_PROTOS:
                            if proto.startswith(prefix):
                                yield Completion(proto, start_position=-len(prefix))
                # /c2 generate flags
                elif c2_sub == "generate" and len(words) >= 3:
                    current = words[-1] if not text.endswith(" ") else ""
                    for flag in self.C2_GENERATE_FLAGS:
                        if flag.startswith(current) and flag not in words:
                            yield Completion(flag, start_position=-len(current))
            return

        # /auto subcommand completion
        if base_cmd == "/auto":
            if len(words) == 1 and text.endswith(" "):
                for sub, desc in self.AUTO_SUBCOMMANDS.items():
                    yield Completion(sub, display_meta=desc)
            elif len(words) == 2 and not text.endswith(" "):
                prefix = words[1]
                for sub, desc in self.AUTO_SUBCOMMANDS.items():
                    if sub.startswith(prefix):
                        yield Completion(sub, start_position=-len(prefix), display_meta=desc)
            return

        # /report subcommand completion
        if base_cmd == "/report":
            from config import FINDINGS_DIR
            if len(words) == 1 and text.endswith(" "):
                yield Completion("fix", display_meta="Rewrite findings to submission quality")
                for f in sorted(FINDINGS_DIR.glob("*.md")):
                    yield Completion(f.name, display_meta="Review this finding")
            elif len(words) == 2 and not text.endswith(" "):
                prefix = words[1]
                if "fix".startswith(prefix):
                    yield Completion("fix", start_position=-len(prefix), display_meta="Rewrite findings")
                for f in sorted(FINDINGS_DIR.glob("*.md")):
                    if f.name.startswith(prefix):
                        yield Completion(f.name, start_position=-len(prefix))
            elif len(words) == 2 and words[1] == "fix" and text.endswith(" "):
                for f in sorted(FINDINGS_DIR.glob("*.md")):
                    yield Completion(f.name, display_meta="Rewrite this finding")
            elif len(words) == 3 and words[1] == "fix" and not text.endswith(" "):
                prefix = words[2]
                for f in sorted(FINDINGS_DIR.glob("*.md")):
                    if f.name.startswith(prefix):
                        yield Completion(f.name, start_position=-len(prefix))
            return

        # /opsec subcommand completion
        if base_cmd == "/opsec":
            if len(words) == 1 and text.endswith(" "):
                for sub, desc in self.OPSEC_SUBCOMMANDS.items():
                    yield Completion(sub, display_meta=desc)
            elif len(words) == 2 and not text.endswith(" "):
                prefix = words[1]
                for sub, desc in self.OPSEC_SUBCOMMANDS.items():
                    if sub.startswith(prefix):
                        yield Completion(sub, start_position=-len(prefix), display_meta=desc)
            return

        # /bounty subcommand completion
        if base_cmd == "/bounty":
            if len(words) == 1 and text.endswith(" "):
                for sub, desc in self.BOUNTY_SUBCOMMANDS.items():
                    yield Completion(sub, display_meta=desc)
            elif len(words) == 2 and not text.endswith(" "):
                prefix = words[1]
                for sub, desc in self.BOUNTY_SUBCOMMANDS.items():
                    if sub.startswith(prefix):
                        yield Completion(sub, start_position=-len(prefix), display_meta=desc)
            elif len(words) == 2 and words[1] == "filter" and text.endswith(" "):
                for f in ("min_bounty", "paid_only", "platforms", "exclude"):
                    yield Completion(f, display_meta=f"Set {f}")
            elif len(words) == 2 and words[1] == "programs" and text.endswith(" "):
                for p in ("hackerone", "bugcrowd", "intigriti", "yeswehack"):
                    yield Completion(p, display_meta=f"Filter by {p}")
            return

        # /tasks subcommand completion
        if base_cmd == "/tasks":
            task_subs = {"add": "Add task", "start": "Start task", "done": "Complete task",
                         "fail": "Fail task", "block": "Block task", "skip": "Skip task"}
            if len(words) == 1 and text.endswith(" "):
                for sub, desc in task_subs.items():
                    yield Completion(sub, display_meta=desc)
            elif len(words) == 2 and not text.endswith(" "):
                prefix = words[1]
                for sub, desc in task_subs.items():
                    if sub.startswith(prefix):
                        yield Completion(sub, start_position=-len(prefix), display_meta=desc)
            return

        # /save and /load — complete with saved engagement names
        if base_cmd in ("/save", "/load"):
            mgr = EngagementManager()
            saved = [e["target"] for e in mgr.list_all()]
            saved = [s for s in saved if not s.startswith("_")]
            if len(words) == 1 and text.endswith(" "):
                for name in saved:
                    yield Completion(name)
            elif len(words) == 2 and not text.endswith(" "):
                prefix = words[1]
                for name in saved:
                    if name.startswith(prefix):
                        yield Completion(name, start_position=-len(prefix))
            return


theme = Theme({
    "tool.name": "bold cyan",
    "tool.cmd": "dim white",
    "warning": "bold yellow",
    "danger": "bold red",
    "success": "bold green",
    "cost": "dim cyan",
    "c2": "bold magenta",
    "verbose.agent": "bold blue",
    "verbose.cmd": "bold white",
    "verbose.output": "dim white",
    "verbose.reasoning": "dim cyan",
    "verbose.phase": "bold magenta",
    "verbose.opsec_high": "bold red",
    "verbose.opsec_low": "dim green",
    "verbose.tool": "cyan",
    "verbose.border": "dim white",
    # Engagement mode colors
    "mode.ctf": "bold red",
    "mode.le": "bold green",
    "mode.redteam": "bold magenta",
})

console = Console(theme=theme)

# Global verbose mode flag
_verbose_mode = False


def _handle_fast_query(state, user_input: str) -> str | None:
    """Handle simple state questions instantly without calling Claude.

    Returns an answer string if matched, None to fall through to the agent.
    """
    import re as _re
    q = user_input.lower().strip().rstrip("?!.")

    # Target IP
    if _re.match(r"^(what('?s| is) (the |our )?(current )?(target|engagement)( ip| address| host)?.*|"
                 r"(show|display|print) (the |our )?(current )?(target|ip).*|"
                 r"target ip|current target|what target|which target)$", q):
        if state.target:
            return f"Target: **{state.target}**"
        return "No target set. Use `/target <ip>` or start a new engagement."

    # Credentials
    if _re.match(r"^(what('?s| are) (the |our |my )?(current )?(cred|credential|password|hash|secret)s?|"
                 r"(show|list|display|print) (the |our |my )?(cred|credential|password)s?|"
                 r"what creds (do )?(we |i )have)$", q):
        if not state.credentials:
            return "No credentials stored."
        lines = ["**Credentials:**"]
        for c in state.credentials:
            lines.append(f"- `{c['username']}` : `{c['secret']}` [{c['type']}] (from {c.get('source', '?')})")
        return "\n".join(lines)

    # Compromised hosts
    if _re.match(r"^(what('?s| are) (the )?(compromised|owned|pwned) hosts?|"
                 r"(show|list) (compromised|owned|pwned) hosts?|"
                 r"what (do )?(we|i) (own|have access to))$", q):
        if not state.compromised_hosts:
            return "No compromised hosts."
        lines = ["**Compromised Hosts:**"]
        for h in state.compromised_hosts:
            lines.append(f"- {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]")
        return "\n".join(lines)

    # Defenses
    if _re.match(r"^(what('?s| are) (the )?(known )?(defense|defence|protection|security control)s?|"
                 r"(show|list) (defense|defence)s?)$", q):
        if not state.defenses:
            return "No defenses detected."
        lines = ["**Detected Defenses:**"]
        for name, val in state.defenses.items():
            if val:
                lines.append(f"- {name}")
        return "\n".join(lines)

    # Capabilities / ACLs
    if _re.match(r"^(what('?s| are) (the |our )?(current )?(capabilit|acl|permission|primitive).*|"
                 r"(show|list) (capabilit|acl|permission|primitive).*|"
                 r"what can (we|i|j\.arbuckle|l\.wilson) do)$", q):
        caps = getattr(state, "capabilities", [])
        if not caps:
            return "No capabilities/ACLs tracked."
        lines = ["**Capabilities:**"]
        for c in caps:
            lines.append(f"- **{c.get('account', '?')}** → {c.get('capability', '?')} on {c.get('target', '?')}")
        return "\n".join(lines)

    # Status / overview
    if _re.match(r"^(status|state|engagement (status|state|info|summary)|"
                 r"where (are|am) (we|i)|what('?s| is) (the )?(current )?(status|state|situation))$", q):
        return state.summary()

    # Notes
    if _re.match(r"^(what('?s| are) (the |our )?(engagement )?notes?|"
                 r"(show|list|display) (the )?(engagement )?notes?)$", q):
        if not state.notes:
            return "No notes."
        lines = ["**Notes:**"]
        for n in state.notes[-15:]:
            lines.append(f"- {n}")
        return "\n".join(lines)

    return None


def _status_line(console, name: str, enabled: bool, detail: str = ""):
    """Print a single status line for the startup dashboard."""
    if enabled:
        tag = "[success]ENABLED[/success]"
    else:
        tag = "[red]DISABLED[/red]"
    detail_str = f" [dim]({detail})[/dim]" if detail else ""
    console.print(f"  {name}: {tag}{detail_str}")

# Verbose mode progress tracking
_verbose_start_time = 0.0
_verbose_turn = 0
_verbose_cmds = 0
_verbose_agent = ""


def _verbose_progress_bar() -> str:
    """Build a compact progress line for verbose mode. Updates every second via background thread."""
    import time as _t
    elapsed = _t.monotonic() - _verbose_start_time if _verbose_start_time else 0
    elapsed_str = f"{int(elapsed // 60)}:{int(elapsed % 60):02d}"
    agent_tag = f"[{_verbose_agent}] " if _verbose_agent else ""
    turn = _verbose_turn
    max_t = 3  # AGENT_MAX_TURNS (micro-agent)
    if turn > 0:
        pct = min(int(turn / max_t * 100), 100)
        bar_filled = int(pct / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        return f"[dim]  ─── ⏱ {elapsed_str} │ {agent_tag}Turn {turn}/{max_t} [{bar}] {pct}% │ Cmds: {_verbose_cmds} ───[/dim]"
    return f"[dim]  ─── ⏱ {elapsed_str} │ {agent_tag}Thinking... │ Cmds: {_verbose_cmds} ───[/dim]"


def _render_progress_event(event: dict) -> None:
    """Render a structured progress event to the console in verbose mode.

    Event types:
        command   — A Bash command being executed (with OPSEC scoring)
        output    — Tool result / command output
        reasoning — Agent's thinking / response text
        tool_use  — Non-Bash tool invocation (Read, Glob, etc.)
        phase     — Phase transition or orchestrator decision
        error     — Error during execution
    """
    global _verbose_turn, _verbose_cmds, _verbose_agent

    etype = event.get("type", "")
    agent = event.get("agent", "?")
    _verbose_agent = agent

    # Track progress
    if etype == "output":
        _verbose_turn = event.get("turn", _verbose_turn)
    if etype == "command":
        _verbose_cmds += 1

    # The background ticker thread handles the real-time progress bar now.
    # No need to print it here — the ticker updates every 1 second.

    if etype == "command":
        cmd = event.get("command", "")
        opsec_level = event.get("opsec_level", "LOW")
        opsec_score = event.get("opsec_score", 0)
        opsec_reasons = event.get("opsec_reasons", [])

        # Color the OPSEC tag based on severity
        if opsec_score >= 3:  # HIGH/CRITICAL
            opsec_tag = f"[verbose.opsec_high][OPSEC:{opsec_level}][/verbose.opsec_high]"
        else:
            opsec_tag = f"[verbose.opsec_low][OPSEC:{opsec_level}][/verbose.opsec_low]"

        console.print(f"  [verbose.agent][{agent}][/verbose.agent] {opsec_tag} [verbose.cmd]$ {cmd}[/verbose.cmd]")
        if opsec_score >= 3 and opsec_reasons:
            for reason in opsec_reasons[:2]:
                console.print(f"         [verbose.opsec_high]^ {reason}[/verbose.opsec_high]")

    elif etype == "output":
        content = event.get("content", "")
        turn = event.get("turn", "?")
        if not content.strip():
            return
        # Truncate long output but show enough to be useful
        lines = content.strip().splitlines()
        max_lines = 25
        console.print(f"  [verbose.agent][{agent}][/verbose.agent] [dim]--- output (turn {turn}) ---[/dim]")
        for line in lines[:max_lines]:
            console.print(f"  [verbose.output]  {line}[/verbose.output]")
        if len(lines) > max_lines:
            console.print(f"  [dim]  ... ({len(lines) - max_lines} more lines)[/dim]")

    elif etype == "reasoning":
        text = event.get("text", "")
        if not text.strip():
            return
        # Show a preview of the reasoning
        lines = text.strip().splitlines()
        max_lines = 10
        console.print(f"  [verbose.agent][{agent}][/verbose.agent] [verbose.reasoning]>>> thinking:[/verbose.reasoning]")
        for line in lines[:max_lines]:
            console.print(f"  [verbose.reasoning]  {line}[/verbose.reasoning]")
        if len(lines) > max_lines:
            console.print(f"  [dim]  ... ({len(lines) - max_lines} more lines)[/dim]")

    elif etype == "tool_use":
        tool = event.get("tool", "?")
        tool_input = event.get("input", {})
        preview = ""
        if "file_path" in tool_input:
            preview = f" {tool_input['file_path']}"
        elif "pattern" in tool_input:
            preview = f" '{tool_input['pattern']}'"
        console.print(f"  [verbose.agent][{agent}][/verbose.agent] [verbose.tool]{tool}{preview}[/verbose.tool]")

    elif etype == "phase":
        text = event.get("text", "")
        task = event.get("task", "")
        console.print(f"\n  [verbose.phase]{text}[/verbose.phase]")
        if task:
            # Show first 2 lines of the task
            task_lines = task.strip().splitlines()[:2]
            for line in task_lines:
                console.print(f"  [dim]  {line}[/dim]")

    elif etype == "error":
        text = event.get("text", "")
        console.print(f"  [verbose.agent][{agent}][/verbose.agent] [danger]ERROR: {text}[/danger]")

BANNER = r"""
[red]
  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗
  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗
  ██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║
  ██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║
  ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
[/red]
[dim]  Red Team Operator Assistant | Powered by Claude Code + Sliver C2 | By |3lackdawn[/dim]
"""

HELP_TEXT = """
**Engagement Commands:**
| Command | Description |
|---|---|
| `/target <ip/range>` | Set engagement target |
| `/scope <description>` | Set engagement scope |
| `/roe <rules>` | Set rules of engagement |
| `/status` | Show engagement state |
| `/autonomous` | Toggle autonomous mode |
| `/creds` | List discovered credentials |
| `/hosts` | List compromised hosts |
| `/addcred <user> <secret> <type>` | Manually add a credential |
| `/addhost <hostname> [ip] [level]` | Manually add a compromised host |
| `/note <text>` | Add a note to engagement state |

**Sliver C2 Commands:**
| Command | Description |
|---|---|
| `/c2 start` | Start Sliver server daemon |
| `/c2 stop` | Stop Sliver server daemon |
| `/c2 status` | Full C2 status (server, listeners, sessions, beacons) |
| `/c2 listen <proto> [host] [port]` | Start a listener (mtls/http/https/dns/wg) |
| `/c2 jobs` | List active listeners |
| `/c2 kill <job_id>` | Kill a listener |
| `/c2 generate <url> [options]` | Generate implant (see below) |
| `/c2 builds` | List generated implants |
| `/c2 sessions` | List active sessions |
| `/c2 beacons` | List active beacons |
| `/c2 exec <id> <command>` | Execute command on session |
| `/c2 task <id> <command>` | Queue command on beacon |
| `/c2 screenshot <id>` | Take screenshot from session |
| `/c2 ps <id>` | List processes on session |
| `/c2 upload <id> <local> <remote>` | Upload file to session |
| `/c2 download <id> <remote>` | Download file from session |

**Generate options:** `/c2 generate mtls://10.0.0.1:8443 --os windows --arch amd64 --type beacon --format exe`

**Engagement Persistence:**
| Command | Description |
|---|---|
| `/save` | Save engagement state to disk |
| `/load <target>` | Switch to a saved engagement |
| `/engagements` | List all engagements with status/phase |
| `/tasks` | Show task ledger |
| `/tasks add <objective>` | Add a task to the ledger |
| `/tasks start <id> [agent]` | Mark task as active |
| `/tasks done <id> [result]` | Mark task as completed |
| `/tasks fail <id> [reason]` | Mark task as failed |
| `/tasks block <id> [blocker]` | Mark task as blocked |

**Autonomous Agents:**
| Command | Description |
|---|---|
| `/auto recon [task]` | Run recon agent (OSINT + scanning) |
| `/auto exploit [task]` | Run exploit agent (initial access) |
| `/auto postex [task]` | Run post-exploitation agent |
| `/auto codereview [task]` | Run code review agent (source code vuln analysis) |
| `/auto cvehunter [task]` | Run CVE hunter agent (CVE scanning + PoC research) |
| `/review [path] [focus]` | Source code review — scanners + manual audit |
| `/auto chain` | Run full chain with LLM decisions + human-in-the-loop |
| `/auto resume` | Resume an interrupted chain from last checkpoint |
| `/auto status` | Show orchestrator agent status |
| `/auto threshold <0-100>` | Set confidence threshold (below = ask operator) |

**Bounty Monitor (LE mode):**
| Command | Description |
|---|---|
| `/bounty start [interval]` | Watch platforms for new programs / scope changes |
| `/bounty stop` | Stop monitoring |
| `/bounty status` | Show monitor status and recent activity |
| `/bounty scan` | Run one poll cycle immediately |
| `/bounty filter <key> <value>` | Set filter (min_bounty, paid_only, platforms, exclude) |
| `/bounty programs [platform]` | List tracked programs |
| `/bounty history` | Show change detection history |

**Planning & OPSEC:**
| Command | Description |
|---|---|
| `/plan` | Generate attack plan based on current engagement state |
| `/report` | Review all findings for submission quality |
| `/report <file>` | Review a specific finding file |
| `/report fix` | Rewrite all findings to submission quality |
| `/report fix <file>` | Rewrite a specific finding file |
| `/opsec` | Show OPSEC log for commands executed this session |
| `/opsec score <command>` | Score a command before running it |

**General Commands:**
| Command | Description |
|---|---|
| `/verbose` | Toggle verbose progress mode (show commands, outputs, reasoning) |
| `/ingest-url <url>` | Fetch article and add to knowledge base |
| `/quickstart` | Show the quick start guide |
| `/reset` | Clear conversation history |
| `/compact` | Trim old conversation history |
| `/help` | Show this help |
| `/quit` | Exit |
"""


def handle_c2_command(c2: SliverManager, args_str: str) -> None:
    """Handle /c2 subcommands."""
    parts = args_str.strip().split()
    if not parts:
        console.print("[warning]Usage: /c2 <subcommand> — try /help for full list[/warning]")
        return

    subcmd = parts[0].lower()
    rest = parts[1:]

    if subcmd == "start":
        lhost = rest[0] if rest else "0.0.0.0"
        lport = int(rest[1]) if len(rest) > 1 else 31337
        with Live(Spinner("dots", text="[dim]Starting Sliver daemon...[/dim]"), console=console, transient=True):
            result = c2.start_server(lhost, lport)
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "stop":
        result = c2.stop_server()
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "status":
        with Live(Spinner("dots", text="[dim]Checking C2 status...[/dim]"), console=console, transient=True):
            result = c2.full_status()
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "listen":
        if not rest:
            console.print("[warning]Usage: /c2 listen <mtls|http|https|dns|wg> [host] [port][/warning]")
            return
        proto = rest[0]
        lhost = rest[1] if len(rest) > 1 else "0.0.0.0"
        lport = int(rest[2]) if len(rest) > 2 else 8443
        with Live(Spinner("dots", text=f"[dim]Starting {proto} listener...[/dim]"), console=console, transient=True):
            result = c2.start_listener(proto, lhost, lport)
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "jobs":
        result = c2.list_jobs()
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "kill":
        if not rest:
            console.print("[warning]Usage: /c2 kill <job_id>[/warning]")
            return
        result = c2.kill_job(int(rest[0]))
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "generate":
        if not rest:
            console.print("[warning]Usage: /c2 generate <proto://host:port> [--os windows] [--arch amd64] [--type beacon] [--format exe] [--name myimplant] [--interval 60] [--jitter 30][/warning]")
            return
        url = rest[0]
        # Parse optional flags
        opts = {"os_target": "windows", "arch": "amd64", "implant_type": "beacon",
                "format": "exe", "name": "", "interval": 60, "jitter": 30}
        i = 1
        while i < len(rest):
            flag = rest[i].lstrip("-")
            val = rest[i + 1] if i + 1 < len(rest) else ""
            if flag == "os":
                opts["os_target"] = val; i += 2
            elif flag == "arch":
                opts["arch"] = val; i += 2
            elif flag == "type":
                opts["implant_type"] = val; i += 2
            elif flag == "format":
                opts["format"] = val; i += 2
            elif flag == "name":
                opts["name"] = val; i += 2
            elif flag == "interval":
                opts["interval"] = int(val); i += 2
            elif flag == "jitter":
                opts["jitter"] = int(val); i += 2
            else:
                i += 1

        console.print(f"[dim]Generating {opts['implant_type']} implant for {opts['os_target']}/{opts['arch']}...[/dim]")
        with Live(Spinner("dots", text="[dim]Compiling implant (this may take a few minutes)...[/dim]"), console=console, transient=True):
            result = c2.generate_implant(url, **opts)
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "builds":
        result = c2.list_implant_builds()
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "sessions":
        result = c2.list_sessions()
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "beacons":
        result = c2.list_beacons()
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "exec":
        if len(rest) < 2:
            console.print("[warning]Usage: /c2 exec <session_id> <command>[/warning]")
            return
        sid = rest[0]
        cmd = " ".join(rest[1:])
        with Live(Spinner("dots", text=f"[dim]Executing on {sid[:8]}...[/dim]"), console=console, transient=True):
            result = c2.interact_session(sid, cmd)
        console.print(result)

    elif subcmd == "task":
        if len(rest) < 2:
            console.print("[warning]Usage: /c2 task <beacon_id> <command>[/warning]")
            return
        bid = rest[0]
        cmd = " ".join(rest[1:])
        result = c2.interact_beacon(bid, cmd)
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "screenshot":
        if not rest:
            console.print("[warning]Usage: /c2 screenshot <session_id>[/warning]")
            return
        result = c2.session_screenshot(rest[0])
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "ps":
        if not rest:
            console.print("[warning]Usage: /c2 ps <session_id>[/warning]")
            return
        with Live(Spinner("dots", text="[dim]Listing processes...[/dim]"), console=console, transient=True):
            result = c2.session_ps(rest[0])
        console.print(result)

    elif subcmd == "upload":
        if len(rest) < 3:
            console.print("[warning]Usage: /c2 upload <session_id> <local_path> <remote_path>[/warning]")
            return
        result = c2.session_upload(rest[0], rest[1], rest[2])
        console.print(f"[c2]{result}[/c2]")

    elif subcmd == "download":
        if len(rest) < 2:
            console.print("[warning]Usage: /c2 download <session_id> <remote_path>[/warning]")
            return
        result = c2.session_download(rest[0], rest[1])
        console.print(f"[c2]{result}[/c2]")

    else:
        console.print(f"[warning]Unknown C2 command: {subcmd}. Try /help[/warning]")


def _handle_ingest_url(url: str) -> None:
    """Fetch a URL, save as article, and incrementally ingest into ChromaDB."""
    import re
    import subprocess
    import claude_client
    from config import ARTICLES_DIR, MODEL_FAST
    from ingest import ingest_incremental

    console.print(f"[dim]Fetching: {url}[/dim]")

    # Use claude to fetch and extract the article content
    try:
        result = claude_client.oneshot(
            (
                f"Fetch this URL and return the full article content in clean markdown. "
                f"Include all sections, technical details, commands, code blocks, and specifics. "
                f"Do not summarize. URL: {url}"
            ),
            model=MODEL_FAST, timeout=120,
        )
        if result.returncode != 0 or not result.stdout.strip():
            console.print(f"[danger]Failed to fetch URL: {result.stderr[:300]}[/danger]")
            return
        content = result.stdout.strip()
    except Exception as e:
        console.print(f"[danger]Error fetching URL: {e}[/danger]")
        return

    # Generate filename from URL
    slug = url.split("/")[-1][:80]
    slug = re.sub(r'[^a-zA-Z0-9_-]', '_', slug).strip("_").lower()
    if not slug:
        slug = "article"
    filename = f"{slug}.md"
    filepath = ARTICLES_DIR / filename

    # Prepend source URL
    content = f"**Source:** {url}\n\n{content}"
    filepath.write_text(content)
    console.print(f"[success]Saved: {filepath}[/success]")

    # Incremental ingest
    console.print("[dim]Ingesting into knowledge base...[/dim]")
    ingest_incremental(filepath)


def _handle_opsec(agent: RedTeamAgent, arg: str) -> None:
    """Handle /opsec command — show log or score a command."""
    parts = arg.strip().split(maxsplit=1)

    if parts and parts[0] == "score" and len(parts) > 1:
        # Score a specific command
        cmd_to_score = parts[1]
        result = score_command(cmd_to_score)
        color = LEVEL_COLORS.get(result.score, "white")
        console.print(f"[{color}][OPSEC: {result.level_name}][/{color}] {cmd_to_score}")
        for reason in result.reasons:
            console.print(f"  [dim]-[/dim] {reason}")
        if result.alternatives:
            console.print("  [dim]Alternatives:[/dim]")
            for alt in result.alternatives:
                console.print(f"    [success]->[/success] {alt}")
        return

    # Show OPSEC log
    if not agent.opsec_log:
        console.print("[dim]No commands scored yet this session.[/dim]")
        return

    console.print("[bold]OPSEC Log[/bold]\n")
    for entry in agent.opsec_log:
        level = entry["level"]
        score = entry["score"]
        color = LEVEL_COLORS.get(score, "white")
        console.print(f"  [{color}]{level:8}[/{color}] {entry['command']}")
        for reason in entry["reasons"]:
            console.print(f"           [dim]- {reason}[/dim]")

    # Summary
    from collections import Counter
    counts = Counter(e["level"] for e in agent.opsec_log)
    summary_parts = []
    for level_val, level_name in sorted(LEVEL_NAMES.items()):
        cnt = counts.get(level_name, 0)
        if cnt:
            color = LEVEL_COLORS[level_val]
            summary_parts.append(f"[{color}]{level_name}: {cnt}[/{color}]")
    console.print(f"\n  Total: {len(agent.opsec_log)} commands — {', '.join(summary_parts)}")


def _handle_plan(agent: RedTeamAgent) -> None:
    """Generate an attack plan based on current engagement state."""
    import subprocess
    import claude_client
    from config import MODEL

    if not agent.state.target:
        console.print("[warning]Set a target first with /target <ip/range>[/warning]")
        return

    console.print("[dim]Generating attack plan...[/dim]")

    # Build a detailed planning prompt from engagement state
    state_info = agent.state.summary()

    # Retrieve relevant knowledge base context
    from retriever import KnowledgeBase
    kb_context = ""
    try:
        kb = KnowledgeBase()
        # Query based on current state to get relevant techniques
        queries = []
        if agent.state.compromised_hosts:
            access_levels = set(h["access_level"] for h in agent.state.compromised_hosts)
            if "SYSTEM" in access_levels or "admin" in access_levels:
                queries.append("post-exploitation privilege escalation lateral movement domain admin")
            else:
                queries.append("privilege escalation windows local admin")
        if agent.state.credentials:
            queries.append("credential reuse lateral movement pass the hash kerberos")
        if not agent.state.compromised_hosts:
            queries.append("initial access reconnaissance enumeration external")

        all_hits = []
        seen = set()
        _scope = getattr(agent.state, "engagement_id", None)
        for q in queries:
            for hit in kb.multi_search(q, n_results=4, scope=_scope):
                key = hit["text"][:120]
                if key not in seen:
                    seen.add(key)
                    all_hits.append(hit)

        if all_hits:
            all_hits.sort(key=lambda h: h["distance"] or 0)
            kb_context = kb.format_context(all_hits[:8])
    except Exception:
        pass

    plan_prompt = f"""You are a red team engagement planner. Based on the current engagement state, generate a prioritized attack plan.

## Current Engagement State
{state_info}

## Rules of Engagement
{agent.state.roe or 'Standard rules — no denial of service, stay in scope'}

"""
    if kb_context:
        plan_prompt += f"""## Relevant Techniques
{kb_context}

"""
    plan_prompt += """## Instructions
Generate a structured attack plan with:
1. **Current Position Assessment** — Where are we in the kill chain?
2. **Immediate Next Steps** (1-3 actions) — What to do right now, with exact commands
3. **Medium-Term Objectives** (3-5 actions) — After immediate steps succeed
4. **Stretch Goals** — If everything goes well
5. **OPSEC Considerations** — What to watch out for

For each action, include:
- The technique name and MITRE ATT&CK ID if applicable
- The exact command(s) to run
- OPSEC risk level (LOW/MEDIUM/HIGH/CRITICAL)
- What success looks like

## Scanning Strategy
For port scanning, always plan TCP scanning first (fast, actionable results) and UDP scanning in the background (slow, run with & and check later). Never block the engagement waiting for UDP — process TCP results and continue the kill chain immediately while UDP runs.

Be specific and actionable — this is a working plan, not a textbook."""

    try:
        result = claude_client.oneshot(
            plan_prompt, model=MODEL, max_turns=None, timeout=300,
        )
        if result.returncode == 0 and result.stdout.strip():
            console.print()
            console.print(Markdown(result.stdout.strip()))
        else:
            # Build a detailed error message from all available output
            error_detail = result.stderr.strip() or result.stdout.strip() or "no output"
            console.print(f"[danger]Plan generation failed (exit code {result.returncode}): {error_detail[:500]}[/danger]")
    except subprocess.TimeoutExpired:
        console.print("[danger]Plan generation timed out (300s limit). Try narrowing the scope or simplifying the engagement state.[/danger]")
    except Exception as e:
        console.print(f"[danger]Plan generation error: {type(e).__name__}: {e}[/danger]")


def _handle_report(orchestrator: Orchestrator, arg: str) -> None:
    """Handle /report command — review or rewrite findings for submission quality.

    Usage:
        /report                     Review all findings in findings/ directory
        /report <filename>          Review a specific finding file
        /report fix                 Rewrite all findings to submission quality
        /report fix <filename>      Rewrite a specific finding file
        /report export [platform]   Export reportable findings (hackerone|bugcrowd|generic)
    """
    from config import FINDINGS_DIR

    parts = arg.strip().split(maxsplit=1)
    subcmd = parts[0].lower() if parts else ""
    target_file = ""
    mode = "review"

    # Deterministic submission package from the findings DB (reportable only)
    if subcmd == "export":
        from findings_db import FindingsDB
        platform = (parts[1].strip().lower() if len(parts) > 1 else "generic") or "generic"
        db = FindingsDB()
        package = db.export_for_platform(platform)
        out_path = FINDINGS_DIR / f"submission_{platform}.md"
        try:
            FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
            out_path.write_text(package)
            console.print(f"[success]Submission package written: {out_path}[/success]")
        except Exception as e:
            console.print(f"[warning]Could not write file ({e}) — printing instead.[/warning]")
        console.print(Markdown(package))
        return

    if subcmd == "fix":
        mode = "rewrite"
        target_file = parts[1].strip() if len(parts) > 1 else ""
    elif subcmd:
        target_file = subcmd

    # Build the file list
    if target_file:
        # Specific file
        finding_path = FINDINGS_DIR / target_file
        if not finding_path.exists():
            # Try adding .md extension
            finding_path = FINDINGS_DIR / f"{target_file}.md"
        if not finding_path.exists():
            console.print(f"[danger]Finding not found: {target_file}[/danger]")
            console.print(f"[dim]Available findings in {FINDINGS_DIR}:[/dim]")
            for f in sorted(FINDINGS_DIR.glob("*.md")):
                console.print(f"  - {f.name}")
            return
        finding_files = [finding_path]
    else:
        # All findings
        finding_files = sorted(FINDINGS_DIR.glob("*.md"))
        if not finding_files:
            console.print("[dim]No findings in findings/ directory.[/dim]")
            return

    # Build the task prompt
    file_list = "\n".join(f"- {f}" for f in finding_files)
    if mode == "rewrite":
        task = (
            f"REWRITE MODE: Read each finding file, apply all quality checks, fix every issue, "
            f"and write the corrected version back to the same file path. Make them submission-ready.\n\n"
            f"Finding files to process:\n{file_list}"
        )
    else:
        task = (
            f"REVIEW MODE: Read each finding file and output a structured quality assessment. "
            f"Do NOT modify the files — just report issues found.\n\n"
            f"Finding files to review:\n{file_list}"
        )

    console.print(f"[dim]Report agent ({mode} mode): processing {len(finding_files)} finding(s)...[/dim]")

    def on_status(msg):
        console.print(f"  [dim]{msg}[/dim]")

    def on_progress(event):
        if _verbose_mode and event.get("type") == "assistant":
            text = event.get("text", "")
            if text:
                console.print(f"  [dim]{text[:200]}[/dim]")

    try:
        output = orchestrator.dispatch(
            "report", task,
            on_status=on_status,
            on_progress=on_progress,
            summarize=False,
            max_turns=len(finding_files) * 4 + 2,  # ~4 turns per finding
        )
        if output:
            console.print()
            console.print(Markdown(output))
    except Exception as e:
        console.print(f"[danger]Report agent error: {type(e).__name__}: {e}[/danger]")


def _handle_findings(agent: RedTeamAgent, arg: str) -> None:
    """Handle /findings command — query, triage, and verify the findings database.

    Usage:
        /findings                 Triage summary (reportable / awaiting-PoC / notes)
        /findings export          Full triaged markdown report
        /findings <host>          Findings for a host
        /findings promote <id>    Force a finding into the report (operator override)
        /findings note <id>       Force a finding to notes / demote (operator override)
        /findings cvss <id> <vec> Attach a CVSS 3.1 vector to a finding
        /findings dupes           Show likely duplicate clusters
        /findings verify          Dispatch the agent to PoC material findings (the gate)
        /findings clear           Wipe the findings database
    """
    from findings_db import FindingsDB
    db = FindingsDB()

    parts = arg.strip().split(maxsplit=1)
    subcmd = parts[0].lower() if parts else ""
    rest = parts[1].strip() if len(parts) > 1 else ""

    sev_color = {"critical": "danger", "high": "warning", "medium": "yellow",
                 "low": "dim", "info": "dim"}

    if subcmd == "export":
        console.print(Markdown(db.export_markdown()))

    elif subcmd == "clear":
        db.clear()
        console.print("[success]Findings database cleared.[/success]")

    elif subcmd in ("promote", "note", "demote"):
        override = "promote" if subcmd == "promote" else "demote"
        try:
            fid = int(rest.split()[0])
        except (ValueError, IndexError):
            console.print(f"[warning]Usage: /findings {subcmd} <id>[/warning]")
            return
        if db.set_report_override(fid, override):
            verb = "promoted into report" if override == "promote" else "moved to notes"
            console.print(f"[success]Finding #{fid} {verb}.[/success]")
        else:
            console.print(f"[danger]No finding with id {fid}.[/danger]")

    elif subcmd == "cvss":
        bits = rest.split(maxsplit=1)
        if len(bits) < 2:
            console.print("[warning]Usage: /findings cvss <id> <CVSS:3.1/...>[/warning]")
            return
        try:
            fid = int(bits[0])
        except ValueError:
            console.print("[warning]Finding id must be a number.[/warning]")
            return
        if db.set_cvss(fid, bits[1]):
            console.print(f"[success]CVSS vector set on finding #{fid}.[/success]")
        else:
            console.print(f"[danger]No finding with id {fid}.[/danger]")

    elif subcmd == "dupes":
        clusters = db.potential_duplicates()
        if not clusters:
            console.print("[dim]No likely duplicates detected.[/dim]")
            return
        console.print(f"[warning]{len(clusters)} possible duplicate cluster(s):[/warning]")
        for cl in clusters:
            console.print(f"  [dim]on {cl[0]['host']}:[/dim]")
            for f in cl:
                console.print(f"    #{f['id']} [{f['severity'].upper()}] {f['title'] or f['finding_type']}")

    elif subcmd == "verify":
        _verify_findings_poc(agent, db)

    elif subcmd:
        # Treat as a host filter — show id + disposition
        findings = db._all_with_disposition(host=subcmd)
        if findings:
            console.print(f"[dim]Findings for {subcmd}: {len(findings)}[/dim]")
            for f in findings:
                port_str = f":{f['port']}" if f['port'] else ""
                col = sev_color.get(f['severity'], "dim")
                disp = {"reportable": "[green]REPORT[/green]",
                        "needs_poc": "[yellow]NEEDS-POC[/yellow]",
                        "noted": "[dim]note[/dim]"}.get(f["disposition"], "")
                console.print(
                    f"  #{f['id']} [{col}][{f['severity'].upper()}][/{col}] {disp} "
                    f"{f['host']}{port_str} — {f['title'] or f['finding_type']}"
                )
        else:
            console.print(f"[dim]No findings for {subcmd}.[/dim]")

    else:
        # Triage summary
        total = db.count()
        if not total:
            console.print("[dim]No findings recorded yet.[/dim]")
            return
        reportable = db.reportable_findings()
        needs = db.needs_poc()
        noted = db.noted_findings()
        console.print(
            f"[dim]Findings: {total} total[/dim]  "
            f"[green]{len(reportable)} reportable[/green] · "
            f"[yellow]{len(needs)} awaiting PoC[/yellow] · "
            f"[dim]{len(noted)} notes[/dim]"
        )
        if reportable:
            console.print("\n[green]Reportable (material + proven PoC):[/green]")
            for f in reportable:
                col = sev_color.get(f['severity'], "dim")
                console.print(f"  #{f['id']} [{col}][{f['severity'].upper()}][/{col}] "
                              f"{f['host']} — {f['title'] or f['finding_type']}")
        if needs:
            console.print("\n[yellow]Awaiting PoC (held back by the gate — /findings verify):[/yellow]")
            for f in needs:
                col = sev_color.get(f['severity'], "dim")
                console.print(f"  #{f['id']} [{col}][{f['severity'].upper()}][/{col}] "
                              f"{f['host']} — {f['title'] or f['finding_type']}")
        if noted:
            console.print(f"\n[dim]Notes / low-hanging fruit: {len(noted)} "
                          f"(/findings promote <id> to elevate)[/dim]")


def _verify_findings_poc(agent: RedTeamAgent, db) -> None:
    """Dispatch the agent to attempt a PoC for each material finding stuck at the gate.

    The agent reproduces each, then records the result back to the findings DB so
    confirmed findings become reportable. This is the active half of the PoC gate.
    """
    queue = db.needs_poc()
    if not queue:
        console.print("[success]Nothing awaiting PoC — all material findings are proven.[/success]")
        return

    listing = "\n".join(
        f"- id={f['id']} [{f['severity'].upper()}] {f['host']}"
        f"{(':' + str(f['port'])) if f['port'] else ''} — {f['title'] or f['finding_type']}"
        f"\n  {(f['description'] or '')[:200]}"
        for f in queue
    )
    db_path = db._db_path
    task = (
        "PoC VERIFICATION PASS. The following MATERIAL findings are recorded but unproven. "
        "For each, attempt a reproducible proof-of-concept against the in-scope target. "
        "Stay strictly in scope.\n\n"
        f"{listing}\n\n"
        "For EACH finding, after testing, update its status in the findings database by running:\n"
        "```\n"
        f"python3 -c \"import sys; sys.path.insert(0,'.'); from findings_db import FindingsDB, PocStatus; "
        f"db=FindingsDB(); db.update_poc(<id>, PocStatus.CONFIRMED, poc_script='<exact reproduce command>')\"\n"
        "```\n"
        "Use PocStatus.CONFIRMED only if you reproduced it yourself. Use PocStatus.UNCONFIRMED if you "
        "could not, or PocStatus.MANUAL with poc_instructions if it needs manual/browser steps. "
        "Be honest — do not mark CONFIRMED without a working PoC.\n"
        f"(The findings DB is at: {db_path})"
    )

    console.print(f"[dim]Dispatching PoC verification for {len(queue)} finding(s)...[/dim]")

    def on_status(msg):
        if _verbose_mode:
            console.print(f"  [dim]{msg}[/dim]")

    try:
        output = agent.chat(task, on_status=on_status)
        if output:
            console.print(Markdown(output))
    except Exception as e:
        console.print(f"[danger]Verification error: {type(e).__name__}: {e}[/danger]")

    # Re-report the gate after verification
    remaining = db.needs_poc()
    newly = len(queue) - len(remaining)
    console.print(f"\n[success]Verification pass complete.[/success] "
                  f"[green]{newly} newly proven[/green], [yellow]{len(remaining)} still pending[/yellow].")


def _handle_cve_sync(arg: str, console) -> None:
    """Handle /cve-sync command — fetch CVE intelligence and PoCs."""
    from cve_feed import sync_all, sync_single_cve, ingest_to_rag

    def _status(msg):
        console.print(f"[dim]{msg}[/dim]")

    parts = arg.strip().split()

    # /cve-sync --cve CVE-2025-0927
    if "--cve" in parts:
        idx = parts.index("--cve")
        if idx + 1 < len(parts):
            cve_id = parts[idx + 1].upper()
            record = sync_single_cve(cve_id, on_status=_status)
            if record:
                console.print(f"\n[bold]{record.cve_id}[/bold]: {record.description[:200]}")
                if record.cvss_score:
                    sev_color = "red" if record.severity == "critical" else "yellow" if record.severity == "high" else "dim"
                    console.print(f"  CVSS: [{sev_color}]{record.cvss_score} ({record.severity.upper()})[/{sev_color}]")
                if record.exploited_in_wild:
                    console.print("  [red bold]ACTIVELY EXPLOITED IN THE WILD (CISA KEV)[/red bold]")
                if record.tags:
                    console.print(f"  Tags: {', '.join(record.tags)}")
                if record.poc_sources:
                    console.print(f"  [green]PoCs ({len(record.poc_sources)}):[/green]")
                    for src in record.poc_sources:
                        stars = f" ({src['stars']}★)" if src.get("stars") else ""
                        local = f" → {src['local_path']}" if src.get("local_path") else ""
                        console.print(f"    [{src['type']}] {src.get('url', '')}{stars}{local}")
                else:
                    console.print("  [dim]No PoCs found[/dim]")

                # Ingest into RAG
                ingest_to_rag([record], on_status=_status)
            else:
                console.print(f"[dim]No data found for {cve_id}[/dim]")
            return

    # /cve-sync --days N
    days = 7
    if "--days" in parts:
        idx = parts.index("--days")
        if idx + 1 < len(parts):
            try:
                days = int(parts[idx + 1])
            except ValueError:
                pass

    # Full sync
    console.print(f"[bold]Syncing CVE intelligence (last {days} days)...[/bold]")
    summary = sync_all(days=days, download_pocs=True, on_status=_status)

    # Display results
    records = summary.get("records", [])
    if not records:
        console.print("[dim]No CVEs found.[/dim]")
        return

    # Group by severity
    critical = [r for r in records if r.severity == "critical"]
    high = [r for r in records if r.severity == "high"]
    exploited = [r for r in records if r.exploited_in_wild]
    with_poc = [r for r in records if r.poc_available]

    console.print(f"\n[bold]CVE Sync Summary[/bold]")
    console.print(f"  Total: {len(records)} CVEs")
    console.print(f"  [red]Critical: {len(critical)}[/red]")
    console.print(f"  [yellow]High: {len(high)}[/yellow]")
    console.print(f"  [red bold]Exploited in wild: {len(exploited)}[/red bold]")
    console.print(f"  [green]With PoC: {len(with_poc)}[/green]")
    console.print(f"  Downloaded: {summary.get('pocs_downloaded', 0)} PoCs")

    # Show top exploited + PoC available
    hot = [r for r in records if r.exploited_in_wild and r.poc_available]
    if hot:
        console.print(f"\n[red bold]HOT — Exploited + PoC Available:[/red bold]")
        for r in hot[:10]:
            console.print(f"  {r.cve_id} | CVSS {r.cvss_score} | {r.description[:80]}")
            for src in r.poc_sources[:2]:
                local = f" → {src.get('local_path', '')}" if src.get("local_path") else ""
                console.print(f"    [green][{src['type']}] {src.get('url', '')}{local}[/green]")

    # Show critical without PoC (research targets)
    no_poc_crit = [r for r in critical if not r.poc_available]
    if no_poc_crit:
        console.print(f"\n[yellow]Critical without known PoC (research opportunity):[/yellow]")
        for r in no_poc_crit[:5]:
            console.print(f"  {r.cve_id} | CVSS {r.cvss_score} | {r.description[:80]}")

    # Ingest into RAG
    ingested = ingest_to_rag(records, on_status=_status)
    console.print(f"\n[dim]{ingested} CVEs ingested into knowledge base[/dim]")


def _handle_review(orchestrator, agent: RedTeamAgent, arg: str) -> None:
    """Handle /review command — source code security review.

    Usage:
      /review                       Review code found during engagement
      /review /path/to/source       Review specific directory or file
      /review /path custom task     Review path with custom focus
    """
    import threading
    from rich.live import Live
    from rich.spinner import Spinner

    parts = arg.strip().split(maxsplit=1) if arg.strip() else []
    target_path = parts[0] if parts else ""
    custom_focus = parts[1] if len(parts) > 1 else ""

    # Build the review task
    task_parts = []
    if target_path:
        task_parts.append(f"Review source code at: {target_path}")
        task_parts.append(f"This is a targeted source code security audit of {target_path}.")
    else:
        task_parts.append(f"Review all source code discovered during the engagement against: {agent.state.target}")

    if custom_focus:
        task_parts.append(f"\nFocus area: {custom_focus}")

    task_parts.append("\nRun automated scanners (Semgrep, Bandit, Trufflehog) first, then manual review.")
    task_parts.append("Report all findings with exact file:line locations and exploitation steps.")
    task_parts.append(f"Save findings to {agent.state.evidence_dir}/codereview_findings.md")

    task = "\n".join(task_parts)

    console.print(f"[bold cyan]Source Code Review[/bold cyan]")
    if target_path:
        console.print(f"  Target: {target_path}")
    else:
        console.print(f"  Target: engagement artifacts for {agent.state.target}")
    if custom_focus:
        console.print(f"  Focus: {custom_focus}")
    console.print()

    spinner = Spinner("dots", text="Running source code review agent...")
    _stop = threading.Event()

    def on_status(msg: str):
        spinner.update(text=msg)

    def on_progress(line: str):
        try:
            spinner.update(text=line[:120])
        except Exception:
            pass

    with Live(spinner, console=console, refresh_per_second=4):
        result = orchestrator.run_codereview(
            task=task, on_status=on_status, on_progress=on_progress
        )

    console.print()
    console.print(Markdown(result))
    console.print(f"\n[dim]Findings saved to {agent.state.evidence_dir}/codereview_findings.md[/dim]")


def _handle_research(agent: RedTeamAgent, arg: str, console) -> None:
    """Handle /research command — vulnerability research management."""
    from research_engagement import ResearchEngagement, format_bug
    from agents.target_classifier import classify_target, classify_with_llm

    parts = arg.strip().split(maxsplit=1)
    subcmd = parts[0].lower() if parts else ""
    subarg = parts[1] if len(parts) > 1 else ""

    # Store research engagement on the agent for cross-command access
    if not hasattr(agent, "_research"):
        agent._research = None

    if subcmd == "target" and subarg:
        # Classify a new target
        console.print(f"[dim]Classifying target: {subarg}[/dim]")
        profile = classify_target(subarg)
        if not profile.target_type:
            console.print(f"[danger]Could not classify target: {subarg}[/danger]")
            return

        console.print(f"  Type: [bold]{profile.target_type}[/bold]")
        console.print(f"  Language: {profile.language or 'n/a'}")
        console.print(f"  Arch: {profile.arch or 'n/a'}")
        console.print(f"  Files: {profile.file_count} | LOC: {profile.estimated_loc}")
        console.print(f"  Build: {profile.build_system or 'n/a'}")
        console.print(f"  Pipeline: {' → '.join(profile.recommended_pipeline)}")

        # Ask LLM for entry points (background enhancement)
        import os
        try:
            listing = ""
            from pathlib import Path
            p = Path(subarg)
            if p.is_dir():
                # Get file listing for LLM
                import subprocess
                result = subprocess.run(
                    ["find", str(p), "-type", "f", "-name", "*.c", "-o",
                     "-name", "*.h", "-o", "-name", "*.py", "-o",
                     "-name", "*.php", "-o", "-name", "*.js"],
                    capture_output=True, text=True, timeout=5,
                )
                listing = result.stdout[:3000]
            console.print("[dim]Analyzing attack surface...[/dim]")
            profile = classify_with_llm(profile, listing)
            if profile.entry_points:
                console.print(f"  Entry points: {', '.join(profile.entry_points[:8])}")
        except Exception:
            pass

        # Create research engagement
        target_name = os.path.basename(subarg.rstrip("/"))
        r = ResearchEngagement(target_name, subarg)
        r.profile = profile
        r.pipeline = profile.recommended_pipeline
        r.current_phase = "classify"
        r.completed_phases = ["classify"]
        r.save()
        agent._research = r
        console.print(f"\n[bold magenta]Research engagement created: {target_name}[/bold magenta]")
        console.print(f"[dim]State: {r.state_path}[/dim]")

    elif subcmd == "status":
        # Show dashboard
        r = agent._research
        if not r:
            # Try loading from research directory
            from config import ENGAGEMENTS_DIR
            research_dir = ENGAGEMENTS_DIR / "research"
            if research_dir.exists():
                targets = [d for d in research_dir.iterdir() if d.is_dir() and (d / "state.json").exists()]
                if targets:
                    # Load most recent
                    latest = max(targets, key=lambda d: d.stat().st_mtime)
                    r = ResearchEngagement(latest.name)
                    r.load()
                    agent._research = r
        if not r:
            console.print("[dim]No active research engagement. Use: /research target <path>[/dim]")
            return
        console.print(f"\n[bold magenta]RESEARCH DASHBOARD[/bold magenta]")
        console.print(r.dashboard_display())

    elif subcmd == "bugs":
        # List all bugs
        r = agent._research
        if not r:
            console.print("[dim]No active research engagement.[/dim]")
            return
        if not r.bug_candidates and not r.confirmed_bugs:
            console.print("[dim]No bugs found yet.[/dim]")
            return
        if r.confirmed_bugs:
            console.print("\n[bold green]CONFIRMED[/bold green]")
            for bug in r.confirmed_bugs:
                console.print(format_bug(bug))
                console.print()
        candidates = [b for b in r.bug_candidates if b["status"] == "candidate"]
        if candidates:
            console.print("[bold yellow]CANDIDATES[/bold yellow]")
            for bug in candidates:
                console.print(format_bug(bug))
                console.print()
        fps = [b for b in r.bug_candidates if b["status"] == "false_positive"]
        if fps:
            console.print(f"[dim]{len(fps)} false positives filtered.[/dim]")

    elif subcmd == "crashes":
        r = agent._research
        if not r:
            console.print("[dim]No active research engagement.[/dim]")
            return
        if not r.crash_corpus:
            console.print("[dim]No crashes collected yet.[/dim]")
            return
        by_expl = r.crashes_by_exploitability()
        console.print(f"\n[bold]CRASH CORPUS[/bold]: {len(r.crash_corpus)} total, {r.unique_crashes()} unique")
        for level, count in sorted(by_expl.items(), key=lambda x: -x[1]):
            color = "green" if level == "weaponizable" else "yellow" if level == "promising" else "dim"
            console.print(f"  [{color}]{level}: {count}[/{color}]")

    elif subcmd == "run" and subarg:
        # Full pipeline run
        from agents.research_orchestrator import ResearchOrchestrator

        # Create or load engagement
        r = agent._research
        if not r or r.target_path != subarg:
            target_name = os.path.basename(subarg.rstrip("/"))
            r = ResearchEngagement(target_name, subarg)
            if r.state_path.exists():
                r.load()
            agent._research = r

        orch = ResearchOrchestrator(r, autonomous=True)

        def _status(msg):
            console.print(f"[dim]{msg}[/dim]")

        def _confirm(msg):
            console.print(f"\n[bold yellow]{msg}[/bold yellow]")
            resp = input("  [y/N] > ").strip().lower()
            return resp in ("y", "yes")

        try:
            summary = orch.run(
                target_path=subarg,
                on_status=_status,
                on_confirm=_confirm,
            )
            console.print(f"\n[bold magenta]RESULTS[/bold magenta]")
            console.print(r.dashboard_display())
        except KeyboardInterrupt:
            console.print("\n[dim]Pipeline interrupted. Use /research resume to continue.[/dim]")

    elif subcmd == "resume":
        # Resume from last checkpoint
        from agents.research_orchestrator import ResearchOrchestrator

        r = agent._research
        if not r:
            # Find most recent research engagement
            from config import ENGAGEMENTS_DIR
            research_dir = ENGAGEMENTS_DIR / "research"
            if research_dir.exists():
                targets = [d for d in research_dir.iterdir()
                           if d.is_dir() and (d / "state.json").exists()]
                if targets:
                    latest = max(targets, key=lambda d: d.stat().st_mtime)
                    r = ResearchEngagement(latest.name)
                    r.load()
                    agent._research = r

        if not r:
            console.print("[dim]No research engagement to resume.[/dim]")
            return

        console.print(f"[bold magenta]Resuming: {r.target_name}[/bold magenta]")
        console.print(f"[dim]Completed phases: {', '.join(r.completed_phases) or 'none'}[/dim]")

        orch = ResearchOrchestrator(r, autonomous=True)

        def _status(msg):
            console.print(f"[dim]{msg}[/dim]")

        try:
            summary = orch.run(on_status=_status, on_confirm=lambda msg: True)
            console.print(f"\n[bold magenta]RESULTS[/bold magenta]")
            console.print(r.dashboard_display())
        except KeyboardInterrupt:
            console.print("\n[dim]Pipeline interrupted.[/dim]")

    elif subcmd == "phase" and subarg:
        # Run a single phase
        from agents.research_orchestrator import ResearchOrchestrator

        r = agent._research
        if not r:
            console.print("[dim]No active research engagement. Use /research target or /research run first.[/dim]")
            return

        orch = ResearchOrchestrator(r, autonomous=True)

        def _status(msg):
            console.print(f"[dim]{msg}[/dim]")

        phase_name = subarg.strip().lower()
        console.print(f"[bold magenta]Running phase: {phase_name}[/bold magenta]")
        success = orch.run_phase(phase_name, on_status=_status)
        if success:
            console.print(f"\n[bold magenta]DASHBOARD[/bold magenta]")
            console.print(r.dashboard_display())
        else:
            console.print(f"[dim]Phase {phase_name} did not complete successfully.[/dim]")

    elif subcmd == "classify" and subarg:
        # Quick classify without creating engagement
        profile = classify_target(subarg)
        console.print(f"  Type: {profile.target_type}")
        console.print(f"  Language: {profile.language or 'n/a'}")
        console.print(f"  Arch: {profile.arch or 'n/a'}")
        console.print(f"  Files: {profile.file_count} | LOC: {profile.estimated_loc}")
        console.print(f"  Pipeline: {' → '.join(profile.recommended_pipeline)}")

    else:
        console.print("[bold magenta]Research Mode Commands:[/bold magenta]")
        console.print("  /research target <path>    — Classify target and create engagement")
        console.print("  /research run <path>       — Run full pipeline (auto-detects kernel targets)")
        console.print("  /research resume           — Resume interrupted pipeline")
        console.print("  /research phase <name>     — Run single phase:")
        console.print("    [dim]classify, audit, re, fuzz, triage, poc, variant, syzkaller, patch_diff[/dim]")
        console.print("  /research status           — Show dashboard")
        console.print("  /research bugs             — List bugs (candidates + confirmed)")
        console.print("  /research crashes          — Show crash corpus summary")
        console.print("  /research classify <path>  — Quick classify without engagement")
        console.print("")
        console.print("  [dim]Kernel targets auto-detected: adds syzkaller + patch_differ to pipeline[/dim]")


def _handle_tasks(agent: RedTeamAgent, arg: str) -> None:
    """Handle /tasks command — manage the engagement task ledger."""
    ledger = agent.state.task_ledger
    parts = arg.strip().split(maxsplit=1)
    subcmd = parts[0].lower() if parts else ""
    rest = parts[1] if len(parts) > 1 else ""

    if subcmd == "add":
        if not rest:
            console.print("[warning]Usage: /tasks add <objective>[/warning]")
            return
        task = ledger.add(rest)
        agent.state.save()
        console.print(f"[success]Task {task.id} created: {task.objective}[/success]")

    elif subcmd == "start":
        if not rest:
            console.print("[warning]Usage: /tasks start <task_id> [agent][/warning]")
            return
        tid_parts = rest.split(maxsplit=1)
        tid = tid_parts[0].upper()
        ag = tid_parts[1] if len(tid_parts) > 1 else ""
        task = ledger.start(tid, ag)
        if task:
            agent.state.save()
            console.print(f"[success]{tid} -> active{' [' + ag + ']' if ag else ''}[/success]")
        else:
            console.print(f"[danger]Task {tid} not found.[/danger]")

    elif subcmd == "done":
        if not rest:
            console.print("[warning]Usage: /tasks done <task_id> [result][/warning]")
            return
        tid_parts = rest.split(maxsplit=1)
        tid = tid_parts[0].upper()
        result = tid_parts[1] if len(tid_parts) > 1 else ""
        task = ledger.complete(tid, result)
        if task:
            agent.state.save()
            console.print(f"[success]{tid} -> completed[/success]")
        else:
            console.print(f"[danger]Task {tid} not found.[/danger]")

    elif subcmd == "fail":
        if not rest:
            console.print("[warning]Usage: /tasks fail <task_id> [reason][/warning]")
            return
        tid_parts = rest.split(maxsplit=1)
        tid = tid_parts[0].upper()
        reason = tid_parts[1] if len(tid_parts) > 1 else ""
        task = ledger.fail(tid, reason)
        if task:
            agent.state.save()
            console.print(f"[danger]{tid} -> failed[/danger]")
        else:
            console.print(f"[danger]Task {tid} not found.[/danger]")

    elif subcmd == "block":
        if not rest:
            console.print("[warning]Usage: /tasks block <task_id> [blocker][/warning]")
            return
        tid_parts = rest.split(maxsplit=1)
        tid = tid_parts[0].upper()
        blocker = tid_parts[1] if len(tid_parts) > 1 else ""
        task = ledger.block(tid, blocker)
        if task:
            agent.state.save()
            console.print(f"[warning]{tid} -> blocked ({blocker})[/warning]")
        else:
            console.print(f"[danger]Task {tid} not found.[/danger]")

    elif subcmd == "skip":
        if not rest:
            console.print("[warning]Usage: /tasks skip <task_id>[/warning]")
            return
        tid = rest.split()[0].upper()
        task = ledger.update(tid, status="skipped")
        if task:
            agent.state.save()
            console.print(f"[dim]{tid} -> skipped[/dim]")
        else:
            console.print(f"[danger]Task {tid} not found.[/danger]")

    else:
        # Default: show full ledger
        summary = ledger.summary()
        if summary:
            console.print(Markdown(summary))
        else:
            console.print("[dim]No tasks. Use /tasks add <objective> to create one.[/dim]")


def _handle_bounty(orchestrator: Orchestrator, agent: "RedTeamAgent", arg: str) -> None:
    """Handle /bounty subcommands for bug bounty platform monitoring."""
    parts = arg.strip().split(maxsplit=1)
    subcmd = parts[0].lower() if parts else ""
    rest = parts[1] if len(parts) > 1 else ""

    # Lazy-init bounty monitor
    if not orchestrator.bounty_monitor:
        def _bounty_status(msg):
            console.print(f"[dim]{msg}[/dim]")

        def _on_new_engagement(program, targets):
            """Auto-create LE engagement and dispatch recon for new program/scope."""
            primary_target = targets[0]
            console.print(f"\n[bold yellow]>>> AUTO-ENGAGE: {program.name}[/bold yellow]")
            console.print(f"[dim]  Platform: {program.platform} | URL: {program.url}[/dim]")
            console.print(f"[dim]  Targets: {', '.join(targets[:10])}[/dim]")
            console.print(f"[dim]  Bounty: up to ${program.bounty_max:.0f}[/dim]")

            # Create a new LE engagement for the primary target
            mgr = agent._engagement_mgr
            eng = mgr.create(primary_target, "le")

            # Set all targets as scope
            scope_text = "\n".join(targets)
            eng.set_target(primary_target, scope=scope_text)
            eng.save()

            console.print(
                f"[success]  Created LE engagement: {primary_target} "
                f"({len(targets)} targets in scope)[/success]"
            )

            # Build a recon orchestrator for this engagement and dispatch
            recon_orch = Orchestrator(eng, autonomous=True)
            task = (
                f"NEW BUG BOUNTY PROGRAM — first-mover recon.\n\n"
                f"Program: {program.name} ({program.platform})\n"
                f"URL: {program.url}\n"
                f"Bounty: up to ${program.bounty_max:.0f}\n\n"
                f"Targets in scope:\n"
                + "\n".join(f"- {t}" for t in targets) +
                f"\n\nPriority: this is a NEWLY LISTED program. Speed matters — "
                f"other hunters are racing to find bugs. Run fast recon:\n"
                f"1. Port scan all targets (top 1000, fast)\n"
                f"2. Subdomain enumeration on all domains\n"
                f"3. Web technology fingerprinting\n"
                f"4. Directory/endpoint discovery on web targets\n"
                f"5. Check for common misconfigurations and low-hanging fruit\n"
                f"6. Identify interesting parameters and input points\n\n"
                f"Save all findings to the evidence directory. "
                f"Focus on breadth first, depth second."
            )
            console.print("[dim]  Dispatching recon agent...[/dim]")
            result = recon_orch.dispatch(
                "recon", task,
                on_status=_bounty_status,
            )
            if result:
                # Save a summary
                summary_lines = [
                    f"# Auto-Recon: {program.name}",
                    f"Platform: {program.platform}",
                    f"Discovered: {__import__('datetime').datetime.now().isoformat()[:19]}",
                    f"Targets: {', '.join(targets)}",
                    "",
                    "## Recon Output",
                    result[:3000],
                ]
                summary_path = eng.evidence_dir / f"auto_recon_{program.handle}.md"
                summary_path.write_text("\n".join(summary_lines))
                console.print(
                    f"[success]  Recon complete — saved to {summary_path.name}[/success]"
                )

        orchestrator.setup_bounty_monitor(
            on_status=_bounty_status,
            on_new_engagement=_on_new_engagement,
        )

    bm = orchestrator.bounty_monitor

    if subcmd == "start":
        interval = None
        if rest:
            try:
                interval = int(rest)
            except ValueError:
                m = __import__("re").match(r"^(\d+)\s*m(?:in)?$", rest)
                if m:
                    interval = int(m.group(1)) * 60
                else:
                    console.print("[warning]Usage: /bounty start [interval_seconds | Nm][/warning]")
                    return
        bm.start(interval=interval)
        console.print(
            f"[success]Bounty monitor started — polling every "
            f"{bm._interval}s ({bm._interval // 60}m)[/success]"
        )
        console.print(
            f"[dim]  Platforms: {', '.join(bm.bounty_filter.platforms)} | "
            f"Paid only: {bm.bounty_filter.paid_only} | "
            f"Min bounty: ${bm.bounty_filter.min_bounty:.0f}[/dim]"
        )
        console.print(
            "[dim]  New programs auto-create LE engagements and dispatch recon.[/dim]"
        )

    elif subcmd == "stop":
        bm.stop()
        console.print(f"[success]Bounty monitor stopped.[/success]")

    elif subcmd == "status":
        console.print(Markdown(bm.status()))

    elif subcmd == "scan":
        console.print("[dim]Running one poll cycle...[/dim]")
        import time as _time
        start = _time.monotonic()
        delta = bm.run_cycle()
        elapsed = _time.monotonic() - start
        console.print(f"[success]Poll complete in {elapsed:.1f}s[/success]")
        if delta.has_changes:
            console.print(f"[warning]{delta.summary()}[/warning]")
        else:
            console.print(f"[dim]No changes. {bm.program_count} programs tracked.[/dim]")

    elif subcmd == "filter":
        if not rest:
            f = bm.bounty_filter
            console.print(Markdown(
                f"## Bounty Filter\n"
                f"- **min_bounty:** ${f.min_bounty:.0f}\n"
                f"- **paid_only:** {f.paid_only}\n"
                f"- **platforms:** {', '.join(f.platforms)}\n"
                f"- **asset_types:** {', '.join(f.asset_types)}\n"
                f"- **exclude:** {', '.join(f.exclude_handles) or 'none'}\n\n"
                f"Set with: `/bounty filter <key> <value>`"
            ))
            return

        filter_parts = rest.split(maxsplit=1)
        key = filter_parts[0].lower()
        val = filter_parts[1] if len(filter_parts) > 1 else ""

        if key == "min_bounty":
            try:
                bm.bounty_filter.min_bounty = float(val)
                bm.save_filter()
                console.print(f"[success]min_bounty set to ${bm.bounty_filter.min_bounty:.0f}[/success]")
            except ValueError:
                console.print("[warning]Usage: /bounty filter min_bounty <amount>[/warning]")
        elif key == "paid_only":
            bm.bounty_filter.paid_only = val.lower() in ("true", "1", "yes", "on")
            bm.save_filter()
            console.print(f"[success]paid_only set to {bm.bounty_filter.paid_only}[/success]")
        elif key == "platforms":
            bm.bounty_filter.platforms = [p.strip() for p in val.split(",") if p.strip()]
            bm.save_filter()
            console.print(f"[success]platforms set to {', '.join(bm.bounty_filter.platforms)}[/success]")
        elif key == "exclude":
            if val.startswith("+"):
                handle = val[1:].strip()
                if handle not in bm.bounty_filter.exclude_handles:
                    bm.bounty_filter.exclude_handles.append(handle)
                console.print(f"[success]Added {handle} to exclusion list[/success]")
            elif val.startswith("-"):
                handle = val[1:].strip()
                bm.bounty_filter.exclude_handles = [
                    h for h in bm.bounty_filter.exclude_handles if h != handle
                ]
                console.print(f"[success]Removed {handle} from exclusion list[/success]")
            else:
                bm.bounty_filter.exclude_handles = [h.strip() for h in val.split(",") if h.strip()]
                console.print(f"[success]Exclusion list set[/success]")
            bm.save_filter()
        else:
            console.print(f"[warning]Unknown filter key: {key}. Use: min_bounty, paid_only, platforms, exclude[/warning]")

    elif subcmd == "programs":
        platform = rest.strip().lower() if rest else ""
        progs = bm.list_programs(platform=platform, limit=30)
        if not progs:
            msg = f"No programs tracked" + (f" for {platform}" if platform else "")
            console.print(f"[dim]{msg}. Run /bounty scan first.[/dim]")
        else:
            lines = [f"## Tracked Programs ({len(progs)} shown)", ""]
            lines.append("| Program | Platform | Bounty | Targets | First Seen |")
            lines.append("|---------|----------|--------|---------|------------|")
            for p in progs:
                bounty = f"${p.bounty_max:.0f}" if p.bounty_max else "VDP"
                targets = len(p.web_targets)
                first = p.first_seen[:10] if p.first_seen else "?"
                lines.append(f"| {p.name[:30]} | {p.platform} | {bounty} | {targets} | {first} |")
            console.print(Markdown("\n".join(lines)))

    elif subcmd == "history":
        if bm._history_path.exists():
            try:
                import json as _json
                history = _json.loads(bm._history_path.read_text())
                if history:
                    lines = ["## Bounty Monitor History", ""]
                    for entry in reversed(history[-20:]):
                        ts = entry["timestamp"][:16]
                        new_progs = entry.get("new_programs", [])
                        scope_exps = entry.get("scope_expansions", [])
                        parts = []
                        if new_progs:
                            names = ", ".join(p["name"] for p in new_progs[:3])
                            parts.append(f"+{len(new_progs)} new ({names})")
                        if scope_exps:
                            names = ", ".join(e["name"] for e in scope_exps[:3])
                            parts.append(f"+{len(scope_exps)} scope ({names})")
                        if parts:
                            lines.append(f"- [{ts}] {'; '.join(parts)}")
                    console.print(Markdown("\n".join(lines)))
                else:
                    console.print("[dim]No changes recorded yet.[/dim]")
            except Exception as e:
                console.print(f"[danger]Error: {e}[/danger]")
        else:
            console.print("[dim]No history yet. Run /bounty scan or /bounty start first.[/dim]")

    elif subcmd == "reset":
        from prompt_toolkit import prompt as pt_prompt
        from prompt_toolkit.formatted_text import HTML
        try:
            confirm = pt_prompt(
                HTML('<yellow>Reset all tracked program state? Type "yes": </yellow>')
            ).strip()
        except (KeyboardInterrupt, EOFError):
            confirm = ""
        if confirm.lower() == "yes":
            bm.reset()
            console.print("[success]Bounty monitor state cleared.[/success]")
        else:
            console.print("[dim]Cancelled.[/dim]")

    else:
        console.print(Markdown(
            "## /bounty — Bug Bounty Platform Monitor\n\n"
            "Watches HackerOne, Bugcrowd, and other platforms for new programs\n"
            "and scope expansions. Auto-creates LE engagements and dispatches\n"
            "recon on qualifying changes.\n\n"
            "| Command | Description |\n"
            "|---------|-------------|\n"
            "| `/bounty start [interval]` | Start monitoring (default: 5m) |\n"
            "| `/bounty stop` | Stop monitoring |\n"
            "| `/bounty status` | Show status and recent activity |\n"
            "| `/bounty scan` | Run one poll cycle now |\n"
            "| `/bounty filter <key> <val>` | Set filter (min_bounty, paid_only, platforms, exclude) |\n"
            "| `/bounty programs [platform]` | List tracked programs |\n"
            "| `/bounty history` | Show change detection history |\n"
            "| `/bounty reset` | Clear all tracked state |\n\n"
            "**Data sources:** bounty-targets-data (all platforms, 30m updates),\n"
            "HackerOne API (real-time, set H1_API_USERNAME + H1_API_TOKEN),\n"
            "Bugcrowd public API.\n\n"
            "**Filter examples:**\n"
            "```\n"
            "/bounty filter min_bounty 500\n"
            "/bounty filter paid_only true\n"
            "/bounty filter platforms hackerone,bugcrowd\n"
            "/bounty filter exclude +google    (add to exclusion list)\n"
            "/bounty filter exclude -google    (remove from exclusion list)\n"
            "```"
        ))


def _handle_auto(orchestrator: Orchestrator, arg: str) -> None:
    """Handle /auto subcommands for autonomous agent dispatch."""
    parts = arg.strip().split(maxsplit=1)
    if not parts:
        console.print("[warning]Usage: /auto <recon|exploit|postex|codereview|chain|status|threshold> [task][/warning]")
        return

    subcmd = parts[0].lower()
    custom_task = parts[1] if len(parts) > 1 else ""

    # Status doesn't need a target
    if subcmd == "status":
        console.print(Markdown(orchestrator.status()))
        return

    # Threshold adjustment
    if subcmd == "threshold":
        if custom_task:
            try:
                val = int(custom_task)
                orchestrator.confidence_threshold = max(0, min(100, val))
                # Update the module-level default too
                import agents.orchestrator as orch_mod
                orch_mod.DEFAULT_CONFIDENCE_THRESHOLD = orchestrator.confidence_threshold
                console.print(f"[success]Confidence threshold set to {orchestrator.confidence_threshold}%[/success]")
            except ValueError:
                console.print("[warning]Usage: /auto threshold <0-100>[/warning]")
        else:
            console.print(f"[dim]Current confidence threshold: {orchestrator.confidence_threshold}%[/dim]")
        return

    if not orchestrator.state.target:
        console.print("[warning]Set a target first with /target <ip/range>[/warning]")
        return

    # Wire up human-in-the-loop: the orchestrator calls this when it needs operator input
    def ask_operator(prompt_text: str) -> str:
        """Pause autonomous execution and ask the operator for guidance."""
        console.print()
        console.print(Markdown(prompt_text))
        console.print()
        try:
            from prompt_toolkit import prompt as pt_prompt
            answer = pt_prompt(HTML('<yellow>[orchestrator] &gt; </yellow>'))
            return answer.strip()
        except (KeyboardInterrupt, EOFError):
            return "stop"

    orchestrator.ask_operator = ask_operator

    # Verbose mode: show real-time progress instead of just a spinner
    verbose = _verbose_mode

    # Spinner for status updates (paused during operator prompts)
    spinner = Spinner("dots", text=f"[dim][orchestrator] Starting {subcmd}...[/dim]")
    live = Live(spinner, console=console, transient=True)

    _auto_turn = [0]
    _auto_cmds = [0]
    _auto_agent = [subcmd]
    _auto_last_cmd = [""]

    def on_status(msg):
        # ALWAYS track progress — the background ticker needs these counters
        # Track progress from status messages
        if "Turn " in msg:
            try:
                parts = msg.split("Turn ")[1].split("...")
                turn_parts = parts[0].split("/")
                _auto_turn[0] = int(turn_parts[0])
            except (ValueError, IndexError):
                pass
        if "Running: " in msg:
            _auto_cmds[0] += 1
            _auto_last_cmd[0] = msg.split("Running: ", 1)[-1][:50]
        if "Dispatching to " in msg:
            try:
                _auto_agent[0] = msg.split("Dispatching to ")[1].split(" ")[0]
                _auto_turn[0] = 0
            except IndexError:
                pass

        if verbose:
            return  # In verbose mode, background ticker handles display

        # Restart live display if stopped for operator input
        if not live.is_started:
            live.start()

        # Build rich status bar
        elapsed = time.monotonic() - start_time
        elapsed_str = f"{int(elapsed // 60)}:{int(elapsed % 60):02d}"
        turn = _auto_turn[0]

        if turn > 0:
            max_t = 3  # AGENT_MAX_TURNS (micro-agent)
            pct = min(int(turn / max_t * 100), 100)
            bar_filled = int(pct / 5)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            status_line = (
                f"[dim]⏱ {elapsed_str} │ [{_auto_agent[0]}] Turn {turn}/{max_t} "
                f"[{bar}] {pct}% │ Cmds: {_auto_cmds[0]}[/dim]"
            )
            if _auto_last_cmd[0]:
                status_line += f" [dim]│ {_auto_last_cmd[0]}[/dim]"
        else:
            status_line = f"[dim]⏱ {elapsed_str} │ {msg}[/dim]"

        spinner.update(text=status_line)
        live.refresh()

    on_progress = _render_progress_event if verbose else None

    # Wrap ask_operator to pause the spinner
    original_ask = ask_operator
    def ask_with_spinner_pause(prompt_text: str) -> str:
        if live.is_started:
            live.stop()
        result = original_ask(prompt_text)
        return result

    orchestrator.ask_operator = ask_with_spinner_pause

    # Early exit checks for /auto continue
    if subcmd == "continue":
        _state = orchestrator.state

        # Check 1: Already solved?
        _rp = (_state.resume_point or "").upper()
        _any_solved = any("SOLVED" in n.upper() for n in _state.notes) if _state.notes else False
        if (_state.engagement_mode == "ctf" and
                ("SOLVED" in _rp or "OBJECTIVE COMPLETE" in _rp or _any_solved)):
            import re as _re
            console.print(f"\n[success]  ENGAGEMENT SOLVED — {_state.target}[/success]")
            _flags = _re.findall(r'[a-f0-9]{32}', _state.resume_point or "")
            if _flags:
                console.print(f"[success]  Flags: {', '.join(_flags)}[/success]")
            console.print(f"[dim]  Start a new engagement: /new <target_ip>[/dim]\n")
            return

        # Note: fresh target detection is handled at the caller level
        # (routes to interactive agent instead of orchestrator)

    # Reset verbose progress tracking for /auto
    global _verbose_start_time, _verbose_turn, _verbose_cmds, _verbose_agent
    _verbose_start_time = time.monotonic()
    _verbose_turn = 0
    _verbose_cmds = 0
    _verbose_agent = subcmd

    if verbose:
        console.print(f"\n  [verbose.phase]--- verbose mode: showing live progress for /{subcmd} ---[/verbose.phase]\n")
    else:
        live.start()

    start_time = time.monotonic()

    # Background timer thread: refreshes progress display every 1 second
    import threading
    _auto_refresh_stop = threading.Event()

    # For verbose mode: dedicated Live ticker that overwrites in-place
    if verbose:
        _auto_verbose_spinner = Spinner("dots", text="[dim]Starting...[/dim]")
        _auto_verbose_ticker = Live(_auto_verbose_spinner, console=console, transient=True)
        _auto_verbose_ticker.start()
    else:
        _auto_verbose_ticker = None

    def _auto_refresh_loop():
        while not _auto_refresh_stop.is_set():
            _auto_refresh_stop.wait(1.0)
            if _auto_refresh_stop.is_set():
                break
            elapsed = time.monotonic() - start_time
            elapsed_str = f"{int(elapsed // 60)}:{int(elapsed % 60):02d}"
            turn = _auto_turn[0]
            max_t = 3  # AGENT_MAX_TURNS (micro-agent)

            if turn > 0:
                pct = min(int(turn / max_t * 100), 100)
                bar_filled = int(pct / 5)
                bar = "█" * bar_filled + "░" * (20 - bar_filled)
                line = (
                    f"[dim]⏱ {elapsed_str} │ [{_auto_agent[0]}] Turn {turn}/{max_t} "
                    f"[{bar}] {pct}% │ Cmds: {_auto_cmds[0]}[/dim]"
                )
            else:
                line = f"[dim]⏱ {elapsed_str} │ [{_auto_agent[0]}] Thinking... │ Cmds: {_auto_cmds[0]}[/dim]"

            try:
                if verbose and _auto_verbose_ticker:
                    _auto_verbose_spinner.update(text=line)
                    _auto_verbose_ticker.refresh()
                elif not verbose:
                    spinner.update(text=line)
                    live.refresh()
            except Exception:
                pass

    _auto_refresh_thread = threading.Thread(target=_auto_refresh_loop, daemon=True)
    _auto_refresh_thread.start()

    try:
        if subcmd == "recon":
            result = orchestrator.run_recon(task=custom_task, on_status=on_status, on_progress=on_progress)
        elif subcmd == "exploit":
            result = orchestrator.run_exploit(task=custom_task, on_status=on_status, on_progress=on_progress)
        elif subcmd == "postex":
            result = orchestrator.run_postex(task=custom_task, on_status=on_status, on_progress=on_progress)
        elif subcmd == "codereview":
            result = orchestrator.run_codereview(task=custom_task, on_status=on_status, on_progress=on_progress)
        elif subcmd == "cvehunter":
            result = orchestrator.run_cvehunter(task=custom_task, on_status=on_status, on_progress=on_progress)
        elif subcmd == "triage":
            result = orchestrator.dispatch(
                "triage",
                f"Analyze and rank targets from recon data for: {orchestrator.state.target}",
                on_status=on_status, on_progress=on_progress, summarize=False, max_turns=3,
            )
            orchestrator._apply_triage_rankings(result, on_status)
        elif subcmd == "param_analyzer":
            recon_data = ""
            if orchestrator.recon.results:
                recon_data = orchestrator.recon.results[-1].get("summary") or orchestrator.recon.results[-1]["response"][:8000]
            task = custom_task or (
                f"Analyze the following recon output for {orchestrator.state.target}. "
                f"Extract all endpoints, parameters, and form fields. "
                f"Map each to likely attack vectors and produce a prioritized test plan.\n\n"
                f"{recon_data}"
            )
            result = orchestrator.dispatch(
                "param_analyzer", task,
                on_status=on_status, on_progress=on_progress, summarize=False,
            )
        elif subcmd == "synthesis":
            state = orchestrator.state
            # Use the rich synthesis_context() method — structured by category
            # with defenses as hard blocklist, dead ends separated, etc.
            synth_context = state.synthesis_context()
            if orchestrator.attack_plan.objective:
                synth_context += f"\n\n## CURRENT ATTACK PLAN\n{orchestrator.attack_plan.for_prompt()}"
            # Include lessons from previous synthesis failures
            if orchestrator.attack_plan.lessons:
                synth_context += "\n\n## PREVIOUS LESSONS (do NOT repeat these failures)\n"
                synth_context += "\n".join(f"- {l}" for l in orchestrator.attack_plan.lessons)
            result = orchestrator.dispatch(
                "synthesis", synth_context,
                on_status=on_status, on_progress=on_progress,
                summarize=False,
            )
        elif subcmd in ("linux_postex", "windows_postex", "linux_lateral", "windows_lateral"):
            task = custom_task or f"Post-exploitation on {orchestrator.state.target}"
            result = orchestrator.dispatch(
                subcmd, task,
                on_status=on_status, on_progress=on_progress,
            )
        elif subcmd == "continue":
            # Check if engagement is already solved (CTF mode)
            state = orchestrator.state
            _resume = (state.resume_point or "").upper()
            _notes_check = " ".join(state.notes[-5:]).upper() if state.notes else ""
            _is_solved = (
                state.engagement_mode == "ctf" and
                ("SOLVED" in _resume or "OBJECTIVE COMPLETE" in _resume or
                 "SOLVED" in _notes_check or "FLAGS CAPTURED" in _notes_check)
            )
            if _is_solved:
                console.print(f"\n[success]  ENGAGEMENT SOLVED — {state.target}[/success]")
                # Extract flags from resume_point or notes
                import re as _re
                _flags = _re.findall(r'[a-f0-9]{32}', state.resume_point or "")
                if _flags:
                    console.print(f"[success]  Flags: {', '.join(_flags)}[/success]")
                console.print(f"[dim]  Start a new engagement: /new <target_ip>[/dim]\n")
                return True

            # Smart continuation: run synthesis first, then execute the chain
            # Skips recon/triage/param_analyzer — assumes engagement already has findings
            if on_status:
                on_status("[orchestrator] Continuing engagement — running synthesis first...")
            synth_context = state.synthesis_context()
            if orchestrator.attack_plan.objective:
                synth_context += f"\n\n## CURRENT ATTACK PLAN\n{orchestrator.attack_plan.for_prompt()}"
            if orchestrator.attack_plan.lessons:
                synth_context += "\n\n## PREVIOUS LESSONS (do NOT repeat these failures)\n"
                synth_context += "\n".join(f"- {l}" for l in orchestrator.attack_plan.lessons)
            synth_output = orchestrator.dispatch(
                "synthesis", synth_context,
                on_status=on_status, on_progress=on_progress, summarize=False,
            )
            # Apply synthesis results to plan
            plan_rewritten = orchestrator.attack_plan.apply_synthesis(synth_output, on_status=on_status)
            if plan_rewritten:
                if on_status:
                    on_status("[orchestrator] Synthesis plan applied — executing chain...")
            else:
                # Generate a plan from existing state if synthesis didn't produce HIGH chains
                orchestrator.attack_plan.generate(state, on_status=on_status)
                if on_status:
                    on_status("[orchestrator] No HIGH synthesis chain — using generated plan...")
            # If synthesis produced HIGH chains with commands, execute them directly
            synth_cmds = orchestrator.attack_plan.get_synthesis_commands()
            if synth_cmds and plan_rewritten:
                # Chain execution mode — bypass batch planner entirely
                for cmd_task in synth_cmds:
                    if on_status:
                        on_status(f"[orchestrator] CHAIN EXEC: {cmd_task['agent']} — executing full chain...")
                    result = orchestrator.execute_chain(
                        chain_name="synthesis",
                        validation_commands=orchestrator.attack_plan.paths[0].get("validation_commands", []) if orchestrator.attack_plan.paths else [],
                        execution_commands=orchestrator.attack_plan.paths[0].get("execution_commands", orchestrator.attack_plan.paths[0].get("commands", [])) if orchestrator.attack_plan.paths else [],
                        agent_name=cmd_task["agent"],
                        on_status=on_status,
                        on_progress=on_progress,
                    )
            else:
                # No HIGH chain — fall back to batch planning
                # Create synthetic checkpoint so run_chain skips to micro-dispatch loop
                import json as _json
                from datetime import datetime
                synthetic_checkpoint = {
                    "current_phase": "exploit",
                    "iteration": 0,
                    "completed_phases": ["recon", "noise_filter", "triage", "param_analyzer", "cvehunter", "exploit"],
                    "phase_summaries": {
                        "recon": "(continued from existing engagement)",
                        "noise_filter": "(skipped)",
                        "triage": "(skipped)",
                        "param_analyzer": "(skipped)",
                        "cvehunter": "(skipped)",
                        "exploit": "(skipped — no synthesis chain)",
                    },
                    "current_output_preview": "Continuing without synthesis chain",
                    "phase_log": [],
                    "decisions": [],
                    "target": orchestrator.state.target,
                    "time": datetime.now().isoformat(),
                }
                orchestrator._CHECKPOINT_PATH.write_text(_json.dumps(synthetic_checkpoint, indent=2))
                result = orchestrator.run_chain(on_status=on_status, on_progress=on_progress, resume=True)
        elif subcmd in ("chain", "resume"):
            is_resume = subcmd == "resume"
            result = orchestrator.run_chain(on_status=on_status, on_progress=on_progress, resume=is_resume)
        else:
            if not verbose:
                live.stop()
            console.print(f"[warning]Unknown auto command: {subcmd}. Use: recon, exploit, linux_postex, windows_postex, linux_lateral, windows_lateral, postex, codereview, cvehunter, triage, param_analyzer, synthesis, chain, continue, resume, status, threshold[/warning]")
            return
    except KeyboardInterrupt:
        _auto_refresh_stop.set()
        _auto_refresh_thread.join(timeout=2)
        if _auto_verbose_ticker and _auto_verbose_ticker.is_started:
            _auto_verbose_ticker.stop()
        elapsed = time.monotonic() - start_time
        elapsed_str = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        if live.is_started:
            live.stop()
        # Persist engagement state so discoveries survive the interrupt
        try:
            orchestrator.state.save()
        except Exception:
            pass
        console.print(f"\n[warning]Interrupted after {elapsed_str}. Progress has been checkpointed.[/warning]")
        console.print("[dim]  You can provide context or corrections, then '/auto resume' to continue.[/dim]")
        return
    finally:
        _auto_refresh_stop.set()
        _auto_refresh_thread.join(timeout=2)
        if _auto_verbose_ticker and _auto_verbose_ticker.is_started:
            _auto_verbose_ticker.stop()
        if live.is_started:
            live.stop()

    elapsed = time.monotonic() - start_time
    elapsed_str = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"

    if result:
        console.print()
        console.print(Markdown(result))

        # Show aggregate cost and elapsed time
        total_cost = sum(a._last_cost for a in orchestrator._agents.values())
        total_turns = sum(a._last_turns for a in orchestrator._agents.values())
        console.print(f"\n[cost]  {elapsed_str} elapsed | ${total_cost:.4f} | {total_turns} turn(s)[/cost]")

        # Show OPSEC summary
        all_high = []
        for a in orchestrator._agents.values():
            all_high.extend(e for e in a.opsec_log if e["score"] >= LEVEL_HIGH)
        if all_high:
            console.print(f"\n[warning]  {len(all_high)} HIGH/CRITICAL OPSEC commands across all agents[/warning]")

    console.print()


def handle_command(agent: RedTeamAgent, c2: SliverManager, orchestrator: Orchestrator, cmd: str) -> bool:
    """Handle slash commands. Returns True if command was handled."""
    parts = cmd.strip().split(maxsplit=1)
    command = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if command in ("/quit", "/exit"):
        # Clean up bounty monitor if running
        if orchestrator.bounty_monitor and orchestrator.bounty_monitor.is_running():
            orchestrator.bounty_monitor.stop()
        # Clean up C2 if running
        if c2.daemon.is_running():
            console.print("[dim]Stopping Sliver daemon...[/dim]")
            c2.stop_server()
        console.print("\n[dim]Exiting REDOPS. Stay stealthy.[/dim]")
        sys.exit(0)

    elif command == "/help":
        console.print(Markdown(HELP_TEXT))

    elif command == "/nuke":
        target = arg.strip() if arg else (agent.state.target if agent.state.target else "")
        if not target:
            console.print("[warning]Usage: /nuke [target_ip][/warning]")
            console.print("[dim]  Completely wipes an engagement — all state, evidence, findings, notes, and agent sessions.[/dim]")
            console.print("[dim]  Without an argument, nukes the current engagement.[/dim]")
        else:
            # Confirm before destroying data
            console.print(f"[warning]This will permanently delete ALL data for {target}:[/warning]")
            console.print(f"[dim]  - State (credentials, capabilities, notes, defenses)[/dim]")
            console.print(f"[dim]  - Evidence files[/dim]")
            console.print(f"[dim]  - Findings database[/dim]")
            console.print(f"[dim]  - Attack plan and checkpoints[/dim]")
            console.print(f"[dim]  - Agent sessions and stuck detector state[/dim]")
            try:
                from prompt_toolkit import prompt as pt_prompt
                from prompt_toolkit.formatted_text import HTML
                confirm = pt_prompt(HTML(f'<yellow>Type "yes" to confirm: </yellow>')).strip()
            except (KeyboardInterrupt, EOFError):
                confirm = ""
            if confirm.lower() != "yes":
                console.print("[dim]  Cancelled.[/dim]")
            else:
                from engagement import Engagement
                deleted = Engagement.nuke(target)
                # Clean /etc/hosts with sudo (nuke method can't write without it)
                import subprocess as _sp
                try:
                    _sp.run(
                        ["sudo", "sed", "-i", f"/{target}/d", "/etc/hosts"],
                        capture_output=True, timeout=5
                    )
                    deleted.append("/etc/hosts (sudo cleanup)")
                except Exception:
                    pass
                # Reset agent state if we just nuked the current engagement
                if target == agent.state.target:
                    agent.state = Engagement(target, agent.state.engagement_mode)
                    agent.reset_for_new_engagement()
                    orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                    agent.orchestrator = orchestrator
                console.print(f"[success]Nuked engagement: {target} ({len(deleted)} items deleted)[/success]")
                console.print(f"[dim]  Use '/new {target}' or type a message with the target IP to start fresh.[/dim]")

    elif command == "/new":
        if arg.strip():
            # /new <target> — create a completely fresh engagement via EngagementManager
            new_target = arg.strip()
            old_mode = agent.state.engagement_mode
            _mgr = agent._engagement_mgr
            eng = _mgr.create(new_target, old_mode)
            agent.state = eng
            agent.reset_for_new_engagement()
            orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
            agent.orchestrator = orchestrator
            import config as _cfg
            _cfg.EVIDENCE_DIR = agent.state.evidence_dir
            console.print(f"[success]New engagement: {new_target} — clean slate, fully isolated.[/success]")
        else:
            # /new with no target — just reset session, keep state
            agent._session_id = ""
            agent.conversation_history = []
            console.print("[success]Session reset — fresh agent context. Engagement state preserved.[/success]")

    elif command == "/auto":
        _handle_auto(orchestrator, arg)

    elif command == "/c2":
        handle_c2_command(c2, arg)

    elif command == "/retarget":
        if not arg:
            console.print("[warning]Usage: /retarget <new_ip>[/warning]")
            console.print("[dim]  Changes the target IP while keeping all engagement state (creds, ACLs, notes, evidence).[/dim]")
            console.print("[dim]  Use when a box resets and gets a new IP.[/dim]")
        elif not agent.state.target:
            console.print("[warning]No active engagement to retarget.[/warning]")
        else:
            old_ip = agent.state.target
            _new = arg.strip()
            agent.state.retarget(_new)
            agent._session_id = ""
            agent.conversation_history = []
            # Set resume point so agent picks up where it left off
            if not agent.state.resume_point:
                _resume_parts = []
                if agent.state.phases.current:
                    _resume_parts.append(f"Phase: {agent.state.phases.current.value}")
                if agent.state.credentials:
                    _resume_parts.append(f"{len(agent.state.credentials)} creds")
                if agent.state.compromised_hosts:
                    _resume_parts.append(f"{len(agent.state.compromised_hosts)} hosts compromised")
                if agent.state.flags:
                    _resume_parts.append(f"Flags: {', '.join(f'{k}={v}' for k,v in agent.state.flags.items())}")
                if _resume_parts:
                    agent.state.resume_point = f"Retargeted {old_ip}→{_new}. State: {'; '.join(_resume_parts)}. Continue from where we left off."
            # Rebuild subsystems for new engagement dir
            from agents.base import StuckDetector
            from engagement_logger import EngagementLogger
            agent._stuck = StuckDetector.load("interactive", agent.state.dir)
            agent._log = EngagementLogger(agent.state.dir, agent.state.engagement_mode)
            orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
            agent.orchestrator = orchestrator
            agent._engagement_mgr._set_active(agent.state.target, agent.state.engagement_mode)
            console.print(f"[success]Retargeted: {old_ip} → {_new} (all state preserved)[/success]")
            console.print(f"[dim]  {len(agent.state.credentials)} creds, {len(agent.state.capabilities)} capabilities, {len(agent.state.notes)} notes carried over[/dim]")
            if agent.state.resume_point:
                console.print(f"[dim]  Resume: {agent.state.resume_point}[/dim]")

    elif command == "/target":
        if not arg:
            console.print(f"[dim]Current target: {agent.state.target or 'Not set'}[/dim]")
            if len(agent.state.targets) > 1:
                console.print(f"[dim]All targets: {', '.join(agent.state.targets)}[/dim]")
        else:
            new_target = arg.strip()
            old_target = agent.state.target
            # If changing to a DIFFERENT target, ask whether it's a retarget
            # (same box, IP changed) or a genuinely new target.
            if old_target and new_target != old_target:
                console.print(f"[yellow]Current target is [bold]{old_target}[/bold]. Is [bold]{new_target}[/bold]:[/yellow]")
                console.print(f"[dim]  [1] Same box, IP changed (keep all state)[/dim]")
                console.print(f"[dim]  [2] New target (fresh engagement)[/dim]")
                _choice = session.prompt(HTML("<b>[1/2]</b> ")).strip()
                if _choice == "1":
                    # Retarget — preserve state
                    agent.state.retarget(new_target)
                    agent._session_id = ""
                    agent.conversation_history = []
                    if not agent.state.resume_point:
                        _resume_parts = []
                        if agent.state.phases.current:
                            _resume_parts.append(f"Phase: {agent.state.phases.current.value}")
                        if agent.state.credentials:
                            _resume_parts.append(f"{len(agent.state.credentials)} creds")
                        if agent.state.compromised_hosts:
                            _resume_parts.append(f"{len(agent.state.compromised_hosts)} hosts compromised")
                        if _resume_parts:
                            agent.state.resume_point = f"Retargeted {old_target}→{new_target}. State: {'; '.join(_resume_parts)}. Continue from where we left off."
                    orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                    agent.orchestrator = orchestrator
                    agent._engagement_mgr._set_active(agent.state.target, agent.state.engagement_mode)
                    console.print(f"[success]Retargeted: {old_target} → {new_target} (all state preserved)[/success]")
                    console.print(f"[dim]  {len(agent.state.credentials)} creds, {len(agent.state.capabilities)} capabilities, {len(agent.state.notes)} notes carried over[/dim]")
                else:
                    # New target — switch or create
                    _mgr = agent._engagement_mgr
                    old_mode = agent.state.engagement_mode
                    switched = _mgr.switch(new_target)
                    if switched:
                        agent.state = switched
                        console.print(f"[success]Switched engagement: {new_target} "
                                      f"({len(agent.state.notes)} notes, "
                                      f"{len(agent.state.credentials)} creds)[/success]")
                    else:
                        eng = _mgr.create(new_target, old_mode)
                        agent.state = eng
                        console.print(f"[success]New engagement: {new_target}[/success]")
                    # Full reset — no bleedover from previous engagement
                    agent.reset_for_new_engagement()
                    orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                    agent.orchestrator = orchestrator
            else:
                # First target or same target — set on current engagement
                agent.state.set_target(new_target)
                console.print(f"[success]Target set: {new_target}[/success]")
            if len(agent.state.targets) > 1:
                console.print(f"[dim]All targets: {', '.join(agent.state.targets)}[/dim]")
            # Show parsed scope if enforcer exists
            if agent.state.scope_enforcer:
                console.print(f"[dim]{agent.state.scope_enforcer.scope.summary()}[/dim]")

    elif command == "/targets":
        tm = agent.state.target_manager
        console.print(Markdown(tm.summary()))

    elif command == "/scope":
        if not arg:
            console.print(f"[dim]Current scope: {agent.state.scope or 'Not set'}[/dim]")
            if agent.state.scope_enforcer:
                console.print(f"[dim]{agent.state.scope_enforcer.scope.summary()}[/dim]")
        elif arg.startswith("check "):
            # /scope check <target> — validate a target against scope
            check_target = arg[6:].strip()
            if agent.state.scope_enforcer:
                in_scope, reason = agent.state.scope_enforcer.is_in_scope(check_target)
                if in_scope:
                    console.print(f"[success]IN SCOPE: {check_target} — {reason}[/success]")
                else:
                    console.print(f"[danger]OUT OF SCOPE: {check_target} — {reason}[/danger]")
            else:
                console.print("[warning]No scope enforcer configured. Set scope first.[/warning]")
        else:
            agent.state.scope = arg
            # Re-parse scope into enforcer
            from scope_enforcer import ScopeDefinition, ScopeEnforcer
            scope_def = ScopeDefinition.parse(arg)
            for t in agent.state.targets:
                ScopeDefinition._classify_token(scope_def, t, excluded=False)
            agent.state.scope_enforcer = ScopeEnforcer(scope_def)
            console.print(f"[success]Scope set: {arg}[/success]")
            console.print(f"[dim]{scope_def.summary()}[/dim]")

    elif command == "/findings":
        _handle_findings(agent, arg)

    elif command == "/roe":
        if not arg:
            console.print(f"[dim]Current ROE: {agent.state.roe or 'Not set'}[/dim]")
        else:
            agent.state.roe = arg
            console.print(f"[success]ROE set: {arg}[/success]")

    elif command == "/status":
        console.print(Markdown(agent.state.summary()))
        if c2.daemon.is_running():
            console.print(f"\n[c2]{c2.server_status()}[/c2]")

    elif command == "/autonomous":
        agent.state.autonomous = not agent.state.autonomous
        orchestrator.autonomous = agent.state.autonomous
        for a in orchestrator._agents.values():
            a.autonomous = agent.state.autonomous
        mode = "ENABLED" if agent.state.autonomous else "DISABLED"
        color = "danger" if agent.state.autonomous else "success"
        console.print(f"[{color}]Autonomous mode: {mode}[/{color}]")
        if agent.state.autonomous:
            console.print("[warning]Claude will execute commands without permission prompts.[/warning]")

    elif command == "/budget":
        import config as _bcfg
        _cost = getattr(agent.state, "total_cost", 0.0)
        if arg.strip():
            try:
                new_ceil = float(arg.strip().lstrip("$"))
                if new_ceil < _cost:
                    console.print(f"[warning]Ceiling ${new_ceil:.2f} is below current spend ${_cost:.2f}[/warning]")
                else:
                    _bcfg.MAX_ENGAGEMENT_COST = new_ceil
                    console.print(f"[success]Budget ceiling set: ${new_ceil:.2f}[/success]")
            except ValueError:
                console.print("[warning]Usage: /budget <amount> — e.g. /budget 50[/warning]")
        else:
            _ceil = _bcfg.MAX_ENGAGEMENT_COST
            _pct = int(_cost / _ceil * 100) if _ceil > 0 else 0
            _bar_len = 20
            _filled = min(int(_pct / 5), _bar_len)
            _bar = "█" * _filled + "░" * (_bar_len - _filled)
            _color = "green" if _pct < 60 else ("yellow" if _pct < 85 else "red")
            console.print(f"  [{_color}]${_cost:.2f} / ${_ceil:.2f}[/{_color}]  [{_bar}] {_pct}%")
            console.print(f"[dim]  Set ceiling: /budget <amount>[/dim]")

    elif command == "/fast":
        agent.fast_mode = not agent.fast_mode
        if agent.fast_mode:
            from config import MODEL_EXPLOIT
            console.print(f"[success]Fast mode: ON[/success] — using {MODEL_EXPLOIT} for exploitation turns")
            console.print("[dim]Faster inference, lower cost. Opus still used for synthesis preflight.[/dim]")
        else:
            from config import MODEL
            console.print(f"[warning]Fast mode: OFF[/warning] — using {MODEL} for all turns")

    elif command == "/blitz":
        from multi_target import BlitzDispatcher, TargetSpec, parse_targets

        # Lazily attach the dispatcher to the agent so it persists across commands
        if not hasattr(agent, "_blitz"):
            agent._blitz = BlitzDispatcher()

        blitz = agent._blitz
        sub = arg.strip().lower()

        if sub in ("", "status"):
            # Show status table
            console.print(Markdown(blitz.status_table()))

        elif sub == "stop":
            blitz.stop()
            console.print("[warning]All blitz workers signaled to stop.[/warning]")

        elif sub.startswith("stop "):
            target_ip = sub.split(None, 1)[1].strip()
            blitz.stop(target_ip)
            console.print(f"[warning]Stopped: {target_ip}[/warning]")

        else:
            # Parse targets from the argument
            specs = parse_targets(arg)
            if not specs:
                console.print("[warning]No valid targets found.[/warning]")
                console.print("[dim]Usage: /blitz <ip1> <ip2> ...  or  /blitz Flag 1 (20pts) — IP — Description[/dim]")
            else:
                # Check for jumpbox context — detect internal targets
                jumpbox_cmd = ""
                if hasattr(agent.state, "notes"):
                    for note in agent.state.notes:
                        if "jumpbox" in note.lower() or "ssh -i" in note.lower():
                            # Extract SSH command from note
                            import re as _re
                            ssh_match = _re.search(r'(ssh\s+.+)', note)
                            if ssh_match:
                                jumpbox_cmd = ssh_match.group(1)
                                break

                # Mark RFC1918 targets as internal
                for spec in specs:
                    if spec.ip.startswith(("10.", "172.16.", "192.168.")):
                        spec.internal = True
                        if jumpbox_cmd:
                            spec.jumpbox = jumpbox_cmd

                # Event callback for live updates
                def _on_blitz_event(target: str, message: str):
                    console.print(f"  [dim][blitz][/dim] [bold]{target}[/bold]: {message}")

                # Determine concurrency — cap at 5 to avoid API rate limits
                max_conc = min(5, len(specs))

                console.print(f"\n[bold]Launching blitz against {len(specs)} targets[/bold] "
                              f"(max {max_conc} concurrent)")
                console.print(f"[dim]Fast mode: {'ON' if agent.fast_mode else 'OFF'} | "
                              f"Use /blitz status to monitor, /blitz stop to halt[/dim]\n")

                from rich.table import Table
                table = Table(show_header=True, header_style="bold")
                table.add_column("Target", style="cyan")
                table.add_column("Description", style="dim")
                table.add_column("Points")
                table.add_column("Type")
                for spec in specs:
                    t_type = "internal" if spec.internal else "external"
                    table.add_row(
                        spec.ip,
                        spec.description or "-",
                        str(spec.points) if spec.points else "-",
                        t_type,
                    )
                console.print(table)
                console.print()

                launched = blitz.launch(
                    specs,
                    fast_mode=agent.fast_mode,
                    on_event=_on_blitz_event,
                    max_concurrent=max_conc,
                )
                console.print(f"[success]{launched} agent(s) dispatched.[/success] "
                              f"They run in background — you can keep using the REPL.")

    elif command == "/ctf":
        # Legacy shortcut — switch to CTF mode
        agent.state.engagement_mode = "ctf"
        agent.state.ctf_mode = True
        console.print("[warning]Engagement mode: CTF[/warning]")
        console.print("[dim]Anti-cheat active. Vuln path guaranteed. Stop at flag.[/dim]")

    elif command == "/mode":
        if not arg.strip():
            mode = agent.state.engagement_mode
            mode_colors = {"ctf": "mode.ctf", "le": "mode.le", "redteam": "mode.redteam", "research": "bold magenta"}
            color = mode_colors.get(mode, "mode.ctf")
            console.print(f"  Current: [{color}]{mode.upper()}[/{color}]")
            console.print("")
            console.print("  [mode.ctf]ctf[/mode.ctf]       — Capture the Flag [dim](writeups blocked, vuln guaranteed, stop at flag)[/dim]")
            console.print("  [mode.le]le[/mode.le]        — Live Environment [dim](bug bounty/pentest, may have no vulns, findings report)[/dim]")
            console.print("  [mode.redteam]redteam[/mode.redteam]   — Red Team Ops [dim](adversary sim, persistence, evasion, OPSEC)[/dim]")
            console.print("  [bold magenta]research[/bold magenta]  — Vulnerability Research [dim](0-day hunting, fuzzing, RE, PoC development)[/dim]")
            console.print("")
            console.print("  [dim]Usage: /mode <ctf|le|redteam|research>[/dim]")
        else:
            new_mode = arg.strip().lower()
            if new_mode in ("ctf", "le", "redteam", "research"):
                agent.state.engagement_mode = new_mode
                agent.state.ctf_mode = (new_mode == "ctf")  # Legacy compat
                mode_switch = {
                    "ctf": (
                        "mode.ctf",
                        "CTF MODE ACTIVE",
                        [
                            "Anti-cheat: writeup/walkthrough access blocked",
                            "Assumption: vulnerability path EXISTS — keep looking",
                            "Objective: capture flags (user.txt + root.txt) then STOP",
                            "No persistence, no DCSync, no post-flag enumeration",
                        ]
                    ),
                    "le": (
                        "mode.le",
                        "LIVE ENVIRONMENT MODE ACTIVE",
                        [
                            "Target is REAL — do not cause disruption",
                            "Document ALL findings (auto-generated to /findings/)",
                            "\"No vulnerabilities\" is a valid result",
                            "Scope enforcement: STRICT",
                            "Output: professional findings report",
                        ]
                    ),
                    "redteam": (
                        "mode.redteam",
                        "RED TEAM OPS MODE ACTIVE",
                        [
                            "Adversary simulation — assume SOC is watching",
                            "OPSEC scoring: CRITICAL (warn before high-risk ops)",
                            "Establish persistence at every privilege level",
                            "Prefer living-off-the-land over uploading tools",
                            "Output: attack narrative + MITRE ATT&CK mapping",
                        ]
                    ),
                    "research": (
                        "bold magenta",
                        "VULNERABILITY RESEARCH MODE ACTIVE",
                        [
                            "Target: source code, binaries, firmware, protocols",
                            "Pipeline: classify → audit → fuzz → triage → PoC → variants",
                            "Aggressively filter false positives — validate every finding",
                            "Attempt full weaponization of confirmed bugs",
                            "Output: CVE advisory + PoC exploit + variant scan",
                            "Use /research to manage targets and view dashboard",
                        ]
                    ),
                }
                color, title, bullets = mode_switch[new_mode]
                # Reinitialize vault + logger for the new mode
                from engagement_logger import EngagementLogger
                from secret_vault import SecretVault
                agent._log = EngagementLogger(agent.state.dir, new_mode)
                _vault_on = new_mode in ("le", "redteam", "research")
                agent._vault = SecretVault(agent.state.dir, enabled=_vault_on)
                if _vault_on and agent.state.target:
                    agent._vault.register_from_engagement(agent.state)
                console.print(f"\n  [{color}]{title}[/{color}]")
                if _vault_on:
                    console.print(f"  [dim]  • Secret vault: ACTIVE ({agent._vault.summary()})[/dim]")
                for b in bullets:
                    console.print(f"  [dim]  • {b}[/dim]")
                console.print("")
            else:
                console.print("[warning]Invalid mode. Use: ctf, le, redteam, or research[/warning]")

    elif command == "/creds":
        if not agent.state.credentials:
            console.print("[dim]No credentials collected yet.[/dim]")
        else:
            for c in agent.state.credentials:
                console.print(f"  {c['username']} : {c['secret']} [{c['type']}] (from {c.get('source', '?')})")

    elif command == "/hosts":
        if not agent.state.compromised_hosts:
            console.print("[dim]No compromised hosts yet.[/dim]")
        else:
            for h in agent.state.compromised_hosts:
                console.print(f"  {h['hostname']} ({h.get('ip', '?')}) [{h['access_level']}]")

    elif command == "/addcred":
        cred_parts = arg.split()
        if len(cred_parts) < 3:
            console.print("[warning]Usage: /addcred <username> <secret> <type>[/warning]")
        else:
            agent.state.add_credential(cred_parts[0], cred_parts[1], cred_parts[2])
            console.print(f"[success]Credential added: {cred_parts[0]}[/success]")

    elif command == "/addhost":
        host_parts = arg.split()
        if not host_parts:
            console.print("[warning]Usage: /addhost <hostname> [ip] [access_level][/warning]")
        else:
            hostname = host_parts[0]
            ip = host_parts[1] if len(host_parts) > 1 else ""
            level = host_parts[2] if len(host_parts) > 2 else "user"
            agent.state.add_compromised_host(hostname, ip, level)
            console.print(f"[success]Host added: {hostname}[/success]")

    elif command == "/note":
        if not arg:
            if agent.state.notes:
                for i, note in enumerate(agent.state.notes, 1):
                    console.print(f"  {i}. {note}")
            else:
                console.print("[dim]No notes yet.[/dim]")
        else:
            agent.state.notes.append(arg)
            console.print(f"[success]Note added.[/success]")

    elif command == "/save":
        agent.state.save()
        agent._engagement_mgr._set_active(agent.state.target, agent.state.engagement_mode)
        console.print(f"[success]Engagement saved: {agent.state.state_path}[/success]")

    elif command == "/load":
        name = arg.strip()
        if not name:
            console.print("[warning]Usage: /load <target>[/warning]")
        else:
            eng = agent._engagement_mgr.switch(name)
            if eng:
                agent.state = eng
                agent.reset_for_new_engagement()
                # Restore saved session ID for this engagement (resume thread)
                agent._session_id = getattr(eng, "session_id", "") or ""
                orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                agent.orchestrator = orchestrator
                import config as _cfg
                _cfg.EVIDENCE_DIR = agent.state.evidence_dir
                console.print(f"[success]Loaded engagement: {eng.target} ({eng.phases.summary()})[/success]")
            else:
                console.print(f"[danger]No engagement found for: {name}[/danger]")

    elif command == "/engagements":
        from rich.table import Table

        # Optional filter: /engagements le, /engagements ctf, /engagements all
        mode_filter = arg.strip().lower() if arg else ""
        show_modes = ["ctf", "le", "redteam"]
        if mode_filter in ("ctf", "le", "redteam"):
            show_modes = [mode_filter]

        dashboards = agent._engagement_mgr.dashboard_all()
        if not dashboards:
            console.print("[dim]No saved engagements. Start one with /new <target>[/dim]")
        else:
            # Group by mode
            by_mode = {}
            for d in dashboards:
                by_mode.setdefault(d["mode"], []).append(d)

            for mode in show_modes:
                entries = by_mode.get(mode, [])
                if not entries:
                    continue

                # Sort: active first, then paused, then solved
                def _sort_key(e):
                    if e.get("active"):
                        return (0, e["target"])
                    if e["status"] == "solved":
                        return (2, e["target"])
                    return (1, e["target"])
                entries.sort(key=_sort_key)

                table = Table(
                    title=f" {mode.upper()} Engagements ",
                    title_style="bold white",
                    border_style="dim",
                    show_lines=False,
                    pad_edge=False,
                    expand=False,
                )
                table.add_column("", width=2)  # status icon
                table.add_column("Target", min_width=20)
                table.add_column("Status", min_width=10)
                table.add_column("Phase", min_width=8)
                table.add_column("Findings", min_width=8, justify="right")
                table.add_column("Creds", justify="right")
                table.add_column("Hosts", justify="right")
                table.add_column("Cost", justify="right")
                table.add_column("Time", justify="right")
                table.add_column("Progress", min_width=20)

                for e in entries:
                    # Determine display status: active (in progress), solved, or paused
                    if e["status"] == "solved":
                        icon = "[green]✓[/green]"
                        status_text = "[green]solved[/green]"
                        target_style = "green"
                    elif e.get("active"):
                        icon = "[cyan]►[/cyan]"
                        status_text = "[cyan]active[/cyan]"
                        target_style = "bold cyan"
                    else:
                        icon = "[yellow]⏸[/yellow]"
                        status_text = "[yellow]paused[/yellow]"
                        target_style = "yellow"

                    # Findings summary with severity breakdown
                    fsev = e.get("findings_by_severity", {})
                    if fsev:
                        parts = []
                        for s in ("critical", "high", "medium", "low", "info"):
                            c = fsev.get(s, 0)
                            if c > 0:
                                color = {"critical": "red", "high": "bright_red",
                                         "medium": "yellow", "low": "dim", "info": "dim"}.get(s, "dim")
                                parts.append(f"[{color}]{c}{s[0].upper()}[/{color}]")
                        findings_str = " ".join(parts) if parts else "[dim]0[/dim]"
                    else:
                        findings_str = f"[dim]{e.get('findings', 0)}[/dim]"

                    # Resume / progress indicator
                    resume = e.get("resume", "") or ""
                    if len(resume) > 40:
                        resume = resume[:37] + "..."

                    table.add_row(
                        icon,
                        f"[{target_style}]{e['target']}[/{target_style}]",
                        status_text,
                        f"[dim]{e.get('phase', '?')}[/dim]",
                        findings_str,
                        str(e["creds"]),
                        str(e["hosts"]),
                        e["cost"],
                        e["time"],
                        f"[dim]{resume}[/dim]",
                    )

                console.print()
                console.print(table)

            # Summary line
            total = len(dashboards)
            solved = sum(1 for d in dashboards if d["status"] == "solved")
            active = sum(1 for d in dashboards if d.get("active"))
            paused = total - solved - active
            total_cost = sum(d.get("cost_raw", 0) for d in dashboards)
            console.print(
                f"\n  [dim]{total} engagements: "
                f"[cyan]{active} active[/cyan] · "
                f"[yellow]{paused} paused[/yellow] · "
                f"[green]{solved} solved[/green] · "
                f"${total_cost:.2f} total[/dim]"
            )
            console.print(f"  [dim]Use /load <target> to resume a paused engagement[/dim]")

    elif command == "/review":
        _handle_review(orchestrator, agent, arg)

    elif command == "/research":
        _handle_research(agent, arg, console)

    elif command == "/cve-sync":
        _handle_cve_sync(arg, console)

    elif command == "/tasks":
        _handle_tasks(agent, arg)

    elif command == "/opsec":
        _handle_opsec(agent, arg)

    elif command == "/plan":
        _handle_plan(agent)

    elif command == "/report":
        _handle_report(orchestrator, arg)

    elif command == "/bounty":
        _handle_bounty(orchestrator, agent, arg)

    elif command == "/learn":
        from learner import retroactive_learn_all, learn_from_finding, learn_from_engagement
        if arg.strip():
            # Learn from a specific file
            target_path = Path(arg.strip())
            if target_path.suffix == ".md":
                n = learn_from_finding(target_path)
                console.print(f"[success]Learned {n} chunks from finding: {target_path.name}[/success]")
            elif target_path.suffix == ".json":
                n = learn_from_engagement(target_path)
                console.print(f"[success]Learned {n} chunks from engagement: {target_path.name}[/success]")
            else:
                console.print("[warning]Provide a .md finding or .json engagement file[/warning]")
        else:
            console.print("[dim]Learning from ALL past engagements and findings...[/dim]")
            stats = retroactive_learn_all()
            console.print(
                f"[success]Done: {stats['findings']} findings, "
                f"{stats['engagements']} engagements, "
                f"{stats['chunks']} total chunks ingested into RAG[/success]"
            )

    elif command == "/quickstart":
        try:
            from config import DATA_DIR
            qs_path = DATA_DIR / "quickstart.md"
            console.print(Markdown(qs_path.read_text()))
        except Exception as e:
            console.print(f"[danger]Could not load quickstart guide: {e}[/danger]")

    elif command == "/ingest-url":
        if not arg.strip():
            console.print("[warning]Usage: /ingest-url <url>[/warning]")
        else:
            _handle_ingest_url(arg.strip())

    elif command == "/verbose":
        global _verbose_mode
        _verbose_mode = not _verbose_mode
        mode = "ENABLED" if _verbose_mode else "DISABLED"
        color = "success" if _verbose_mode else "dim"
        console.print(f"[{color}]Verbose progress mode: {mode}[/{color}]")
        if _verbose_mode:
            console.print("[dim]Commands, outputs, and agent reasoning will be shown in real-time.[/dim]")

    elif command == "/reset":
        agent.reset_conversation()
        console.print("[success]Conversation history cleared.[/success]")

    elif command == "/compact":
        agent.compact_history()
        console.print(f"[success]History compacted to last {len(agent.conversation_history)} messages.[/success]")

    else:
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Red Team Operator Agent")
    parser.add_argument("--target", help="Set initial target IP/range")
    parser.add_argument("--scope", help="Set engagement scope description")
    parser.add_argument("--roe", help="Rules of engagement")
    parser.add_argument("--autonomous", "--auto", action="store_true", help="Start in autonomous mode")
    parser.add_argument("--mode", choices=["ctf", "le", "redteam"], default=None, help="Engagement mode: ctf, le, or redteam")
    parser.add_argument("--fast", action="store_true", help="Use Sonnet for exploitation (faster, cheaper)")
    parser.add_argument("--no-banner", action="store_true", help="Skip the banner")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose progress mode (show commands, outputs, reasoning)")
    parser.add_argument("--c2-start", action="store_true", help="Auto-start Sliver daemon")
    args = parser.parse_args()

    if not args.no_banner:
        console.print(BANNER)

    # Initialize agent
    try:
        agent = RedTeamAgent()
    except RuntimeError as e:
        console.print(f"[danger]{e}[/danger]")
        sys.exit(1)

    # Initialize Sliver C2 manager and orchestrator
    c2 = SliverManager()
    orchestrator = Orchestrator(agent.state, autonomous=args.autonomous)
    agent.orchestrator = orchestrator  # Shared reference — handle_command updates via agent.orchestrator

    # Apply CLI arguments
    if args.target:
        agent.state.set_target(args.target, args.scope or "", args.roe or "")
        console.print(f"[success]Target: {args.target}[/success]")
        if args.scope:
            console.print(f"[success]Scope: {args.scope}[/success]")
    if args.autonomous:
        agent.state.autonomous = True
    if args.mode:
        agent.state.engagement_mode = args.mode
        agent.state.ctf_mode = (args.mode == "ctf")
    if args.fast:
        agent.fast_mode = True
    if args.verbose:
        global _verbose_mode
        _verbose_mode = True

    # Auto-start C2 if requested
    if args.c2_start:
        console.print("[dim]Starting Sliver daemon...[/dim]")
        result = c2.start_server()
        console.print(f"[c2]{result}[/c2]")

    # === Status Dashboard ===
    console.print("")

    # Core modes
    _status_line(console, "Autonomous mode", agent.state.autonomous)
    _status_line(console, "Verbose progress", _verbose_mode)
    # Engagement mode with mode-specific color and description
    mode = agent.state.engagement_mode
    mode_info = {
        "ctf": ("mode.ctf", "CTF", "flag capture, anti-cheat, stop at flag"),
        "le": ("mode.le", "LIVE ENVIRONMENT", "bug bounty/pentest, findings-focused"),
        "redteam": ("mode.redteam", "RED TEAM OPS", "adversary sim, persistence, OPSEC"),
    }
    color, name, desc = mode_info.get(mode, ("mode.ctf", "CTF", ""))
    console.print(f"  Engagement mode: [{color}]{name}[/{color}] [dim]({desc})[/dim]")

    # Knowledge base — only show because it has an actionable state (missing = run ingest.py)
    try:
        from config import CHROMA_DIR
        kb_ready = (CHROMA_DIR / "chroma.sqlite3").exists()
    except Exception:
        kb_ready = False
    if not kb_ready:
        _status_line(console, "Knowledge base", False, "run: python3 ingest.py")

    # C2
    c2_running = c2.daemon.is_running()
    _status_line(console, "Sliver C2", c2_running, f"PID {c2.daemon.pid}" if c2_running else "/c2 start")

    console.print("")
    console.print("[dim]Type /quickstart for the guide, /help for commands, /quit to exit.[/dim]\n")

    # Set up prompt with history
    history_path = os.path.expanduser("~/.redops_agent_history")
    session = PromptSession(
        history=FileHistory(history_path),
        auto_suggest=AutoSuggestFromHistory(),
        completer=RedopsCompleter(),
        complete_while_typing=False,  # Only complete on Tab press
    )

    while True:
        try:
            # Mode-aware prompt with color coding
            mode = agent.state.engagement_mode
            if mode == "ctf":
                mode_tag = '<red>[ctf]</red>'
            elif mode == "le":
                mode_tag = '<green>[le]</green>'
            elif mode == "redteam":
                mode_tag = '<magenta>[redteam]</magenta>'
            else:
                mode_tag = '<red>[ctf]</red>'

            if agent.state.autonomous:
                prompt_str = HTML(f'{mode_tag} <red>redops&gt; </red>')
            else:
                prompt_str = HTML(f'{mode_tag} <white>redops&gt; </white>')
            user_input = session.prompt(prompt_str).strip()

            if not user_input:
                continue

            # Handle slash commands — always read orchestrator from agent
            # so handle_command's rebuilds propagate back.
            orchestrator = agent.orchestrator
            if user_input.startswith("/"):
                if not handle_command(agent, c2, orchestrator, user_input):
                    console.print(f"[warning]Unknown command: {user_input.split()[0]}[/warning]")
                continue

            # Fast-path: answer simple state questions locally without calling Claude.
            # These are instant lookups that don't need LLM reasoning.
            _fast_answer = _handle_fast_query(agent.state, user_input)
            if _fast_answer:
                console.print(f"\n{_fast_answer}\n")
                continue

            # Auto-detect new target IP in user input — switch engagement via EngagementManager
            # Only switch when the user clearly intends a new target, not when
            # referencing internal IPs in context (e.g., "the RODC is at 192.168.100.2").
            import re as _re

            # ── Layer 1: Input sanitization ──
            # Strip IPs that appear inside HTML/encoded noise so they never trigger engagement.
            def _sanitize_for_ip_detection(text: str) -> str:
                """Remove content that contains incidental IPs (email HTML, tracking pixels, encoded blobs)."""
                # Remove HTML tags and their attributes (src=, href=, style=, etc.)
                text = _re.sub(r'<[^>]{4,}>', ' ', text)
                # Remove quoted-printable encoded chunks (=3D, =\n continuations)
                text = _re.sub(r'=[0-9A-Fa-f]{2}', ' ', text)
                # Remove base64-like strings (40+ chars of alnum/+/= with no spaces)
                text = _re.sub(r'[A-Za-z0-9+/=\-]{40,}', ' ', text)
                # Remove URLs (IPs in URLs are navigation targets, not engagement targets)
                text = _re.sub(r'https?://[^\s"\'<>]+', ' ', text)
                # Remove MIME boundaries and email headers
                text = _re.sub(r'^--[a-f0-9]{20,}.*$', ' ', text, flags=_re.MULTILINE)
                text = _re.sub(r'^(Content-Type|Content-Transfer-Encoding|MIME-Version):.*$', ' ', text, flags=_re.MULTILINE)
                return text

            # Known mail/CDN infrastructure CIDRs — IPs here are never engagement targets
            _INFRA_CIDRS = [
                ("167.89.0.0", 16),   # SendGrid
                ("198.21.0.0", 16),   # SendGrid
                ("169.45.0.0", 16),   # SoftLayer/IBM
                ("13.107.0.0", 16),   # Microsoft
                ("104.16.0.0", 12),   # Cloudflare
                ("172.217.0.0", 16),  # Google
                ("142.250.0.0", 15),  # Google
                ("34.0.0.0", 8),      # GCP
                ("52.0.0.0", 8),      # AWS
                ("54.0.0.0", 8),      # AWS
                ("99.82.0.0", 16),    # AWS Global Accelerator
            ]

            def _is_infra_ip(ip_str: str) -> bool:
                """Check if IP belongs to known mail/CDN infrastructure."""
                import ipaddress as _ipa
                try:
                    addr = _ipa.ip_address(ip_str)
                except ValueError:
                    return False
                for net_base, prefix in _INFRA_CIDRS:
                    net = _ipa.ip_network(f"{net_base}/{prefix}", strict=False)
                    if addr in net:
                        return True
                return False

            _sanitized_input = _sanitize_for_ip_detection(user_input)
            _ip_match = _re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', _sanitized_input)
            if _ip_match:
                _new_ip = _ip_match.group(1)
                # Reject infrastructure IPs that survived sanitization
                if _is_infra_ip(_new_ip):
                    _ip_match = None
            if _ip_match:
                _new_ip = _ip_match.group(1)
                _current_target = agent.state.target or ""
                # Skip if: same target, loopback, or IP is already known in this engagement
                _known_ips = set()
                _known_ips.add(_current_target)
                for h in agent.state.discovered_hosts:
                    _known_ips.add(h.get("ip", "") if isinstance(h, dict) else str(h))
                for n in agent.state.notes:
                    for m in _re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(n)):
                        _known_ips.add(m)
                # Also require target-intent language if the IP is RFC1918 and not
                # on the same /16 as the current target (likely an internal reference)
                _target_intent = _re.search(
                    r'\b(new\s+target|target\s+is|engage|box\s+at|machine\s+at|start\s+with|pwn|hack)\b',
                    user_input, _re.IGNORECASE
                )
                _is_rfc1918 = (
                    _new_ip.startswith("10.") or _new_ip.startswith("172.") or _new_ip.startswith("192.168.")
                )
                _same_subnet = (
                    _current_target and
                    _new_ip.rsplit(".", 2)[0] == _current_target.rsplit(".", 2)[0]  # same /16
                )
                # Detect retarget intent: IP changed but same box (reset, VPN reconnect)
                _retarget_intent = _re.search(
                    r'\b(ip\s+changed|new\s+ip|box\s+reset|target\s+changed|retarget|reip|'
                    r'changed\s+(?:to|ip)|reset.*new\s+ip|same\s+box|same\s+machine|'
                    r'ip\s+is\s+now|now\s+at)\b',
                    user_input, _re.IGNORECASE
                )
                _should_switch = (
                    _new_ip != _current_target
                    and not _new_ip.startswith("127.")
                    and _new_ip not in _known_ips
                    and (_target_intent or _same_subnet or not _is_rfc1918)
                )
                # ── Layer 2: Confirmation gate ──
                # When there's an active engagement and a new IP is detected,
                # always ask whether it's the same box (retarget) or a new target.
                # This prevents losing engagement state on HTB box resets / VPN reconnects.
                _is_retarget = False
                if _should_switch and agent.state.target:
                    # Auto-detect retarget intent from language
                    if _retarget_intent:
                        _is_retarget = True
                    else:
                        console.print(f"[yellow]Detected IP [bold]{_new_ip}[/bold] — current target is [bold]{agent.state.target}[/bold][/yellow]")
                        console.print(f"[dim]  [1] Same box, IP changed (keep all state)[/dim]")
                        console.print(f"[dim]  [2] New target (fresh engagement)[/dim]")
                        console.print(f"[dim]  [3] Ignore (pass to agent as-is)[/dim]")
                        _choice = session.prompt(HTML("<b>[1/2/3]</b> ")).strip()
                        if _choice == "1":
                            _is_retarget = True
                        elif _choice == "2":
                            pass  # _should_switch stays True, _is_retarget stays False
                        else:
                            _should_switch = False
                elif _should_switch and not agent.state.target:
                    pass  # No existing target — proceed with new engagement

                # Retarget: same engagement, new IP
                if _should_switch and _is_retarget and agent.state.target:
                    old_ip = agent.state.target
                    agent.state.retarget(_new_ip)
                    agent._session_id = ""
                    agent.conversation_history = []
                    # Set resume point so agent picks up where it left off
                    if not agent.state.resume_point:
                        _resume_parts = []
                        if agent.state.phases.current:
                            _resume_parts.append(f"Phase: {agent.state.phases.current.value}")
                        if agent.state.credentials:
                            _resume_parts.append(f"{len(agent.state.credentials)} creds")
                        if agent.state.compromised_hosts:
                            _resume_parts.append(f"{len(agent.state.compromised_hosts)} hosts compromised")
                        if agent.state.flags:
                            _resume_parts.append(f"Flags: {', '.join(f'{k}={v}' for k,v in agent.state.flags.items())}")
                        if _resume_parts:
                            agent.state.resume_point = f"Retargeted {old_ip}→{_new_ip}. State: {'; '.join(_resume_parts)}. Continue from where we left off."
                    # Rebuild subsystems for new engagement dir
                    from agents.base import StuckDetector
                    from engagement_logger import EngagementLogger
                    agent._stuck = StuckDetector.load("interactive", agent.state.dir)
                    agent._log = EngagementLogger(agent.state.dir, agent.state.engagement_mode)
                    orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                    agent.orchestrator = orchestrator
                    agent._engagement_mgr._set_active(agent.state.target, agent.state.engagement_mode)
                    console.print(f"[success]Retargeted: {old_ip} → {_new_ip} (all state preserved)[/success]")
                    console.print(f"[dim]  {len(agent.state.credentials)} creds, {len(agent.state.capabilities)} capabilities, {len(agent.state.notes)} notes carried over[/dim]")
                    if agent.state.resume_point:
                        console.print(f"[dim]  Resume: {agent.state.resume_point}[/dim]")
                # New engagement: different target entirely
                elif _should_switch:
                    _mgr = agent._engagement_mgr
                    old_mode = agent.state.engagement_mode
                    # Try to switch to existing engagement, or create new one
                    switched = _mgr.switch(_new_ip)
                    if switched:
                        agent.state = switched
                        console.print(f"[success]Switched engagement: {_new_ip} ({len(agent.state.notes)} notes, {len(agent.state.credentials)} creds)[/success]")
                    else:
                        eng = _mgr.create(_new_ip, old_mode)
                        agent.state = eng
                        console.print(f"[success]New engagement: {_new_ip}[/success]")
                    # Full reset — no bleedover from previous engagement
                    agent.reset_for_new_engagement()
                    orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                    agent.orchestrator = orchestrator

                    # Parse credentials from the user's message into engagement state
                    # (covers both interactive and orchestrator modes)
                    cred_count = agent.state.parse_credentials_from_text(user_input)
                    if cred_count:
                        console.print(f"[dim]  Parsed {cred_count} credential(s) from input[/dim]")

            # ── Web/domain new-engagement intent (no IPv4 in message) ──
            # Web/bug-bounty targets are domains, not IPs, so the IPv4 switch above
            # never fires for them — that let a stale engagement's resume_point,
            # operator directive, total_cost and vault bleed into a new web target.
            # On EXPLICIT new-engagement intent, resolve a candidate domain and
            # CONFIRM with the operator before creating a fresh, isolated engagement.
            if not _ip_match:
                _new_eng_intent = _re.search(
                    r'\b(new\s+(?:engagement|target)|(?:start|begin)(?:ing)?\s+'
                    r'(?:a\s+)?new\s+(?:engagement|target)|fresh\s+engagement)\b',
                    user_input, _re.IGNORECASE,
                )
                if _new_eng_intent:
                    def _extract_web_target(text: str) -> str:
                        m = _re.search(r'https?://([^\s/"\'<>]+)', text)
                        if m:
                            return m.group(1).lower()
                        m = _re.search(
                            r'\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                            r'[a-z]{2,24})\b',
                            text, _re.IGNORECASE,
                        )
                        return m.group(1).lower() if m else ""

                    _candidate = _extract_web_target(user_input)
                    # If a scope file is referenced, mine it for a domain.
                    if not _candidate:
                        _fp = _re.search(r'(/[^\s"\'<>]+)', user_input)
                        if _fp:
                            from pathlib import Path as _P
                            try:
                                _sp = _P(_fp.group(1))
                                if _sp.is_file():
                                    _candidate = _extract_web_target(
                                        _sp.read_text(errors="replace")[:5000]
                                    )
                            except Exception:
                                _candidate = ""

                    console.print(
                        f"[yellow]New-engagement intent detected — current target: "
                        f"[bold]{agent.state.target or '(none)'}[/bold][/yellow]"
                    )
                    _default_hint = f" [{_candidate}]" if _candidate else ""
                    _ans = session.prompt(
                        HTML(f"<b>New engagement target{_default_hint} "
                             f"(Enter=accept, 'n'=cancel):</b> ")
                    ).strip()

                    if _ans.lower() in ("n", "no", "cancel"):
                        console.print("[dim]  Cancelled — passing message to agent as-is.[/dim]")
                    else:
                        _target = _ans or _candidate
                        if not _target:
                            console.print("[dim]  No target resolved — passing message to agent as-is.[/dim]")
                        else:
                            _mgr = agent._engagement_mgr
                            _old_mode = agent.state.engagement_mode
                            _existing = _mgr.switch(_target)
                            if _existing and _existing.target:
                                agent.state = _existing
                                console.print(
                                    f"[success]Switched to existing engagement: "
                                    f"{_existing.target} ({_existing.engagement_mode})[/success]"
                                )
                            else:
                                _eng = _mgr.create(_target, _old_mode)
                                agent.state = _eng
                                console.print(
                                    f"[success]New engagement: {_target} ({_old_mode}) — "
                                    f"fresh state, cost reset[/success]"
                                )
                            # Full reset — no bleedover from previous engagement.
                            agent.reset_for_new_engagement()
                            orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                            agent.orchestrator = orchestrator
                            import config as _cfg
                            _cfg.EVIDENCE_DIR = agent.state.evidence_dir
                            _cred_n = agent.state.parse_credentials_from_text(user_input)
                            if _cred_n:
                                console.print(f"[dim]  Parsed {_cred_n} credential(s) from input[/dim]")

            # Detect engagement continuation requests — with or without attached context.
            # "continue" alone → resume orchestrator. "continue but focus on X" → resume
            # with the directive injected into the next planning cycle.
            _continue_phrases = (
                "continue", "continue with the engagement", "continue with engagement",
                "continue engagement", "continue the engagement",
                "keep going", "resume", "pick up where we left off", "carry on",
                "continue the attack", "continue attacking", "go",
            )
            _input_clean = user_input.lower().strip().rstrip(".!?")
            _is_bare_continue = _input_clean in _continue_phrases
            # "continue but ..." / "continue, focus on ..." / "keep going with the RODC path"
            _is_continue_with_context = (
                not _is_bare_continue
                and any(_input_clean.startswith(p) for p in (
                    "continue but", "continue,", "continue and", "continue with",
                    "keep going", "carry on", "resume but", "resume and", "resume,",
                    "go but", "go ahead",
                ))
                and len(user_input) > 20
            )
            _is_continue = _is_bare_continue or _is_continue_with_context

            if _is_continue and agent.state.target:
                if agent.state.is_solved:
                    console.print("[warning]This engagement is SOLVED. Use /new <target> for a new one or /load to revisit.[/warning]")
                    continue

                # --- Engagement switch detection ---
                # "continue with paypal engagement" or "continue with 10.129.33.5"
                # should switch to that engagement, not save as a directive.
                _switched = False
                if _is_continue_with_context:
                    import re as _sw_re
                    # Extract potential target from phrases like:
                    #   "continue with paypal engagement"
                    #   "continue with the 10.129.33.5 box"
                    #   "switch to bancoplata"
                    _switch_match = _sw_re.search(
                        r'(?:continue\s+with(?:\s+the)?|switch\s+to|resume|load)\s+'
                        r'([a-zA-Z0-9][\w.\-]*)',
                        user_input, _sw_re.IGNORECASE,
                    )
                    if _switch_match:
                        _candidate = _switch_match.group(1).strip()
                        # Filter out noise words that aren't targets
                        _noise = {"engagement", "the", "attack", "current", "bug", "bounty",
                                  "same", "this", "my", "our", "previous"}
                        if _candidate.lower() not in _noise and len(_candidate) >= 3:
                            _mgr = agent._engagement_mgr
                            _found = _mgr.switch(_candidate)
                            if _found and _found.target != agent.state.target:
                                agent.state = _found
                                agent.reset_for_new_engagement()
                                # Restore saved session ID for this engagement
                                agent._session_id = getattr(_found, "session_id", "") or ""
                                orchestrator = Orchestrator(agent.state, autonomous=agent.state.autonomous)
                                agent.orchestrator = orchestrator
                                import config as _cfg
                                _cfg.EVIDENCE_DIR = agent.state.evidence_dir
                                console.print(
                                    f"[success]Switched to engagement: {_found.target} "
                                    f"({_found.engagement_mode}) — "
                                    f"{len(_found.credentials)} creds, "
                                    f"{_found.phases.current} phase[/success]"
                                )
                                _switched = True

                # If we didn't switch, save as operator directive
                if not _switched and _is_continue_with_context:
                    directive = f"[operator directive] {user_input[:500]}"
                    if directive not in agent.state.notes:
                        agent.state.notes.append(directive)
                    # Also parse credentials if mentioned
                    try:
                        agent.state.parse_credentials_from_text(user_input)
                    except Exception:
                        pass
                    agent.state.save()
                    console.print(f"[dim]  Operator directive saved — will guide next planning cycle[/dim]")

                if agent.state.has_exploit_data:
                    handle_command(agent, c2, orchestrator, "/auto continue")
                    continue
                # else: fall through to interactive agent (no prior progress to resume)

            # Persist user-provided context as engagement notes so it survives restarts.
            # Only save messages that contain actionable target context — NOT
            # conversational messages, agent corrections, or behavioral instructions.
            import re as _note_re
            if (agent.state.target
                    and not user_input.startswith("/")
                    and not _is_continue
                    and len(user_input) > 30):

                # Detect if this is an instruction/correction to the agent (→ directive)
                # vs. factual target context (→ note). Instructions reference the agent's
                # behavior: "don't skip", "focus on", "try X instead", "you should", etc.
                _is_instruction = _note_re.search(
                    r'\b(don\'?t skip|do not skip|don\'?t ignore|focus on|try .* instead|'
                    r'you should|stop doing|skip the|ignore the|'
                    r'don\'?t bother|don\'?t use|use .* instead|'
                    r'prioritize|deprioritize|avoid|prefer)\b',
                    user_input, _note_re.IGNORECASE
                )
                # Detect factual target context (IPs, hostnames, ports, creds, findings)
                _has_target_facts = _note_re.search(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPs
                    r'port\s+\d+|'                              # ports
                    r'credential|password|hash|'                # creds
                    r'cached|RODC|ADCS|delegation|'             # AD concepts
                    r'SID|ACL|ACE|DN=|CN=|'                    # AD objects
                    r'\.htb|\.local|DC\d)',                     # domain names
                    user_input, _note_re.IGNORECASE
                )

                if _is_instruction:
                    # Save as directive — the agent will follow it, not just read it
                    directive = f"[operator directive] {user_input[:500]}"
                    if directive not in agent.state.notes:
                        agent.state.notes.append(directive)
                        agent.state.save()
                elif _has_target_facts:
                    # Save as context note — factual info about the target
                    note = f"[operator] {user_input[:500]}"
                    if note not in agent.state.notes:
                        agent.state.notes.append(note)
                        agent.state.save()
                # else: conversational message — don't persist, just pass to agent

                # Parse any credentials mentioned
                try:
                    agent.state.parse_credentials_from_text(user_input)
                except Exception:
                    pass

            # Inject C2 state into the message context for the agent
            c2_context = ""
            if c2.daemon.is_running() and c2.is_connected:
                c2_context = f"\n[Current C2 state: Sliver server running. Use 'sliver-client' or Sliver CLI commands for C2 operations.]"

            # Send to agent with live status updates
            console.print()

            verbose = _verbose_mode

            spinner = Spinner("dots", text="[dim]Thinking...[/dim]")
            live = Live(spinner, console=console, transient=True)

            # Progress tracking state for the status bar
            _chat_turn = [0]
            _chat_cmds = [0]
            _chat_start_time = [time.monotonic()]
            _chat_last_cmd = [""]

            def update_status(msg):
                # ALWAYS track turns and commands — the background ticker needs these
                if "Turn " in msg:
                    try:
                        _chat_turn[0] = int(msg.split("Turn ")[1].split("...")[0].split("/")[0])
                    except (ValueError, IndexError):
                        pass
                if "Running: " in msg:
                    _chat_cmds[0] += 1
                    _chat_last_cmd[0] = msg.split("Running: ", 1)[-1][:50]

                # Debug/system messages always print in verbose mode
                if verbose:
                    _debug_prefixes = ("[WATCHDOG]", "STUCK:")
                    if any(msg.startswith(p) or p in msg for p in _debug_prefixes):
                        console.print(f"  [bold yellow]{msg}[/bold yellow]")
                    return  # Other status messages handled by background ticker

                # Non-verbose: update the spinner directly
                elapsed = time.monotonic() - _chat_start_time[0]
                elapsed_str = f"{int(elapsed // 60)}:{int(elapsed % 60):02d}"
                turn = _chat_turn[0]
                max_t = 25

                if turn > 0:
                    pct = min(int(turn / max_t * 100), 100)
                    bar_filled = int(pct / 5)
                    bar = "█" * bar_filled + "░" * (20 - bar_filled)
                    status_line = (
                        f"[dim]⏱ {elapsed_str} │ Turn {turn}/{max_t} [{bar}] {pct}% │ "
                        f"Cmds: {_chat_cmds[0]}[/dim]"
                    )
                    if _chat_last_cmd[0]:
                        status_line += f" [dim]│ {_chat_last_cmd[0]}[/dim]"
                else:
                    status_line = f"[dim]⏱ {elapsed_str} │ {msg}[/dim]"

                spinner.update(text=status_line)
                live.refresh()

            on_progress = _render_progress_event if verbose else None

            if not verbose:
                live.start()

            chat_start = time.monotonic()
            _chat_start_time[0] = chat_start
            # Reset verbose progress tracking
            global _verbose_start_time, _verbose_turn, _verbose_cmds, _verbose_agent
            _verbose_start_time = chat_start
            _verbose_turn = 0
            _verbose_cmds = 0
            _verbose_agent = ""

            # Background timer thread: refreshes progress display every 1 second
            # so elapsed time ticks even during long thinking blocks
            import threading
            _refresh_stop = threading.Event()

            # For verbose mode: use a Live display for the ticker so it overwrites in-place
            if verbose:
                _verbose_ticker_spinner = Spinner("dots", text="[dim]Starting...[/dim]")
                _verbose_ticker = Live(_verbose_ticker_spinner, console=console, transient=True)
                _verbose_ticker.start()
            else:
                _verbose_ticker = None

            def _refresh_loop():
                while not _refresh_stop.is_set():
                    _refresh_stop.wait(1.0)
                    if _refresh_stop.is_set():
                        break
                    elapsed = time.monotonic() - _chat_start_time[0]
                    elapsed_str = f"{int(elapsed // 60)}:{int(elapsed % 60):02d}"
                    turn = _chat_turn[0]

                    if verbose and _verbose_ticker:
                        # Verbose: update the transient Live ticker
                        max_t = 25
                        if turn > 0:
                            pct = min(int(turn / max_t * 100), 100)
                            bar_filled = int(pct / 5)
                            bar = "█" * bar_filled + "░" * (20 - bar_filled)
                            line = (
                                f"[dim]⏱ {elapsed_str} │ Turn {turn}/{max_t} [{bar}] {pct}% │ "
                                f"Cmds: {_chat_cmds[0]}[/dim]"
                            )
                        else:
                            line = f"[dim]⏱ {elapsed_str} │ Thinking... │ Cmds: {_chat_cmds[0]}[/dim]"
                        try:
                            _verbose_ticker_spinner.update(text=line)
                            _verbose_ticker.refresh()
                        except Exception:
                            pass
                    elif not verbose:
                        # Non-verbose: update the main spinner
                        max_t = 25
                        if turn > 0:
                            pct = min(int(turn / max_t * 100), 100)
                            bar_filled = int(pct / 5)
                            bar = "█" * bar_filled + "░" * (20 - bar_filled)
                            status_line = (
                                f"[dim]⏱ {elapsed_str} │ Turn {turn}/{max_t} [{bar}] {pct}% │ "
                                f"Cmds: {_chat_cmds[0]}[/dim]"
                            )
                        else:
                            status_line = f"[dim]⏱ {elapsed_str} │ Thinking... │ Cmds: {_chat_cmds[0]}[/dim]"
                        try:
                            spinner.update(text=status_line)
                            live.refresh()
                        except Exception:
                            pass

            _refresh_thread = threading.Thread(target=_refresh_loop, daemon=True)
            _refresh_thread.start()

            def _prompt_budget_extension(cost_so_far: float, current_ceiling: float):
                _refresh_stop.set()
                if _verbose_ticker and _verbose_ticker.is_started:
                    _verbose_ticker.stop()
                if live.is_started:
                    live.stop()
                console.print(f"\n[bold yellow]  Budget ceiling reached: ${cost_so_far:.2f} / ${current_ceiling:.2f}[/bold yellow]")
                _flags = len(agent.state.flags or {})
                if _flags:
                    console.print(f"[dim]  Flags captured: {_flags}[/dim]")
                console.print(f"[dim]  Extend budget to continue the engagement.[/dim]\n")
                _increments = [10, 25, 50]
                for i, inc in enumerate(_increments, 1):
                    console.print(f"  [{i}] +${inc}  (new ceiling: ${current_ceiling + inc:.2f})")
                console.print(f"  [c] Custom amount")
                console.print(f"  [s] Stop run\n")
                while True:
                    try:
                        choice = console.input("[bold]  Extend budget? [/bold]").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        return None
                    if choice == "s":
                        return None
                    if choice == "c":
                        try:
                            amt = float(console.input("  Amount to add: $").strip())
                            if amt > 0:
                                new = current_ceiling + amt
                                console.print(f"[success]  Budget extended → ${new:.2f}[/success]\n")
                                return new
                        except (ValueError, EOFError, KeyboardInterrupt):
                            console.print("[warning]  Invalid amount.[/warning]")
                            continue
                    if choice in ("1", "2", "3"):
                        inc = _increments[int(choice) - 1]
                        new = current_ceiling + inc
                        console.print(f"[success]  Budget extended → ${new:.2f}[/success]\n")
                        return new
                    console.print("[dim]  Enter 1-3, c, or s[/dim]")

            def _prompt_session_limit(frac: float, cost_so_far: float) -> bool:
                """LE/RT: Claude session usage hit the warn threshold. Red warning,
                halt, operator picks continue (fresh session) or stop. Returns True
                to continue, False to stop."""
                _refresh_stop.set()
                if _verbose_ticker and _verbose_ticker.is_started:
                    _verbose_ticker.stop()
                if live.is_started:
                    live.stop()
                console.print(
                    f"\n[bold red]  ⚠  SESSION USAGE {frac * 100:.0f}% — "
                    f"Claude context is nearly full (${cost_so_far:.2f} spent).[/bold red]"
                )
                console.print("[red]  The engagement has been halted.[/red]")
                console.print("[dim]  [c] Continue (starts a fresh session, context resets)[/dim]")
                console.print("[dim]  [s] Stop the run[/dim]\n")
                while True:
                    try:
                        choice = console.input("[bold]  Continue? [c/s] [/bold]").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        return False
                    if choice in ("c", "continue", "y", "yes"):
                        console.print("[success]  Continuing with a fresh session.[/success]\n")
                        return True
                    if choice in ("s", "stop", "n", "no"):
                        return False
                    console.print("[dim]  Enter c or s[/dim]")

            try:
                response = agent.chat(user_input + c2_context, on_status=update_status,
                                      on_progress=on_progress,
                                      on_budget_exceeded=_prompt_budget_extension,
                                      on_session_limit=_prompt_session_limit)
            finally:
                _refresh_stop.set()
                _refresh_thread.join(timeout=2)
                if _verbose_ticker and _verbose_ticker.is_started:
                    _verbose_ticker.stop()
                if live.is_started:
                    live.stop()

            chat_elapsed = time.monotonic() - chat_start
            chat_time_str = f"{int(chat_elapsed // 60):02d}:{int(chat_elapsed % 60):02d}"

            if response:
                console.print(Markdown(response))

                # Show OPSEC warnings for HIGH/CRITICAL commands from this interaction
                high_cmds = [e for e in agent.opsec_log if e["score"] >= LEVEL_HIGH]
                if high_cmds:
                    last_high = [e for e in high_cmds if e == high_cmds[-1]]
                    for entry in last_high:
                        color = LEVEL_COLORS.get(entry["score"], "yellow")
                        console.print(f"\n  [{color}][OPSEC: {entry['level']}][/{color}] {entry['command'][:80]}")
                        for r in entry["reasons"][:2]:
                            console.print(f"    [dim]- {r}[/dim]")

                # Show cost and elapsed time
                cost = getattr(agent, "_last_cost", 0)
                turns = getattr(agent, "_last_turns", 1)
                console.print(f"\n[cost]  {chat_time_str} elapsed | ${cost:.4f} | {turns} turn(s)[/cost]")

            console.print()

        except KeyboardInterrupt:
            # Persist engagement state so discoveries survive the interrupt
            try:
                agent.state.save()
            except Exception:
                pass
            console.print("\n[dim](Ctrl+C — provide context or type /quit to exit)[/dim]")
            continue
        except EOFError:
            if c2.daemon.is_running():
                c2.stop_server()
            console.print("\n[dim]Exiting REDOPS.[/dim]")
            break


if __name__ == "__main__":
    main()
