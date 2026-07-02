"""Single source of truth for invoking the `claude` CLI.

Every redops component that shells out to `claude` builds its argv here, and
one-shot callers run the subprocess through this module too. Invocation flags,
model defaults, and timeout wiring therefore live in exactly one place instead
of being copy-pasted across ~20 call sites in both the interactive agent and
the orchestrator/specialist paths.

Two call shapes:
  * oneshot(prompt, ...)  -> subprocess.CompletedProcess   (single text response)
  * stream_argv(...)      -> list[str]                      (argv for stream-json Popen callers)

The streaming callers (interactive agent, specialist BaseAgent, re_agent) keep
their own event-parse loops but share argv construction here so a change to how
we launch `claude` only has to be made once.
"""
from __future__ import annotations

import subprocess

import config as _config

CLAUDE_BIN = "claude"

# The tool set the interactive agent grants by default.
DEFAULT_ALLOWED_TOOLS = "Edit,Write,Read,Bash,Glob,Grep"


def oneshot_argv(model: str, *, max_turns: int | None = 1,
                 output_format: str = "text",
                 extra: list[str] | None = None) -> list[str]:
    """Build argv for a single-response (`-p`) call.

    ``max_turns=None`` omits the ``--max-turns`` flag (a few callers rely on the
    CLI default).
    """
    argv = [CLAUDE_BIN, "-p", "--output-format", output_format]
    if max_turns is not None:
        argv += ["--max-turns", str(max_turns)]
    argv += ["--model", model]
    if extra:
        argv += list(extra)
    return argv


def stream_argv(model: str, *, max_turns: int,
                allowed_tools: str | None = None,
                permission_mode: str | None = "auto",
                resume: str | None = None,
                skip_permissions: bool = False,
                mcp_config: str | None = None,
                extra: list[str] | None = None) -> list[str]:
    """Build argv for a streaming (`--output-format stream-json`) call.

    Callers keep their own event loop over the process's stdout; this only
    centralizes the flag list they all shared. ``permission_mode=None`` omits
    the flag (a caller that relies solely on --dangerously-skip-permissions).
    """
    argv = [
        CLAUDE_BIN, "-p",
        "--output-format", "stream-json",
        "--verbose",
        "--model", model,
        "--max-turns", str(max_turns),
    ]
    if permission_mode:
        argv += ["--permission-mode", permission_mode]
    if allowed_tools:
        argv += ["--allowedTools", allowed_tools]
    if mcp_config:
        argv += ["--mcp-config", mcp_config]
    if resume:
        argv += ["--resume", resume]
    if skip_permissions:
        argv.append("--dangerously-skip-permissions")
    if extra:
        argv += list(extra)
    return argv


def oneshot(prompt: str, *, model: str | None = None,
            max_turns: int | None = 1, timeout: float = 60,
            output_format: str = "text",
            extra: list[str] | None = None,
            cwd: str | None = None, env: dict | None = None):
    """Run a single-response `claude` call and return the CompletedProcess.

    Drop-in for the scattered ``subprocess.run([...], input=prompt, ...)`` calls:
    the return value exposes ``.returncode`` / ``.stdout`` / ``.stderr`` exactly
    as before, and ``subprocess.TimeoutExpired`` still propagates so existing
    ``except`` blocks keep working unchanged.
    """
    if model is None:
        model = _config.MODEL_FAST
    argv = oneshot_argv(model, max_turns=max_turns,
                        output_format=output_format, extra=extra)
    return subprocess.run(
        argv, input=prompt, capture_output=True, text=True,
        timeout=timeout, cwd=cwd, env=env,
    )


def verify_cli(timeout: float = 10) -> subprocess.CompletedProcess:
    """Run ``claude --version``; caller inspects ``.returncode`` / catches
    ``FileNotFoundError`` for a missing binary."""
    return subprocess.run(
        [CLAUDE_BIN, "--version"], capture_output=True, text=True, timeout=timeout,
    )
