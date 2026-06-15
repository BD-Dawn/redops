"""Per-engagement verbose logging.

Writes structured logs to data/engagements/<mode>/<target>/engagement.log.
Captures infrastructure events: crashes, errors, auth failures, stuck kills,
auto-continues, context overflows, cost/time, milestones, etc.

Modes:
  CTF / LE: log everything verbatim.
  Red Team: scrub sensitive data (credentials, hashes, PII, internal hostnames)
            before writing — logs may be shared with clients or stored long-term.
"""

import re
import logging
from datetime import datetime
from pathlib import Path


# Scrubbing patterns for red team mode.
# Each: (compiled regex, replacement string)
_SCRUB_PATTERNS: list[tuple[re.Pattern, str]] = [
    # NTLM hashes — user:RID:LM:NT
    (re.compile(r"([a-zA-Z0-9_\.\-]+):\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"), r"\1:<NTLM_HASH_REDACTED>"),
    # Standalone 32-char hex that looks like a hash (NT, LM, MD5)
    (re.compile(r"\b[a-fA-F0-9]{32}\b"), "<HASH_REDACTED>"),
    # Kerberos tickets / base64 blobs (50+ chars of base64)
    (re.compile(r"[A-Za-z0-9+/]{50,}={0,2}"), "<BASE64_REDACTED>"),
    # Password values after common labels
    (re.compile(r"(password|passwd|secret|pwd|pass)\s*[:=]\s*\S+", re.IGNORECASE), r"\1=<REDACTED>"),
    # Credential pairs — user:password in structured output
    (re.compile(r"(\w+):(\S+)\[(password|plaintext|ntlm|hash|kerberos|ccache)\]"), r"\1:<REDACTED>[\3]"),
    # Email addresses
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "<EMAIL_REDACTED>"),
    # Internal hostnames (FQDN with internal-looking TLDs)
    (re.compile(r"\b[a-zA-Z0-9-]+\.(internal|local|corp|ad|intra|lan)\b", re.IGNORECASE), "<HOST_REDACTED>"),
    # Windows domain\user
    (re.compile(r"[A-Z][A-Z0-9_-]{1,15}\\[a-zA-Z0-9_.\-]+"), "<DOMAIN_USER_REDACTED>"),
    # SSH/RSA private keys
    (re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----"), "<PRIVATE_KEY_REDACTED>"),
]


def _scrub(text: str) -> str:
    """Remove sensitive data from a log message for red team mode."""
    for pattern, replacement in _SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class EngagementLogger:
    """Structured logger that writes to per-engagement log files.

    Usage:
        logger = EngagementLogger(engagement.dir, engagement.engagement_mode)
        logger.info("session_start", agent="redops", turns=25)
        logger.error("auth_failure", detail="401 from Claude API")
    """

    def __init__(self, engagement_dir: Path, mode: str = "ctf"):
        self.mode = mode
        self._scrub = mode == "redteam"
        self._log_path = engagement_dir / "engagement.log"
        engagement_dir.mkdir(parents=True, exist_ok=True)

        # Python logger with file handler — one per engagement
        self._logger = logging.getLogger(f"engagement.{engagement_dir.name}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False

        # Avoid duplicate handlers on re-init
        if not self._logger.handlers:
            handler = logging.FileHandler(self._log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def _format(self, level: str, event: str, **kwargs) -> str:
        """Build a structured log line."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts = [f"[{ts}] [{level}] {event}"]
        for k, v in kwargs.items():
            v_str = str(v)
            if self._scrub:
                v_str = _scrub(v_str)
            # Truncate long values
            if len(v_str) > 500:
                v_str = v_str[:500] + "..."
            parts.append(f"  {k}={v_str}")
        return " | ".join(parts)

    def info(self, event: str, **kwargs):
        self._logger.info(self._format("INFO", event, **kwargs))

    def warn(self, event: str, **kwargs):
        self._logger.warning(self._format("WARN", event, **kwargs))

    def error(self, event: str, **kwargs):
        self._logger.error(self._format("ERROR", event, **kwargs))

    def debug(self, event: str, **kwargs):
        self._logger.debug(self._format("DEBUG", event, **kwargs))

    # --- Convenience methods for common events ---

    def session_start(self, agent: str, session_id: str = "", turns: int = 0,
                      model: str = "", resumed: bool = False):
        self.info("session_start", agent=agent, session_id=session_id or "new",
                  max_turns=turns, model=model, resumed=resumed)

    def session_end(self, agent: str, cost: float, turns: int, elapsed: float,
                    session_id: str = ""):
        self.info("session_end", agent=agent, cost=f"${cost:.4f}", turns=turns,
                  elapsed=f"{elapsed:.1f}s", session_id=session_id)

    def auto_continue(self, reason: str, count: int, max_count: int, cost_so_far: float):
        self.info("auto_continue", reason=reason, count=f"{count}/{max_count}",
                  total_cost=f"${cost_so_far:.4f}")

    def stuck_detected(self, agent: str, message: str, categories: str,
                       auto_restart: bool = False):
        self.warn("stuck_detected", agent=agent, message=message,
                  exhausted=categories, auto_restart=auto_restart)

    def milestone(self, agent: str, priority: int, label: str):
        self.info("milestone", agent=agent, priority=priority, label=label)

    def flag_captured(self, flag_type: str, flag_hash: str):
        if self.mode != "ctf":
            return  # flags only exist in CTF mode
        self.info("flag_captured", type=flag_type, value=flag_hash)

    def auth_failure(self, detail: str):
        self.error("auth_failure", detail=detail)

    def context_overflow(self, agent: str, turns: int):
        self.warn("context_overflow", agent=agent, turns_completed=turns)

    def command_error(self, agent: str, command: str, error: str):
        cmd = command[:200]
        err = error[:300]
        if self._scrub:
            cmd = _scrub(cmd)
            err = _scrub(err)
        self.error("command_error", agent=agent, command=cmd, error=err)

    def crash(self, agent: str, error: str, context: str = ""):
        self.error("crash", agent=agent, error=error[:500],
                   context=context[:200] if context else "")

    def compaction(self, input_chunks: int, output_chars: int, elapsed: float):
        self.info("compaction", input_chunks=input_chunks,
                  output_chars=output_chars, elapsed=f"{elapsed:.1f}s")

    def opsec_event(self, agent: str, command: str, level: str, reasons: str):
        cmd = command[:200]
        if self._scrub:
            cmd = _scrub(cmd)
        self.info("opsec", agent=agent, command=cmd, level=level, reasons=reasons)
