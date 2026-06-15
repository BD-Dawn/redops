"""Secret vault — tokenizes sensitive engagement data before it reaches the cloud API.

Stores token↔value mappings locally. Prompts sent to the API contain only tokens
(CRED_001, HOST_001, etc.). Dereference happens at command execution time on the
local machine. The cloud API never sees raw credentials, hostnames, or hashes.

Encryption at rest uses Fernet symmetric encryption with a machine-derived key
so vault files are not useful if exfiltrated.

Active in LE and Red Team modes. CTF mode skips tokenization (synthetic data).
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Optional


# --- Encryption helpers (Fernet, key derived from machine ID) ---

def _derive_key() -> bytes:
    """Derive a Fernet key from stable machine identifiers.

    Uses machine-id + username. If machine-id doesn't exist (container, etc.),
    falls back to hostname + username. Not meant to be unbreakable — just
    ensures vault files aren't portable between machines.
    """
    from cryptography.fernet import Fernet
    import base64

    seed_parts = [os.getenv("USER", "redops")]

    # Linux machine-id (stable across reboots)
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            seed_parts.append(Path(path).read_text().strip())
            break
        except (FileNotFoundError, PermissionError):
            continue
    else:
        # Fallback to hostname
        import socket
        seed_parts.append(socket.gethostname())

    seed = ":".join(seed_parts).encode()
    # SHA-256 → 32 bytes → base64-encode for Fernet (requires url-safe base64)
    key_bytes = hashlib.sha256(seed).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _encrypt(data: str) -> bytes:
    """Encrypt a string with machine-derived key."""
    from cryptography.fernet import Fernet
    f = Fernet(_derive_key())
    return f.encrypt(data.encode())


def _decrypt(data: bytes) -> str:
    """Decrypt bytes with machine-derived key."""
    from cryptography.fernet import Fernet
    f = Fernet(_derive_key())
    return f.decrypt(data).decode()


# --- Token types ---

TOKEN_TYPES = {
    "cred_user": "CRED_{:03d}_USER",
    "cred_pass": "CRED_{:03d}_PASS",
    "cred_hash": "CRED_{:03d}_HASH",
    "host": "HOST_{:03d}",
    "hash": "HASH_{:03d}",
    "domain": "DOMAIN_{:03d}",
    "secret": "SECRET_{:03d}",
}

# Regex that matches any vault token in text
_TOKEN_PATTERN = re.compile(
    r"\b(CRED_\d{3}_(?:USER|PASS|HASH)|HOST_\d{3}|HASH_\d{3}|DOMAIN_\d{3}|SECRET_\d{3})\b"
)


class SecretVault:
    """Local secret store that maps tokens to sensitive values.

    Usage:
        vault = SecretVault(engagement_dir)
        vault.register_credential("admin", "P@ssw0rd!", "password")
        tokenized = vault.tokenize("login admin:P@ssw0rd!")
        # → "login CRED_001_USER:CRED_001_PASS"
        real_cmd = vault.dereference("evil-winrm -u CRED_001_USER -p CRED_001_PASS")
        # → "evil-winrm -u admin -p P@ssw0rd!"
    """

    def __init__(self, engagement_dir: Path, enabled: bool = True):
        self.enabled = enabled
        self._dir = engagement_dir
        self._vault_path = engagement_dir / "vault.enc"

        # Forward map: token → value
        self._tokens: dict[str, str] = {}
        # Reverse map: value → token (for tokenizing text)
        self._values: dict[str, str] = {}

        # Counters per type
        self._counters: dict[str, int] = {
            "cred": 0,
            "host": 0,
            "hash": 0,
            "domain": 0,
            "secret": 0,
        }

        # Load existing vault
        self._load()

    def _next_id(self, type_key: str) -> int:
        """Get next sequential ID for a token type."""
        self._counters[type_key] = self._counters.get(type_key, 0) + 1
        return self._counters[type_key]

    # --- Registration methods ---

    def register_credential(self, username: str, secret: str, secret_type: str = "password") -> dict[str, str]:
        """Register a credential pair. Returns dict of token→value mappings added."""
        if not self.enabled or not username or not secret:
            return {}

        # Skip if already registered
        if username in self._values and secret in self._values:
            return {}

        cred_id = self._next_id("cred")
        mappings = {}

        # Username token
        user_token = TOKEN_TYPES["cred_user"].format(cred_id)
        if username not in self._values:
            self._tokens[user_token] = username
            self._values[username] = user_token
            mappings[user_token] = username

        # Secret token (password, hash, or key)
        if secret_type in ("ntlm", "hash", "lm", "nt"):
            pass_token = TOKEN_TYPES["cred_hash"].format(cred_id)
        else:
            pass_token = TOKEN_TYPES["cred_pass"].format(cred_id)
        if secret not in self._values:
            self._tokens[pass_token] = secret
            self._values[secret] = pass_token
            mappings[pass_token] = secret

        self._save()
        return mappings

    def register_host(self, hostname: str, ip: str = "") -> dict[str, str]:
        """Register a host (hostname and/or IP). Returns mappings added."""
        if not self.enabled:
            return {}

        mappings = {}
        for value in (hostname, ip):
            if not value or value in self._values:
                continue
            host_id = self._next_id("host")
            token = TOKEN_TYPES["host"].format(host_id)
            self._tokens[token] = value
            self._values[value] = token
            mappings[token] = value

        if mappings:
            self._save()
        return mappings

    def register_hash(self, hash_value: str) -> Optional[str]:
        """Register a standalone hash. Returns token or None if already registered."""
        if not self.enabled or not hash_value or hash_value in self._values:
            return None

        hash_id = self._next_id("hash")
        token = TOKEN_TYPES["hash"].format(hash_id)
        self._tokens[token] = hash_value
        self._values[hash_value] = token
        self._save()
        return token

    def register_domain(self, domain: str) -> Optional[str]:
        """Register a domain name. Returns token or None."""
        if not self.enabled or not domain or domain in self._values:
            return None

        dom_id = self._next_id("domain")
        token = TOKEN_TYPES["domain"].format(dom_id)
        self._tokens[token] = domain
        self._values[domain] = token
        self._save()
        return token

    def register_secret(self, value: str, label: str = "") -> Optional[str]:
        """Register an arbitrary secret value. Returns token."""
        if not self.enabled or not value or value in self._values:
            return None

        sec_id = self._next_id("secret")
        token = TOKEN_TYPES["secret"].format(sec_id)
        self._tokens[token] = value
        self._values[value] = token
        self._save()
        return token

    # --- Tokenization / Dereference ---

    def tokenize(self, text: str) -> str:
        """Replace all known secret values in text with their tokens.

        Processes longer values first to avoid partial matches
        (e.g., 'admin@domain.local' before 'admin').
        """
        if not self.enabled or not text or not self._values:
            return text

        # Sort by value length descending — longest match first
        for value, token in sorted(self._values.items(), key=lambda x: -len(x[0])):
            if len(value) < 3:
                continue  # skip tiny values to avoid false positives
            if value in text:
                text = text.replace(value, token)
        return text

    def dereference(self, text: str) -> str:
        """Replace all tokens in text with their real values."""
        if not self.enabled or not text or not self._tokens:
            return text

        def _replace(match):
            token = match.group(0)
            return self._tokens.get(token, token)

        return _TOKEN_PATTERN.sub(_replace, text)

    def has_tokens(self, text: str) -> bool:
        """Check if text contains any vault tokens."""
        return bool(_TOKEN_PATTERN.search(text))

    # --- Bulk registration from engagement state ---

    def register_from_engagement(self, state) -> int:
        """Auto-register all secrets from an engagement state object.

        Call this when loading an engagement or when new data is discovered.
        Returns number of new registrations.
        """
        if not self.enabled:
            return 0

        count = 0

        # Credentials
        for cred in getattr(state, "credentials", []):
            username = cred.get("username", "")
            secret = cred.get("secret", "")
            stype = cred.get("type", "password")
            if username and secret:
                added = self.register_credential(username, secret, stype)
                count += len(added)

        # Compromised hosts
        for host in getattr(state, "compromised_hosts", []):
            hostname = host.get("hostname", "")
            ip = host.get("ip", "")
            added = self.register_host(hostname, ip)
            count += len(added)

        # Target
        target = getattr(state, "target", "")
        if target:
            self.register_host(target)
            count += 1

        # Discovered hosts
        for host in getattr(state, "discovered_hosts", []):
            if isinstance(host, dict):
                self.register_host(host.get("hostname", ""), host.get("ip", ""))
            elif isinstance(host, str):
                self.register_host(host)
            count += 1

        return count

    # --- Persistence (encrypted) ---

    def _save(self):
        """Persist vault to encrypted file."""
        if not self.enabled:
            return
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            data = json.dumps({
                "tokens": self._tokens,
                "counters": self._counters,
            })
            encrypted = _encrypt(data)
            self._vault_path.write_bytes(encrypted)
        except Exception:
            # Fallback: save unencrypted if cryptography not available
            try:
                fallback = self._dir / "vault.json"
                fallback.write_text(json.dumps({
                    "tokens": self._tokens,
                    "counters": self._counters,
                }, indent=2))
            except Exception:
                pass

    def _load(self):
        """Load vault from encrypted file."""
        if not self.enabled:
            return

        # Try encrypted first
        if self._vault_path.exists():
            try:
                encrypted = self._vault_path.read_bytes()
                data = json.loads(_decrypt(encrypted))
                self._tokens = data.get("tokens", {})
                self._counters = data.get("counters", {
                    "cred": 0, "host": 0, "hash": 0, "domain": 0, "secret": 0,
                })
                # Rebuild reverse map
                self._values = {v: k for k, v in self._tokens.items()}
                return
            except Exception:
                pass

        # Try unencrypted fallback
        fallback = self._dir / "vault.json"
        if fallback.exists():
            try:
                data = json.loads(fallback.read_text())
                self._tokens = data.get("tokens", {})
                self._counters = data.get("counters", {
                    "cred": 0, "host": 0, "hash": 0, "domain": 0, "secret": 0,
                })
                self._values = {v: k for k, v in self._tokens.items()}
            except Exception:
                pass

    def summary(self) -> str:
        """Return a compact summary of vault contents."""
        if not self.enabled:
            return "Vault: disabled (CTF mode)"
        types = {}
        for token in self._tokens:
            prefix = token.split("_")[0]
            types[prefix] = types.get(prefix, 0) + 1
        parts = [f"{k}:{v}" for k, v in sorted(types.items())]
        return f"Vault: {len(self._tokens)} tokens ({', '.join(parts) or 'empty'})"

    def write_deref_script(self) -> Optional[Path]:
        """Write a bash deref helper script to the engagement directory.

        The agent sources this script to get shell variables for all tokens.
        This way the agent can write: evil-winrm -u $CRED_001_USER -p $CRED_001_PASS
        and bash dereferences locally — the real values never appear in the
        conversation context sent to the API.

        Returns path to the script, or None if vault is disabled/empty.
        """
        if not self.enabled or not self._tokens:
            return None

        self._dir.mkdir(parents=True, exist_ok=True)
        script_path = self._dir / ".vault_env.sh"
        lines = ["#!/bin/bash", "# Auto-generated vault env — DO NOT COMMIT"]
        for token, value in sorted(self._tokens.items()):
            # Escape single quotes in values
            escaped = value.replace("'", "'\\''")
            lines.append(f"export {token}='{escaped}'")
        lines.append("")  # trailing newline

        script_path.write_text("\n".join(lines))
        script_path.chmod(0o600)  # owner-only read
        return script_path

    def prompt_section(self) -> str:
        """Build a prompt section that tells the agent how to use vault tokens.

        Lists token names (NOT values) and instructs the agent to use
        $TOKEN_NAME in bash commands. Values are resolved by the shell
        via the sourced .vault_env.sh script.
        """
        if not self.enabled or not self._tokens:
            return ""

        lines = [
            "\n## SECRET VAULT (sensitive values tokenized)",
            "Credentials and secrets are stored in environment variables.",
            "Use `source $VAULT_ENV` at the start of any bash session, then",
            "reference secrets as `$TOKEN_NAME` in commands. NEVER type the",
            "raw value — always use the variable reference.\n",
        ]

        # Group by credential sets
        cred_ids = set()
        for token in self._tokens:
            if token.startswith("CRED_"):
                cred_id = token.split("_")[1]  # e.g., "001"
                cred_ids.add(cred_id)

        for cred_id in sorted(cred_ids):
            parts = []
            for suffix in ("USER", "PASS", "HASH"):
                token = f"CRED_{cred_id}_{suffix}"
                if token in self._tokens:
                    parts.append(f"${token}")
            if parts:
                lines.append(f"- Credential set {cred_id}: {', '.join(parts)}")

        # Hosts
        host_tokens = sorted(t for t in self._tokens if t.startswith("HOST_"))
        if host_tokens:
            lines.append(f"- Hosts: {', '.join('$' + t for t in host_tokens)}")

        # Hashes
        hash_tokens = sorted(t for t in self._tokens if t.startswith("HASH_"))
        if hash_tokens:
            lines.append(f"- Hashes: {', '.join('$' + t for t in hash_tokens)}")

        # Domains
        dom_tokens = sorted(t for t in self._tokens if t.startswith("DOMAIN_"))
        if dom_tokens:
            lines.append(f"- Domains: {', '.join('$' + t for t in dom_tokens)}")

        lines.append(
            "\nExample: `source $VAULT_ENV && evil-winrm -u $CRED_001_USER "
            "-p $CRED_001_PASS -i $HOST_001`"
        )

        return "\n".join(lines)
