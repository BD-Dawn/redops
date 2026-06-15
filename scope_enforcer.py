"""Scope and ROE enforcement — deterministic validation of targets and commands.

Two enforcement layers:
1. Hard (orchestrator-level): validates targets before agent dispatch
2. Soft (opsec audit): validates IPs/domains extracted from commands

All checks are deterministic — no LLM calls. Uses ipaddress module for CIDR
matching and regex for domain/URL matching.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScopeDefinition:
    """Parsed scope definition with deterministic matching."""

    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    domain_wildcards: list[str] = field(default_factory=list)  # *.example.com
    url_prefixes: list[str] = field(default_factory=list)
    exclusions_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    exclusions_domains: list[str] = field(default_factory=list)
    exclusions_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=list)
    raw_text: str = ""

    @classmethod
    def parse(cls, scope_text: str) -> "ScopeDefinition":
        """Parse a human-readable scope string into a structured definition.

        Handles formats:
        - CIDR: 10.10.10.0/24, 192.168.1.0/16
        - Individual IPs: 10.10.10.5
        - Domains: example.com, app.example.com
        - Wildcards: *.example.com
        - URLs: https://app.example.com/api/
        - Exclusions: lines starting with ! or "exclude:" or "out of scope:"

        Lines are split on newlines and commas. Each token is classified.
        """
        sd = cls(raw_text=scope_text)

        # Normalize: split on newlines, commas, semicolons
        tokens = re.split(r"[,;\n]+", scope_text)

        in_exclusion_section = False

        for raw_token in tokens:
            token = raw_token.strip()
            if not token:
                continue

            # Detect exclusion markers
            lower = token.lower()
            if lower.startswith(("out of scope", "exclusion", "excluded", "not in scope")):
                in_exclusion_section = True
                # Strip the marker prefix and continue parsing the rest
                token = re.sub(
                    r"^(out of scope|exclusion|excluded|not in scope)\s*[:—-]*\s*",
                    "", token, flags=re.IGNORECASE,
                ).strip()
                if not token:
                    continue

            if lower.startswith(("in scope", "in-scope", "scope:")):
                in_exclusion_section = False
                token = re.sub(
                    r"^(in[- ]scope|scope)\s*[:—-]*\s*",
                    "", token, flags=re.IGNORECASE,
                ).strip()
                if not token:
                    continue

            # Check for per-line exclusion prefix
            is_excluded = in_exclusion_section
            if token.startswith("!"):
                is_excluded = True
                token = token[1:].strip()
            elif lower.startswith("exclude:"):
                is_excluded = True
                token = token[8:].strip()

            if not token:
                continue

            # Skip descriptive text (long tokens with spaces are likely prose)
            if len(token) > 80 and " " in token:
                continue

            # Classify the token
            cls._classify_token(sd, token, is_excluded)

        return sd

    @classmethod
    def _classify_token(cls, sd: "ScopeDefinition", token: str, excluded: bool):
        """Classify a single token and add it to the appropriate list."""
        # Strip surrounding quotes, brackets, etc.
        token = token.strip("\"'`[]() ")

        # URL
        if token.startswith(("http://", "https://")):
            if excluded:
                # Extract domain from URL for exclusion
                parsed = urlparse(token)
                if parsed.hostname:
                    sd.exclusions_domains.append(parsed.hostname.lower())
            else:
                sd.url_prefixes.append(token.rstrip("/"))
                # Also add the domain
                parsed = urlparse(token)
                if parsed.hostname:
                    sd.domains.append(parsed.hostname.lower())
            return

        # Wildcard domain: *.example.com
        if token.startswith("*."):
            domain = token[2:].lower()
            if excluded:
                sd.exclusions_domains.append(token.lower())
            else:
                sd.domain_wildcards.append(domain)
            return

        # Try IP address or CIDR
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                if excluded:
                    sd.exclusions_cidrs.append(network)
                else:
                    sd.cidrs.append(network)
                return
            else:
                addr = ipaddress.ip_address(token)
                if excluded:
                    sd.exclusions_ips.append(addr)
                else:
                    sd.ips.append(addr)
                return
        except ValueError:
            pass

        # Domain name (contains dots, no spaces, reasonable length)
        if "." in token and " " not in token and len(token) < 255:
            # Basic domain validation
            domain = token.lower().rstrip(".")
            if re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", domain):
                if excluded:
                    sd.exclusions_domains.append(domain)
                else:
                    sd.domains.append(domain)

    def summary(self) -> str:
        """Human-readable summary of the parsed scope."""
        lines = ["**Parsed Scope Definition:**"]
        if self.cidrs:
            lines.append(f"  CIDRs: {', '.join(str(c) for c in self.cidrs)}")
        if self.ips:
            lines.append(f"  IPs: {', '.join(str(ip) for ip in self.ips)}")
        if self.domains:
            lines.append(f"  Domains: {', '.join(self.domains)}")
        if self.domain_wildcards:
            lines.append(f"  Wildcards: {', '.join('*.' + w for w in self.domain_wildcards)}")
        if self.url_prefixes:
            lines.append(f"  URLs: {', '.join(self.url_prefixes)}")
        if self.exclusions_cidrs or self.exclusions_domains or self.exclusions_ips:
            excl = []
            excl.extend(str(c) for c in self.exclusions_cidrs)
            excl.extend(str(ip) for ip in self.exclusions_ips)
            excl.extend(self.exclusions_domains)
            lines.append(f"  Exclusions: {', '.join(excl)}")
        if not any([self.cidrs, self.ips, self.domains, self.domain_wildcards, self.url_prefixes]):
            lines.append("  (no structured scope parsed — enforcement relies on prompt-based rules)")
        return "\n".join(lines)


class ScopeEnforcer:
    """Deterministic scope enforcement engine."""

    def __init__(self, scope_def: ScopeDefinition):
        self.scope = scope_def

    def is_in_scope(self, target: str) -> tuple[bool, str]:
        """Check if a target (IP, domain, URL) is in scope.

        Returns (in_scope: bool, reason: str).
        If scope is empty/unparsed, returns (True, "no scope defined").
        """
        if not self._has_scope():
            return True, "no structured scope defined — relying on prompt-based rules"

        target = target.strip().lower()

        # Check exclusions first
        excluded, excl_reason = self._check_exclusions(target)
        if excluded:
            return False, excl_reason

        # URL target — check URL prefixes and extract domain
        if target.startswith(("http://", "https://")):
            # Check URL prefix match
            for prefix in self.scope.url_prefixes:
                if target.startswith(prefix.lower()):
                    return True, f"matches URL prefix {prefix}"
            # Extract hostname and check domain/IP lists
            parsed = urlparse(target)
            if parsed.hostname:
                return self._check_host(parsed.hostname)
            return False, f"cannot parse hostname from URL: {target}"

        # IP or CIDR target
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                # Check if the target network is a subnet of any scope CIDR
                for cidr in self.scope.cidrs:
                    if network.subnet_of(cidr):
                        return True, f"subnet of scope CIDR {cidr}"
                return False, f"network {target} not within any scope CIDR"
            else:
                addr = ipaddress.ip_address(target)
                return self._check_ip(addr)
        except ValueError:
            pass

        # Domain target
        return self._check_domain(target)

    def _has_scope(self) -> bool:
        """Check if any structured scope was parsed."""
        s = self.scope
        return bool(s.cidrs or s.ips or s.domains or s.domain_wildcards or s.url_prefixes)

    def _check_exclusions(self, target: str) -> tuple[bool, str]:
        """Check if target matches any exclusion rule."""
        # Check IP exclusions
        try:
            addr = ipaddress.ip_address(target)
            for excl_ip in self.scope.exclusions_ips:
                if addr == excl_ip:
                    return True, f"explicitly excluded IP: {excl_ip}"
            for excl_cidr in self.scope.exclusions_cidrs:
                if addr in excl_cidr:
                    return True, f"in excluded CIDR: {excl_cidr}"
        except ValueError:
            pass

        # Check domain exclusions
        target_lower = target.lower().rstrip(".")
        for excl_domain in self.scope.exclusions_domains:
            if excl_domain.startswith("*."):
                suffix = excl_domain[2:]
                if target_lower == suffix or target_lower.endswith("." + suffix):
                    return True, f"matches excluded wildcard: {excl_domain}"
            elif target_lower == excl_domain:
                return True, f"explicitly excluded domain: {excl_domain}"

        return False, ""

    def _check_ip(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
        """Check if an IP address is in scope."""
        # Direct IP match
        for scope_ip in self.scope.ips:
            if addr == scope_ip:
                return True, f"matches scope IP {scope_ip}"

        # CIDR match
        for cidr in self.scope.cidrs:
            if addr in cidr:
                return True, f"within scope CIDR {cidr}"

        return False, f"IP {addr} not in any scope CIDR or IP list"

    def _check_domain(self, domain: str) -> tuple[bool, str]:
        """Check if a domain name is in scope."""
        domain = domain.lower().rstrip(".")

        # Exact domain match
        for scope_domain in self.scope.domains:
            if domain == scope_domain:
                return True, f"exact domain match: {scope_domain}"

        # Wildcard match (*.example.com matches sub.example.com and example.com)
        for wildcard in self.scope.domain_wildcards:
            if domain == wildcard or domain.endswith("." + wildcard):
                return True, f"matches wildcard *.{wildcard}"

        return False, f"domain {domain} not in scope domain list"

    def _check_host(self, host: str) -> tuple[bool, str]:
        """Check a hostname that could be an IP or domain."""
        try:
            addr = ipaddress.ip_address(host)
            return self._check_ip(addr)
        except ValueError:
            return self._check_domain(host)

    def validate_command(self, command: str) -> tuple[bool, str]:
        """Extract targets from a command string and validate each against scope.

        Returns (all_in_scope: bool, violation_detail: str).
        If no targets can be extracted, returns (True, "") — we can't validate
        what we can't parse, and blocking unknown commands would be too aggressive.
        """
        if not self._has_scope():
            return True, ""

        targets = self._extract_targets(command)
        if not targets:
            return True, ""  # Can't extract targets — don't block

        violations = []
        for target in targets:
            in_scope, reason = self.is_in_scope(target)
            if not in_scope:
                violations.append(f"{target}: {reason}")

        if violations:
            return False, "SCOPE VIOLATION: " + "; ".join(violations)
        return True, ""

    @staticmethod
    def _extract_targets(command: str) -> list[str]:
        """Extract IP addresses, CIDRs, domains, and URLs from a command string.

        Best-effort extraction — won't catch everything but covers common patterns.
        """
        targets = set()

        # Extract IPs and CIDRs
        ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b"
        for match in re.finditer(ip_pattern, command):
            candidate = match.group(1)
            try:
                if "/" in candidate:
                    ipaddress.ip_network(candidate, strict=False)
                else:
                    ipaddress.ip_address(candidate)
                # Skip loopback and common non-target IPs
                if not candidate.startswith(("127.", "0.0.0.0", "255.")):
                    targets.add(candidate)
            except ValueError:
                continue

        # Extract URLs
        url_pattern = r"https?://[^\s\"'`<>]+"
        for match in re.finditer(url_pattern, command):
            url = match.group(0).rstrip("\"'`);,")
            parsed = urlparse(url)
            if parsed.hostname:
                targets.add(parsed.hostname)

        # Extract domains from common tool patterns
        # e.g., nmap target.com, curl target.com, ffuf -u https://target.com/FUZZ
        # Look for domain-like tokens (word.word.word)
        domain_pattern = r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,}\b"
        for match in re.finditer(domain_pattern, command):
            domain = match.group(0).lower()
            # Skip common non-target domains
            skip = (
                "github.com", "githubusercontent.com", "google.com",
                "exploit-db.com", "kali.org", "debian.org",
                "pypi.org", "npmjs.com", "apt.get",
            )
            if not any(domain.endswith(s) for s in skip):
                targets.add(domain)

        return list(targets)
