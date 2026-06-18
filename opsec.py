"""OPSEC scoring engine for red team commands.

Scores commands on a noise/risk scale and provides warnings.
Used by the agent to evaluate Bash commands before execution.

Scoring levels:
    LOW (1)      — Passive, unlikely to trigger alerts
    MEDIUM (2)   — Moderate footprint, may appear in logs
    HIGH (3)     — Likely to trigger EDR/SIEM alerts
    CRITICAL (4) — Almost certain detection, use only as last resort
"""

import re
from dataclasses import dataclass

LEVEL_LOW = 1
LEVEL_MEDIUM = 2
LEVEL_HIGH = 3
LEVEL_CRITICAL = 4

LEVEL_NAMES = {
    LEVEL_LOW: "LOW",
    LEVEL_MEDIUM: "MEDIUM",
    LEVEL_HIGH: "HIGH",
    LEVEL_CRITICAL: "CRITICAL",
}

LEVEL_COLORS = {
    LEVEL_LOW: "green",
    LEVEL_MEDIUM: "yellow",
    LEVEL_HIGH: "bold yellow",
    LEVEL_CRITICAL: "bold red",
}


@dataclass
class OpsecResult:
    score: int
    reasons: list[str]
    alternatives: list[str]
    scope_violation: bool = False
    scope_detail: str = ""

    @property
    def ctf_blocked(self) -> bool:
        return self.score >= LEVEL_CRITICAL and any(
            "CTF ANTI-CHEAT" in r for r in self.reasons
        )

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES.get(self.score, "UNKNOWN")

    @property
    def color(self) -> str:
        return LEVEL_COLORS.get(self.score, "white")

    def format(self) -> str:
        lines = [f"OPSEC: {self.level_name}"]
        if self.scope_violation:
            lines.insert(0, f"  *** SCOPE VIOLATION: {self.scope_detail}")
        for r in self.reasons:
            lines.append(f"  - {r}")
        if self.alternatives:
            lines.append("  Alternatives:")
            for a in self.alternatives:
                lines.append(f"    -> {a}")
        return "\n".join(lines)


# Each rule: (compiled regex, score, reason, list of alternatives)
# Rules are checked against the full command string.
_RULES: list[tuple[re.Pattern, int, str, list[str]]] = []


def _rule(pattern: str, score: int, reason: str, alternatives: list[str] | None = None):
    _RULES.append((re.compile(pattern, re.IGNORECASE), score, reason, alternatives or []))


# --- Network scanning ---
_rule(r"nmap\b.*-T[45]", LEVEL_HIGH,
      "Aggressive nmap timing (-T4/-T5) generates heavy traffic and IDS alerts",
      ["Use -T2 or -T3 for slower, quieter scans"])
_rule(r"nmap\b.*-A\b", LEVEL_HIGH,
      "nmap -A enables OS detection, version detection, scripts, and traceroute — very noisy",
      ["Use targeted flags: -sV for versions, -O for OS only"])
_rule(r"nmap\b.*-sS\b", LEVEL_MEDIUM,
      "SYN scan (-sS) is detectable by modern IDS/firewalls",
      ["Use -sT (full connect) if stealth matters more than speed"])
_rule(r"nmap\b.*-sU\b", LEVEL_MEDIUM,
      "UDP scan is slow and may trigger ICMP rate-limiting alerts")
_rule(r"nmap\b.*--script[= ]", LEVEL_MEDIUM,
      "NSE scripts actively probe services and may trigger alerts",
      ["Use specific scripts rather than categories like 'vuln' or 'default'"])
_rule(r"nmap\b.*-p-\b", LEVEL_MEDIUM,
      "Full port scan (-p-) covers 65535 ports — high traffic volume",
      ["Scan targeted port ranges or top ports (-p 80,443,445,3389)"])
_rule(r"masscan\b", LEVEL_HIGH,
      "Masscan generates extremely high packet rates",
      ["Use nmap with conservative timing instead"])

# --- Credential attacks ---
_rule(r"(secretsdump|dcsync)", LEVEL_CRITICAL,
      "DCSync/secretsdump replicates the domain controller — high-value alert in any SOC",
      ["Consider targeted Kerberoast or AS-REP roast first"])
_rule(r"mimikatz|sekurlsa|lsadump", LEVEL_CRITICAL,
      "Mimikatz is heavily signatured by EDR and triggers immediate alerts",
      ["Use BOFs, nanodump, or in-memory alternatives"])
_rule(r"(crackmapexec|nxc|netexec)\b.*--sam\b", LEVEL_HIGH,
      "Dumping SAM remotely creates named pipe and service events")
_rule(r"(crackmapexec|nxc|netexec)\b.*--lsa\b", LEVEL_HIGH,
      "Dumping LSA secrets remotely is logged and may trigger EDR")
_rule(r"(crackmapexec|nxc|netexec)\b.*--ntds\b", LEVEL_CRITICAL,
      "Dumping NTDS.dit remotely — equivalent to DCSync in detection risk")
_rule(r"(crackmapexec|nxc|netexec)\b.*-M\s+(petitpotam|zerologon|nopac)", LEVEL_CRITICAL,
      "Exploitation modules trigger high-fidelity alerts",
      ["Validate the vulnerability first, then exploit with care"])
_rule(r"hashcat|john\b", LEVEL_LOW,
      "Offline cracking is local-only — no network footprint")
_rule(r"kerbrute\b", LEVEL_MEDIUM,
      "Kerberos brute-force generates failed auth events (Event ID 4771)",
      ["Use small, targeted user lists and long delays"])
_rule(r"rubeus\b.*kerberoast", LEVEL_MEDIUM,
      "Kerberoasting requests RC4 service tickets — detectable via Event ID 4769",
      ["Request AES tickets where possible to reduce detection"])
_rule(r"rubeus\b.*asreproast", LEVEL_MEDIUM,
      "AS-REP roasting targets accounts without pre-auth — logged as Event ID 4768")

# --- Lateral movement ---
_rule(r"psexec", LEVEL_HIGH,
      "PsExec creates a service on the remote host — logged and monitored by EDR",
      ["Use WMI, WinRM, or DCOM for quieter lateral movement"])
_rule(r"wmiexec", LEVEL_MEDIUM,
      "WMI execution is quieter than PsExec but still creates process events")
_rule(r"smbexec", LEVEL_HIGH,
      "SMBExec creates a service similar to PsExec",
      ["Use WMI or WinRM alternatives"])
_rule(r"atexec", LEVEL_MEDIUM,
      "Scheduled task execution creates task scheduler events (Event ID 4698)")
_rule(r"evil-winrm", LEVEL_MEDIUM,
      "WinRM connections are logged in Windows event logs (Event ID 91, 6)")

# --- Scanning & enumeration ---
_rule(r"(crackmapexec|nxc|netexec)\b.*smb\b.*\d+\.\d+\.\d+\.\d+/\d+", LEVEL_MEDIUM,
      "Subnet-wide SMB enumeration generates many authentication attempts",
      ["Target specific hosts rather than ranges"])
_rule(r"enum4linux", LEVEL_MEDIUM,
      "enum4linux performs loud null-session enumeration")
_rule(r"gobuster|feroxbuster|ffuf|dirsearch|dirb\b", LEVEL_MEDIUM,
      "Directory brute-forcing generates high request volumes in web logs",
      ["Use smaller wordlists or lower thread counts to reduce noise"])
_rule(r"nikto\b", LEVEL_HIGH,
      "Nikto sends thousands of known-bad requests — easily fingerprinted",
      ["Use nuclei with targeted templates instead"])
_rule(r"sqlmap\b", LEVEL_HIGH,
      "SQLMap generates many malformed requests — triggers WAF and IDS",
      ["Test manually first, then use sqlmap with --risk 1 --level 1 and --random-agent"])
_rule(r"nuclei\b.*-t\b.*cves", LEVEL_MEDIUM,
      "Running CVE templates en masse may trigger IDS signatures")

# --- Payload & exploitation ---
_rule(r"msfconsole|msfvenom|metasploit", LEVEL_HIGH,
      "Metasploit payloads are heavily signatured by AV/EDR",
      ["Use custom payloads or Sliver implants with obfuscation"])
_rule(r"powershell\b.*-enc\b", LEVEL_HIGH,
      "Encoded PowerShell is a top EDR detection signal",
      ["Use unencoded commands or .NET execute-assembly"])
_rule(r"powershell\b.*downloadstring|iex|invoke-expression", LEVEL_HIGH,
      "PowerShell cradles are monitored by AMSI and Script Block Logging",
      ["Stage payloads via disk or use execute-assembly"])
_rule(r"certutil\b.*-urlcache", LEVEL_HIGH,
      "certutil download is a well-known LOLBin technique — heavily monitored",
      ["Use curl, wget, or BitsTransfer instead"])
_rule(r"bitsadmin\b.*transfer", LEVEL_MEDIUM,
      "BitsAdmin transfers are logged and monitored by some EDRs")

# --- Destructive / risky ---
_rule(r"rm\s+-rf\s+/", LEVEL_CRITICAL,
      "Recursive deletion from root — extremely destructive")
_rule(r":(){ :\|:& };:", LEVEL_CRITICAL,
      "Fork bomb — will crash the system")
_rule(r"mkfifo|/dev/tcp", LEVEL_MEDIUM,
      "Bash reverse shells are detectable by process monitoring")
_rule(r"nc\b.*-[elp]|ncat\b.*-[elp]", LEVEL_MEDIUM,
      "Netcat listeners/connections may trigger network monitoring")

# --- CTF anti-cheat: writeup/walkthrough access ---
# These only fire when CTF mode is enabled (checked in score_command).
# Stored separately from _RULES so they can be conditionally applied.
_CTF_WRITEUP_DOMAINS = [
    # Writeup aggregators
    r"0xdf\.gitlab\.io", r"ippsec\.rocks", r"rana-khalil\.", r"hackingarticles\.in",
    r"medium\.com.{0,50}(htb|hackthebox|ctf|writeup|walkthrough)",
    r"infosecwriteups\.com", r"0xrick\.", r"snowscan\.",
    # HackTheBox specific
    r"hackthebox\.(com|eu).{0,50}(writeup|walkthrough|solution|guide|retired|official)",
    r"htb-.*writeup", r"htb-.*walkthrough",
    # General CTF writeup sites
    r"ctftime\.org/writeups", r"ctfwriteup", r"writeups?\..*ctf",
    # YouTube walkthroughs
    r"youtube\.com.{0,80}(htb|hackthebox|ctf|walkthrough|ippsec)",
    r"youtu\.be.{0,30}(htb|hackthebox)",
    # Forums with solutions
    r"forum\.hackthebox\.(com|eu)",
    # Writeup repos
    r"github\.com.{0,80}(htb|hackthebox|ctf).{0,40}(writeup|walkthrough|solution)",
    # Blog/guide platforms with CTF solution content
    r"hashnode\..{0,50}(htb|hackthebox|ctf|writeup|walkthrough)",
    r"dev\.to.{0,50}(htb|hackthebox|ctf|writeup|walkthrough)",
    r"notion\.site.{0,50}(htb|hackthebox|ctf|writeup|walkthrough)",
    r"gitbook\.io.{0,80}(htb|hackthebox|ctf|writeup|walkthrough)",
    # Dedicated walkthrough/guide platforms
    r"bengrewell\.", r"0xss0rz\.", r"ar33zy\.", r"ivanitlearning\.",
    r"d4mianwayne\.", r"manuelvargastapia\.",
    r"blog\.tryhackme\.com.{0,50}(writeup|walkthrough|solution)",
    # Reddit solution threads
    r"reddit\.com.{0,60}(htb|hackthebox|ctf).{0,40}(writeup|walkthrough|solution|how.?to|hint)",
    # Discord leak channels (public invite links to CTF solution servers)
    r"discord\.(gg|com).{0,60}(htb|hackthebox|ctf).{0,30}(writeup|solution)",
    # AI chatbots used to get box solutions
    r"chat\.openai\.com", r"chatgpt\.com",
    r"bard\.google\.com", r"gemini\.google\.com",
    r"claude\.ai",
    r"perplexity\.ai",
    r"phind\.com",
    r"you\.com.{0,40}(chat|search)",
]

# Broader patterns for web requests that look like writeup fetching
_CTF_WRITEUP_PATTERNS = [
    r"(curl|wget|lynx|w3m|fetch|http).{0,100}(writeup|walkthrough|solution|guide|cheatsheet).{0,50}(htb|hackthebox|ctf)",
    r"(curl|wget|lynx|w3m|fetch|http).{0,100}(htb|hackthebox).{0,50}(writeup|walkthrough|solution)",
    r"searchsploit.{0,30}(walkthrough|writeup)",
]

# Search engine queries seeking box solutions (not tool docs)
_CTF_SEARCH_PATTERNS = [
    # Google/DDG/Bing searches for box walkthroughs
    r"(google|duckduckgo|bing|startpage|searx)\..{0,30}(q=|search\?|\/search).{0,80}(writeup|walkthrough|solution|how.?to.?solve|flag|root\.txt|user\.txt).{0,40}(htb|hackthebox|tryhackme|ctf|vulnhub)",
    r"(google|duckduckgo|bing|startpage|searx)\..{0,30}(q=|search\?|\/search).{0,80}(htb|hackthebox|tryhackme|ctf|vulnhub).{0,40}(writeup|walkthrough|solution|how.?to|guide|hint|flag)",
    # Curl/wget to search engines with CTF solution queries
    r"(curl|wget).{0,60}(google|duckduckgo|bing).{0,60}(writeup|walkthrough|solution).{0,40}(htb|hackthebox|ctf)",
    r"(curl|wget).{0,60}(google|duckduckgo|bing).{0,60}(htb|hackthebox|ctf).{0,40}(writeup|walkthrough|solution)",
    # Googler/ddgr/surfraw CLI search tools
    r"(googler|ddgr|surfraw|s )\s.{0,80}(writeup|walkthrough|solution).{0,40}(htb|hackthebox|ctf)",
    r"(googler|ddgr|surfraw|s )\s.{0,80}(htb|hackthebox|ctf).{0,40}(writeup|walkthrough|solution|guide)",
]

_CTF_RULES: list[tuple[re.Pattern, int, str, list[str]]] = []
for domain_pattern in _CTF_WRITEUP_DOMAINS:
    _CTF_RULES.append((
        re.compile(domain_pattern, re.IGNORECASE),
        LEVEL_CRITICAL,
        "CTF ANTI-CHEAT: Accessing writeup/walkthrough/AI-assistant site is prohibited — solve independently",
        ["Use your own analysis and the tools available on this system"],
    ))
for wp in _CTF_WRITEUP_PATTERNS:
    _CTF_RULES.append((
        re.compile(wp, re.IGNORECASE),
        LEVEL_CRITICAL,
        "CTF ANTI-CHEAT: Fetching writeup/walkthrough content is prohibited",
        ["Analyze the target using your own methodology"],
    ))
for sp in _CTF_SEARCH_PATTERNS:
    _CTF_RULES.append((
        re.compile(sp, re.IGNORECASE),
        LEVEL_CRITICAL,
        "CTF ANTI-CHEAT: Searching for box solutions is prohibited — solve independently",
        ["Use tool documentation, man pages, exploit-db, and CVE databases instead"],
    ))

# --- OPSEC-positive patterns (reduce score) ---
# These are handled as negative rules in the scoring logic


def score_command(command: str, scope_enforcer=None, ctf_mode: bool = False) -> OpsecResult:
    """Score a command string for OPSEC risk.

    Returns an OpsecResult with the highest matching score,
    all matching reasons, and suggested alternatives.

    Args:
        command: The command string to score
        scope_enforcer: Optional ScopeEnforcer instance for scope violation detection
        ctf_mode: When True, also check for writeup/walkthrough access
    """
    if not command or not command.strip():
        return OpsecResult(score=LEVEL_LOW, reasons=["Empty command"], alternatives=[])

    max_score = LEVEL_LOW
    reasons = []
    alternatives = []
    scope_violation = False
    scope_detail = ""

    # Check scope violations if enforcer is provided
    if scope_enforcer:
        in_scope, detail = scope_enforcer.validate_command(command)
        if not in_scope:
            scope_violation = True
            scope_detail = detail
            max_score = LEVEL_CRITICAL
            reasons.append(f"SCOPE VIOLATION: {detail}")
            alternatives.append("Only target in-scope hosts as defined in the engagement scope")

    for pattern, rule_score, reason, alts in _RULES:
        if pattern.search(command):
            if rule_score > max_score:
                max_score = rule_score
            reasons.append(reason)
            alternatives.extend(alts)

    # CTF anti-cheat rules
    if ctf_mode:
        for pattern, rule_score, reason, alts in _CTF_RULES:
            if pattern.search(command):
                if rule_score > max_score:
                    max_score = rule_score
                reasons.append(reason)
                alternatives.extend(alts)

    if not reasons:
        reasons.append("No known OPSEC concerns for this command")

    return OpsecResult(
        score=max_score, reasons=reasons, alternatives=alternatives,
        scope_violation=scope_violation, scope_detail=scope_detail,
    )


def format_score_badge(result: OpsecResult) -> str:
    """Return a short colored badge string for Rich console output."""
    return f"[{result.color}][OPSEC: {result.level_name}][/{result.color}]"


if __name__ == "__main__":
    # Quick test
    import sys
    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
        result = score_command(cmd)
        print(result.format())
    else:
        test_cmds = [
            "nmap -sS -T2 10.10.10.0/24",
            "nmap -A -T5 -p- 10.10.10.0/24",
            "crackmapexec smb 10.10.10.0/24 --ntds",
            "hashcat -m 13100 hashes.txt wordlist.txt",
            "secretsdump.py domain/user:pass@dc01",
            "curl http://10.10.10.1/api/version",
            "gobuster dir -u http://target -w big.txt -t 50",
            "powershell -enc SQBFAFgA",
        ]
        for cmd in test_cmds:
            r = score_command(cmd)
            print(f"[{r.level_name:8}] {cmd}")
            for reason in r.reasons:
                print(f"           - {reason}")
            print()
