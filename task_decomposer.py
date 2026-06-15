"""Task decomposer — breaks broad agent tasks into narrow parallel subtasks.

Instead of dispatching one agent with a 40-turn budget for "do recon",
decomposes into parallel subtasks (port scan, web enum, DNS enum) each
with 8-12 turn budgets. Handles dependency graphs between subtasks.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime

SUBTASK_MAX_TURNS = int(os.getenv("REDOPS_SUBTASK_MAX_TURNS", "3"))


@dataclass
class SubTask:
    """A narrow, focused task for a specialist agent."""
    name: str
    agent: str                    # Which agent type runs this
    task: str                     # Task description (with {placeholders} for templating)
    max_turns: int = SUBTASK_MAX_TURNS
    depends_on: list[str] = field(default_factory=list)  # Names of subtasks this depends on
    host: str = ""                # Target host for this subtask
    skip_condition: str = ""      # Condition description for when to skip (evaluated by decomposer)
    priority: int = 5             # Higher = run first within a batch


# ---------------------------------------------------------------------------
# Recon subtask templates
# ---------------------------------------------------------------------------

_RECON_PORT_SCAN = SubTask(
    name="port_scan",
    agent="recon",
    task=(
        "Run ONLY this command and report the open ports:\n"
        "nmap -sS -T3 --top-ports 1000 -oA evidence/tcp_quick_{host_safe} {host}\n"
        "List each open port on one line. Do not run any other scans."
    ),
    max_turns=3,
    priority=10,
)

_RECON_UDP_SCAN = SubTask(
    name="udp_scan",
    agent="recon",
    task=(
        "Run ONLY this command:\n"
        "bash /home/kali/OffensiveAI/redops/udp_scan.sh {host}\n"
        "Then immediately check: cat /home/kali/OffensiveAI/evidence/udp_scan.nmap 2>/dev/null\n"
        "Report any UDP ports found or note as pending."
    ),
    max_turns=2,
    priority=8,
)

_RECON_DNS_ENUM = SubTask(
    name="dns_enum",
    agent="recon",
    task=(
        "Quick DNS enumeration for {host}:\n"
        "1. nslookup {host} or dig {host}\n"
        "2. Try zone transfer: dig axfr @{host} if it's a DNS server\n"
        "Report findings. Save to evidence/dns_{host_safe}.txt."
    ),
    max_turns=3,
    priority=7,
)

_RECON_SERVICE_ENUM = SubTask(
    name="service_enum",
    agent="recon",
    task=(
        "Run service version detection on open ports from the port scan:\n"
        "{context}\n"
        "Command: nmap -sV -sC -p {ports} -oA evidence/tcp_svc_{host_safe} {host}\n"
        "Report each service with its exact version."
    ),
    max_turns=3,
    depends_on=["port_scan"],
    priority=9,
)

_RECON_WEB_ENUM = SubTask(
    name="web_enum",
    agent="recon",
    task=(
        "Quick web enumeration on {host} ports {web_ports}:\n"
        "1. curl -sI http://{host}:{web_ports} to check headers/tech stack\n"
        "2. Check robots.txt, .git/HEAD, .env, sitemap.xml\n"
        "3. Run: feroxbuster -u http://{host}:{web_ports} -t 20 -w /usr/share/seclists/Discovery/Web-Content/common.txt -q --no-state -o evidence/web_{host_safe}.txt\n"
        "Report interesting findings only."
    ),
    max_turns=3,
    depends_on=["port_scan"],
    skip_condition="no_web_ports",
    priority=8,
)

_RECON_VHOST_ENUM = SubTask(
    name="vhost_enum",
    agent="recon",
    task=(
        "Enumerate virtual hosts / subdomains on {host}:\n"
        "1. Get baseline response size: curl -s -o /dev/null -w '%{{size_download}}' http://{host}/\n"
        "2. Run: ffuf -u http://{host} -H 'Host: FUZZ.{domain}' "
        "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt "
        "-fs BASELINE_SIZE -o evidence/vhosts_{host_safe}.json\n"
        "Replace BASELINE_SIZE with the number from step 1.\n"
        "Report any new vhosts found. Add them to /etc/hosts if needed."
    ),
    max_turns=3,
    depends_on=["port_scan"],
    skip_condition="no_web_ports",
    priority=8,
)

_RECON_PARAM_DISCOVERY = SubTask(
    name="param_discovery",
    agent="param_analyzer",
    task=(
        "Discover parameters on web endpoints for {host}:\n"
        "1. Extract form fields: curl -s http://{host}/ | grep -oiE '(name|id|action|href)=\"[^\"]*\"'\n"
        "2. Extract API routes from JS: curl -s http://{host}/ | grep -oE 'src=\"[^\"]*\\.js\"' | head -5\n"
        "3. Check common API paths: /api, /api/v1, /api/v2, /graphql\n"
        "4. For each endpoint found, test with: curl -s 'http://{host}/ENDPOINT' and note parameters.\n"
        "Output a JSON attack plan mapping parameters to likely vulnerabilities."
    ),
    max_turns=3,
    depends_on=["web_enum"],
    skip_condition="no_web_ports",
    priority=7,
)

_RECON_SMB_ENUM = SubTask(
    name="smb_enum",
    agent="recon",
    task=(
        "Quick SMB enumeration on {host}:\n"
        "1. crackmapexec smb {host}\n"
        "2. smbclient -N -L //{host}\n"
        "Report: hostname, domain, OS, shares, anonymous access. "
        "Save to evidence/smb_{host_safe}.txt."
    ),
    max_turns=3,
    depends_on=["port_scan"],
    skip_condition="no_smb_port",
    priority=7,
)

# ---------------------------------------------------------------------------
# Exploit subtask templates
# ---------------------------------------------------------------------------

_EXPLOIT_WEB = SubTask(
    name="web_exploit",
    agent="exploit",
    task=(
        "Test web vulnerabilities on {host}:{port}. Findings from recon: {context}. "
        "Priority: parameter manipulation (IDOR, path traversal, SSRF) BEFORE injection. "
        "Then: auth bypass, file upload abuse, SSTI. "
        "Test each vector with minimal probing first, then targeted payloads. "
        "Record any access gained."
    ),
    max_turns=3,
    priority=9,
)

_EXPLOIT_SMB = SubTask(
    name="smb_exploit",
    agent="exploit",
    task=(
        "Test SMB/AD attack vectors on {host}. Findings: {context}. "
        "Priority: relay attacks, null session abuse, credential spraying via SMB. "
        "If domain is identified: kerberoast, AS-REP roast candidates. "
        "Record any credentials or access gained."
    ),
    max_turns=3,
    skip_condition="no_smb_port",
    priority=8,
)

_EXPLOIT_CRED_SPRAY = SubTask(
    name="cred_spray",
    agent="exploit",
    task=(
        "Credential spraying against {host} using known credentials: {creds}. "
        "Target services: {services}. Use conservative timing to avoid lockout. "
        "Record any successful authentications."
    ),
    max_turns=3,
    skip_condition="no_credentials",
    priority=7,
)

_EXPLOIT_CVE = SubTask(
    name="cve_exploit",
    agent="exploit",
    task=(
        "Exploit confirmed CVE(s) on {host}: {cves}. "
        "Verify vulnerability first, then attempt exploitation. "
        "Use available PoCs from evidence/pocs/ if present. "
        "Record access level achieved."
    ),
    max_turns=3,
    skip_condition="no_cves",
    priority=10,
)

# ---------------------------------------------------------------------------
# Decomposition strategies
# ---------------------------------------------------------------------------

_RECON_TEMPLATES = [
    _RECON_PORT_SCAN, _RECON_UDP_SCAN, _RECON_DNS_ENUM,
    _RECON_SERVICE_ENUM, _RECON_WEB_ENUM, _RECON_VHOST_ENUM,
    _RECON_PARAM_DISCOVERY, _RECON_SMB_ENUM,
]

_EXPLOIT_TEMPLATES = [
    _EXPLOIT_WEB, _EXPLOIT_SMB, _EXPLOIT_CRED_SPRAY, _EXPLOIT_CVE,
]


class TaskDecomposer:
    """Decomposes broad agent tasks into narrow parallel subtasks."""

    def decompose_recon(self, host: str, scope: str = "", roe: str = "") -> list[SubTask]:
        """Break a recon task into parallel subtasks for a single host.

        Returns subtasks with {placeholders} filled in.
        """
        host_safe = host.replace(".", "_").replace("/", "_").replace(":", "_")
        subtasks = []

        # Extract domain from host for vhost enumeration
        domain = host if not host.replace(".", "").isdigit() else host

        for template in _RECON_TEMPLATES:
            st = SubTask(
                name=template.name,
                agent=template.agent,
                task=template.task.format(
                    host=host,
                    host_safe=host_safe,
                    domain=domain,
                    ports="{ports}",        # Filled after port_scan
                    web_ports="{web_ports}", # Filled after port_scan
                    context="{context}",     # Filled from dependency output
                ),
                max_turns=template.max_turns,
                depends_on=list(template.depends_on),
                host=host,
                skip_condition=template.skip_condition,
                priority=template.priority,
            )
            # Inject scope/ROE into task
            if scope or roe:
                st.task += f"\nScope: {scope or 'as defined'}\nROE: {roe or 'standard rules'}"
            subtasks.append(st)

        return subtasks

    def decompose_exploit(self, host: str, findings_db=None, engagement_state=None) -> list[SubTask]:
        """Break an exploit task into parallel subtasks based on findings.

        Uses the findings DB to determine which attack vectors are relevant.
        Skips subtasks where the prerequisite findings don't exist.
        """
        host_safe = host.replace(".", "_").replace("/", "_").replace(":", "_")
        subtasks = []

        # Determine what's available from findings
        has_web = False
        has_smb = False
        has_creds = False
        has_cves = False
        web_ports = []
        cves = []
        creds_str = ""
        services_str = ""
        web_context = ""
        smb_context = ""

        if findings_db:
            findings = findings_db.query(host=host, limit=50)
            for f in findings:
                if f.get("service", "").lower() in ("http", "https", "web") or \
                   f.get("port") in (80, 443, 8080, 8443, 8000, 8888):
                    has_web = True
                    if f.get("port"):
                        web_ports.append(str(f["port"]))
                    web_context += f"\n- {f.get('title', '')} {f.get('description', '')[:100]}"
                if f.get("port") == 445 or f.get("service", "").lower() in ("smb", "microsoft-ds"):
                    has_smb = True
                    smb_context += f"\n- {f.get('title', '')} {f.get('description', '')[:100]}"
                if f.get("cve_id"):
                    has_cves = True
                    cves.append(f["cve_id"])
                if f.get("finding_type") == "credential":
                    has_creds = True

        if engagement_state:
            if engagement_state.credentials:
                has_creds = True
                creds_str = ", ".join(
                    f"{c['username']}:{c['secret']}" for c in engagement_state.credentials[:5]
                )
            services_str = ", ".join(
                set(f.get("service", "") for f in (findings_db.query(host=host, limit=50) if findings_db else [])
                    if f.get("service"))
            ) or "SSH, SMB, HTTP"

        for template in _EXPLOIT_TEMPLATES:
            # Check skip conditions
            if template.skip_condition == "no_web_ports" and not has_web:
                continue
            if template.skip_condition == "no_smb_port" and not has_smb:
                continue
            if template.skip_condition == "no_credentials" and not has_creds:
                continue
            if template.skip_condition == "no_cves" and not has_cves:
                continue

            context = ""
            port = ""
            if template.name == "web_exploit":
                context = web_context or "Web service detected"
                port = web_ports[0] if web_ports else "80"
            elif template.name == "smb_exploit":
                context = smb_context or "SMB service detected"
            elif template.name == "cve_exploit":
                context = f"CVEs: {', '.join(cves[:5])}"

            st = SubTask(
                name=template.name,
                agent=template.agent,
                task=template.task.format(
                    host=host,
                    host_safe=host_safe,
                    port=port,
                    context=context,
                    creds=creds_str or "none available",
                    services=services_str,
                    cves=", ".join(cves[:5]) or "none",
                ),
                max_turns=template.max_turns,
                depends_on=list(template.depends_on),
                host=host,
                skip_condition="",
                priority=template.priority,
            )
            subtasks.append(st)

        return subtasks

    @staticmethod
    def build_execution_plan(subtasks: list[SubTask]) -> list[list[SubTask]]:
        """Organize subtasks into sequential batches respecting dependencies.

        Returns a list of batches. Each batch is a list of subtasks that
        can run in parallel. Batches execute sequentially.

        Example: [[port_scan, udp_scan, dns_enum], [service_enum, web_enum, smb_enum]]
        """
        if not subtasks:
            return []

        # Build dependency lookup
        by_name = {st.name: st for st in subtasks}
        completed = set()
        batches = []
        remaining = list(subtasks)

        # Safety limit to prevent infinite loops
        max_iterations = 10
        for _ in range(max_iterations):
            if not remaining:
                break

            # Find all subtasks whose dependencies are satisfied
            batch = []
            still_remaining = []
            for st in remaining:
                deps_met = all(d in completed for d in st.depends_on)
                if deps_met:
                    batch.append(st)
                else:
                    still_remaining.append(st)

            if not batch:
                # Circular dependency or unresolvable — dump remaining into last batch
                batch = still_remaining
                still_remaining = []

            # Sort batch by priority (highest first)
            batch.sort(key=lambda st: -st.priority)
            batches.append(batch)
            completed.update(st.name for st in batch)
            remaining = still_remaining

        return batches

    @staticmethod
    def fill_dependency_context(subtask: SubTask, prior_results: dict[str, str]) -> SubTask:
        """Fill {context} and {ports}/{web_ports} placeholders from prior batch results.

        Args:
            subtask: The subtask to fill
            prior_results: Dict mapping subtask_name -> output text

        Returns the subtask with placeholders replaced.
        """
        task = subtask.task

        # Fill {context} from dependency outputs
        if "{context}" in task and subtask.depends_on:
            context_parts = []
            for dep in subtask.depends_on:
                if dep in prior_results:
                    # Take first 1500 chars of dependency output
                    context_parts.append(prior_results[dep][:1500])
            context = "\n".join(context_parts) or "No prior results available"
            task = task.replace("{context}", context)

        # Extract port info from port_scan results
        if "{ports}" in task and "port_scan" in prior_results:
            ports = _extract_ports(prior_results["port_scan"])
            task = task.replace("{ports}", ports or "80,443,22")

        if "{web_ports}" in task and "port_scan" in prior_results:
            web_ports = _extract_web_ports(prior_results["port_scan"])
            task = task.replace("{web_ports}", web_ports or "80,443")

        subtask.task = task
        return subtask


def _extract_ports(scan_output: str) -> str:
    """Extract open port numbers from nmap-like output."""
    import re
    ports = set()
    # Match patterns like "80/tcp open" or "443/tcp"
    for match in re.finditer(r"(\d+)/(?:tcp|udp)\s+open", scan_output):
        ports.add(match.group(1))
    # Also match "Port XXXX" patterns
    for match in re.finditer(r"[Pp]ort\s+(\d+)", scan_output):
        ports.add(match.group(1))
    return ",".join(sorted(ports, key=int)) if ports else ""


def _extract_web_ports(scan_output: str) -> str:
    """Extract HTTP/HTTPS port numbers from scan output."""
    import re
    web_ports = set()
    common_web = {"80", "443", "8080", "8443", "8000", "8888", "3000", "5000", "9090"}
    for match in re.finditer(r"(\d+)/tcp\s+open\s+(https?|ssl/http)", scan_output):
        web_ports.add(match.group(1))
    # Check for common web ports in the open ports list
    for match in re.finditer(r"(\d+)/tcp\s+open", scan_output):
        port = match.group(1)
        if port in common_web:
            web_ports.add(port)
    return ",".join(sorted(web_ports, key=int)) if web_ports else ""
