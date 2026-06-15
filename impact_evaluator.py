"""Finding impact evaluator — forces proof of impact before severity escalation.

Every finding above LOW must answer: what did you actually demonstrate?
No proof = downgrade. This prevents the common pattern of agents spending
10 turns building a narrative around a non-finding.

Two modes:
1. Gate mode: called before writing to findings DB, downgrades unproven findings
2. Inline mode: injected into agent prompts as a self-check rubric
"""

import re
from dataclasses import dataclass

from findings_db import Finding


@dataclass
class ImpactVerdict:
    """Result of impact evaluation."""
    original_severity: str
    adjusted_severity: str
    downgraded: bool
    reason: str
    proof_present: bool


# Keywords that indicate actual demonstrated impact (not theoretical)
_PROOF_INDICATORS = {
    "critical": [
        # Must have at least one of these to stay critical
        r"accessed\s+(data|records|PII|credentials|database)",
        r"(remote|arbitrary)\s+code\s+execution",
        r"(RCE|shell|reverse.shell|command.execution)\s+(confirmed|achieved|successful)",
        r"domain\s+admin",
        r"SYSTEM\s+(shell|access)",
        r"exfiltrat",
        r"dump(ed|ing)\s+(credentials|hashes|NTDS|SAM|LSASS)",
        r"(dangling\s+NS|NS\s+delegation).*(expired|unclaimed|available|full\s+DNS\s+control)",
    ],
    "high": [
        # Must have at least one of these to stay high
        r"bypass(ed|ing)\s+(auth|authentication|authorization|access.control)",
        r"(IDOR|insecure.direct)\s+(confirmed|demonstrated|verified)",
        r"(SQL|command|SSTI|XXE)\s+injection\s+(confirmed|verified|successful)",
        r"accessed\s+(other|another|different)\s+user",
        r"(unauthenticated|unauthorized)\s+access\s+to\s+(data|admin|API|endpoint)",
        r"(password|credential|secret|token|key)\s+(leak|expos|disclos|theft|captur|intercept|stol)",
        r"(oauth|access.token|session.token|auth.code).{0,30}(captur|intercept|stol|exfiltrat|theft)",
        r"(file|path)\s+traversal\s+(confirmed|read|accessed)",
        r"privilege\s+escalat",
        r"(uploaded|wrote)\s+(shell|webshell|backdoor|payload)",
        r"CVE-\d{4}-\d{4,}.*\b(exploit|PoC|confirmed|verified)\b",
        r"(subdomain|sub.domain)\s*(takeover|take.over)\s*(confirmed|claimed|content\s+served)",
        r"(dangling\s+NS|NS\s+delegation).*(expired|unclaimed|available)",
    ],
    "medium": [
        # Must have at least one of these to stay medium
        r"(reflected|stored|DOM)\s+XSS\s+(confirmed|fires|executed|triggered)",
        r"CSRF\s+(confirmed|demonstrated|no.token)",
        r"open\s+redirect\s+(confirmed|redirects|followed)",
        r"(email|user)\s+(enumerat|valid)",
        r"(information|version|stack.trace)\s+(disclos|leak|expos)",
        r"(missing|absent|no)\s+(rate.limit|lockout|CSRF.token|auth)",
        r"(clickjack|framing)\s+(possible|confirmed|no.X-Frame)",
        r"(directory|path)\s+listing\s+(enabled|visible|accessible)",
        r"(sensitive|internal)\s+(endpoint|data|config)\s+(exposed|accessible|visible)",
        r"(subdomain|sub.domain)\s*(takeover|take.over).{0,30}(dangling|no.verification|unclaimed)",
    ],
}

# Phrases that indicate the agent is speculating rather than proving
_SPECULATION_INDICATORS = [
    r"\b(potential|possible|might|could|may)\s+(vulnerability|bypass|leak|exploit|issue)",
    r"\bthis\s+(could|might|may)\s+(allow|enable|lead)",
    r"\b(goldmine|jackpot|massive\s+(find|disclos|leak|breach)|game.?changer)\b",
    r"\b(major|critical|significant|enormous|huge|massive|extensive)\s+(\w+\s+)?(find|finding|discovery|disclos|leak|breach|expos|vuln)\w*\b",
    r"\bif\s+an?\s+attacker\s+(could|were|can)\b",
    r"\b(in\s+theory|theoretically|hypothetically)\b",
    r"\b(further\s+investigation|needs?\s+more\s+testing|worth\s+exploring)\b",
    r"\b(token\s+exhaustion|resource\s+consumption)\s+.{0,20}(DoS|denial)",  # speculative DoS
    r"\b(sandbox|test|demo|example)\s+.{0,20}(hardcoded|default|123456)",  # documented sandbox behavior
    r"\b(promo|coupon|discount|voucher)\s+code\s+.{0,30}(enumerat|brute|discover)",  # public marketing codes
    r"\bwithout\s+auth.{0,30}(pric|coupon|promo|public|search|marketing)",  # public features called vuln
    r"\b(500|server\s+error|crash|exception).{0,40}(strong\s+indicator|evidence|confirms?)\s+.{0,20}(injection|SSTI|SQLi|RCE)",  # crash claimed as injection proof
    r"\b(accept|return|respond).{0,20}(200|success).{0,30}(proves?|confirms?|demonstrates?)",  # 200 response claimed as processing proof
    r"\bif\s+.{0,30}(can\s+be\s+confirmed|escalat|past\s+the\s+crash)",  # teasing escalation without proof
    r"\b(brute.?force|enumerat).{0,30}(token|session|UUID|GUID)",  # token brute-force without feasibility analysis
    r"\b(contain|associated\s+with).{0,30}(PII|SSN|sensitive)",  # claiming PII access without proof of retrieval
    r"\b(endpoint|api).{0,20}(lack|missing|no|without).{0,20}(auth|check)",  # listing endpoints without proving data access
    r"\b(subdomain|sub.domain)\s*(takeover|take.over).{0,50}(dangling|cname|fastly|unknown.domain)",  # dangling CNAME reported as takeover without claim proof
    r"\b(redirect_uri|redirect|return_url|callback).{0,40}(pass|preserv|surviv|present|reflect).{0,40}(url|param|chain)",  # parameter reflection claimed as open redirect without terminal proof
    r"\bopen\s+redirect.{0,60}(parameter\s+(is\s+)?(pass|preserv|present|reflect))",  # same pattern, different word order
    r"\b(by\s+itself|individually|alone).{0,30}(doesn't|does\s+not|won't|no).{0,20}(grant|allow|give|enable).{0,30}(but|however|combined)",  # narrative bundling: "alone it's nothing, but combined..."
    r"\b(useful|valuable)\s+for\s+(IDOR|brute|fuzzing|enum|manipulation|tampering|exploit|attack)",  # speculative future use without demonstrated exploitation
    r"\b(reveal|expos|leak).{0,20}(architecture|structure|internal|format|pattern).{0,30}(useful|valuable|critical)",  # info disclosure inflated by speculative utility
    r"\b(should\s+(be|have\s+been)|never\s+be)\s+(behind|in|on)\s+(VPN|internal|private)",  # claiming exposure without proving access to protected resources
    r"\b(jwk|public.key|cert).{0,20}(expos|leak|disclos).{0,20}(unauth|without.auth|no.auth)",  # JWK/public key endpoints are by design in OIDC
    r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0).{0,30}(reference|artifact|found|present|leak)",  # localhost in JS bundles is informational noise
]

# Providers where subdomain takeover is NOT feasible (domain verification required).
# Dangling CNAME to these providers is informational, not a vulnerability.
_UNCLAIMABLE_PROVIDERS = [
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "netlify.app", "netlify.com", "vercel-dns.com", "vercel.app",
    "myshopify.com", "shopify.com", "ghost.io", "tumblr.com",
    "zendesk.com", "fastly.net", "pages.dev", "cloudflare",
    "heroku", "azure",
]

# Phrases indicating the agent walked back its own finding
_WALKBACK_INDICATORS = [
    r"\b(however|but)\s+.{0,80}(still\s+require|requires|needed|needs|block|prevent|gate)",
    r"\bthe\s+token\s+alone\s+(isn't|is\s+not|doesn't|won't|cannot)\b",
    r"\b(can't|cannot|unable)\s+(be\s+used|complete|access)\s+without\b",
    r"\b(downstream|separate|additional)\s+(auth|validation|check)\s+(require|block|prevent)",
    r"\b(however|but).{0,30}(require|need).{0,30}(auth|access|session|credential|token)",
    r"\bnot\s+enough\s+(to|for|without)\b",
    r"\b(while|although).{0,50}(doesn't|does\s+not|can't|cannot)\s+(grant|give|provide|allow)\b",
]


def _check_output_grounding(finding: Finding, evidence_text: str) -> list[str]:
    """Detect claims in a finding that are contradicted by actual tool output.

    Catches the hallucination pattern where an agent claims to observe specific
    response codes, error messages, or API behavior that does not appear in the
    raw evidence (tool output).  Returns a list of grounding violations found.
    """
    violations = []
    if not evidence_text:
        return violations

    evidence_lower = evidence_text.lower()
    combined = f"{finding.title} {finding.description}".lower()

    # --- 1. Claimed HTTP status/error codes not present in raw output ---
    # Agent says "error 264" or "status 200" but the tool output never contained it
    claimed_codes = re.findall(
        r"(?:error|status|code|response)\s*[:\-]?\s*(\d{3,5})", combined
    )
    for code in claimed_codes:
        if code not in evidence_lower:
            violations.append(
                f"Claims response code {code} but code never appears in tool output"
            )

    # --- 2. Claims JSON API response but output is HTML ---
    json_api_claim = bool(re.search(
        r"(json|api\s+respond|error\s+code|response.*\{)", combined
    ))
    evidence_is_html = bool(re.search(
        r"<html|<!DOCTYPE|<head>|<body", evidence_text, re.IGNORECASE
    ))
    evidence_has_json = bool(re.search(r"\{.*\"", evidence_text))
    if json_api_claim and evidence_is_html and not evidence_has_json:
        violations.append(
            "Claims JSON/API response but tool output is HTML "
            "(endpoint may not exist or returned error page)"
        )

    # --- 3. Claims differential behavior but evidence shows identical responses ---
    # Detect "with header X → behavior A, without → behavior B" claims
    # where the raw output shows identical responses
    differential_claim = bool(re.search(
        r"(with(out)?\s+(the\s+)?header|adding\s+the\s+header|without\s+.*header)"
        r".{0,100}(different|change|switch|skip|bypass)",
        combined,
    ))
    if differential_claim:
        # Look for repeated identical response blocks in evidence
        # (same response appearing 2+ times = no differential behavior)
        chunks = re.split(r"(?:─{10,}|\n{3,}|={10,})", evidence_text)
        response_bodies = []
        for chunk in chunks:
            chunk = chunk.strip()
            if len(chunk) > 200:
                # Normalize whitespace for comparison
                normalized = re.sub(r"\s+", " ", chunk[:500])
                response_bodies.append(normalized)
        if len(response_bodies) >= 2:
            for i in range(len(response_bodies)):
                for j in range(i + 1, len(response_bodies)):
                    # If two response bodies are >80% similar, no differential
                    a, b = response_bodies[i], response_bodies[j]
                    overlap = sum(1 for c1, c2 in zip(a, b) if c1 == c2)
                    similarity = overlap / max(len(a), len(b), 1)
                    if similarity > 0.8:
                        violations.append(
                            "Claims differential behavior between requests but "
                            "tool output shows near-identical responses"
                        )
                        break
                if violations and "identical" in violations[-1]:
                    break

    # --- 4. Claims successful exploitation but output contains error/not-found ---
    exploit_claim = bool(re.search(
        r"(bypass\s+confirmed|access\s+granted|auth.*bypass|exploit.*success|"
        r"password.*skip|dump.*credential|"
        r"accessed\s+\w+\s+(panel|dashboard|endpoint|data|page|portal)|"
        r"unauthenticated\s+access|"
        r"response\s+show|"
        r"successfully\s+(exploit|access|bypass|extract|dump|read))",
        combined,
    ))
    output_shows_failure = bool(re.search(
        r"(page\s+not\s+found|404|not\s+found|endpoint\s+does\s+not\s+exist|"
        r"connection\s+refused|timeout|ECONNREFUSED|Name\s+or\s+service\s+not\s+known)",
        evidence_lower,
    ))
    if exploit_claim and output_shows_failure:
        violations.append(
            "Claims successful exploitation but tool output contains "
            "error/not-found/connection failure indicators"
        )

    # --- 5. Subdomain takeover without claim proof ---
    is_takeover_finding = bool(re.search(
        r"(subdomain|sub.domain)\s*(takeover|take.over)", combined
    ))
    if is_takeover_finding:
        # Check if the provider is in the unclaimable list
        for provider in _UNCLAIMABLE_PROVIDERS:
            if provider in evidence_lower or provider in combined:
                # Did the agent actually claim the domain? Look for proof.
                has_claim_proof = bool(re.search(
                    r"(claimed|content\s+served|serving\s+content|"
                    r"controlled\s+by\s+us|our\s+content|poc\s+page\s+live|"
                    r"successfully\s+added\s+domain|domain\s+added|"
                    r"verified\s+ownership|takeover\s+confirmed\s+with\s+content)",
                    combined,
                ))
                if not has_claim_proof:
                    violations.append(
                        f"Subdomain takeover claim against {provider} but no proof of "
                        f"domain claim. {provider} requires domain verification — "
                        f"dangling CNAME alone is not exploitable"
                    )
                break

        # Even for claimable providers, check if the agent actually claimed it
        if not violations or "takeover" not in violations[-1]:
            has_any_proof = bool(re.search(
                r"(claimed|content\s+served|poc\s+page|our\s+content|"
                r"domain\s+added|takeover\s+confirmed)",
                combined,
            ))
            if not has_any_proof and is_takeover_finding:
                # Not a grounding violation per se, but add to evidence text
                # so speculation detection catches it
                pass  # Let the speculation indicators handle it

    # --- 6. Open redirect without terminal redirect proof ---
    # "Parameter present in URL" ≠ "parameter consumed by application".
    # Many apps pass redirect_uri through the URL bar but use a hardcoded
    # return path server-side. Proof requires showing the user actually
    # lands on the attacker URL after completing the flow.
    is_redirect_finding = bool(re.search(
        r"open\s*redirect", combined
    ))
    if is_redirect_finding:
        # Check if the agent proved terminal redirect (user lands on evil URL)
        has_terminal_proof = bool(re.search(
            r"(redirect(s|ed)?\s+to\s+(attacker|evil|our|malicious)|"
            r"land(s|ed)?\s+on\s+(attacker|evil|our|malicious)|"
            r"user\s+(is\s+)?(sent|redirect|forward)\s+to\s+(attacker|evil|http)|"
            r"Location:\s*https?://evil|"
            r"final\s+(redirect|destination|url).{0,30}(evil|attacker|malicious)|"
            r"completes?\s+(the\s+)?flow.{0,30}(evil|attacker|redirected)|"
            r"after\s+(registration|login|signup|onboarding).{0,30}(evil|attacker|redirected))",
            combined,
        ))
        # Check for the anti-pattern: "parameter is preserved/passed/present"
        # without terminal proof
        is_param_reflection_only = bool(re.search(
            r"(redirect_uri|redirect|return_url|callback_url).{0,40}"
            r"(preserv|pass(es|ed)?(\s+through)?|present|reflect|surviv|"
            r"appear|visible|in\s+the\s+url|intact|unvalidated)",
            combined,
        ))
        if is_param_reflection_only and not has_terminal_proof:
            violations.append(
                "Open redirect claim based on parameter reflection only. "
                "Parameter present in URL does NOT prove the application consumes it. "
                "Must demonstrate user lands on attacker URL after completing the flow"
            )

    return violations


def evaluate_finding_impact(finding: Finding, evidence_text: str = "") -> ImpactVerdict:
    """Evaluate whether a finding's severity is justified by demonstrated impact.

    Args:
        finding: The Finding to evaluate
        evidence_text: The full agent output/evidence text for this finding

    Returns:
        ImpactVerdict with potentially adjusted severity
    """
    severity = finding.severity.lower()
    combined_text = f"{finding.title} {finding.description} {evidence_text}".lower()

    # --- Output grounding check (catches fabricated observations) ---
    grounding_violations = _check_output_grounding(finding, evidence_text)
    if grounding_violations:
        # Scale downgrade by violation count: 1 violation = 2 steps,
        # 2+ violations = 3 steps (almost certainly hallucinated).
        steps = 2 if len(grounding_violations) == 1 else 3
        new_severity = _downgrade(severity, steps=steps)
        violation_summary = "; ".join(grounding_violations)
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=new_severity,
            downgraded=True,
            reason=(
                f"OUTPUT GROUNDING FAILURE ({len(grounding_violations)} violations): "
                f"{violation_summary}. "
                f"Agent claims are not supported by raw tool output. "
                f"Downgraded {severity} -> {new_severity}"
            ),
            proof_present=False,
        )

    # LOW and INFO pass through without evaluation
    if severity in ("low", "info"):
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=severity,
            downgraded=False,
            reason="Low/info findings pass through without impact evaluation",
            proof_present=True,
        )

    # Check for speculation indicators
    speculation_count = sum(
        1 for pattern in _SPECULATION_INDICATORS
        if re.search(pattern, combined_text, re.IGNORECASE)
    )

    # Check for walkback indicators (agent contradicting itself)
    walkback_count = sum(
        1 for pattern in _WALKBACK_INDICATORS
        if re.search(pattern, combined_text, re.IGNORECASE)
    )

    # Check for proof of impact at this severity level
    proof_patterns = _PROOF_INDICATORS.get(severity, [])
    proof_matches = [
        pattern for pattern in proof_patterns
        if re.search(pattern, combined_text, re.IGNORECASE)
    ]
    has_proof = len(proof_matches) > 0

    # Decision logic
    if has_proof and walkback_count == 0 and speculation_count == 0:
        # Proof present, no walkback, no speculation — severity stands
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=severity,
            downgraded=False,
            reason=f"Impact proof found: matches {len(proof_matches)} indicators",
            proof_present=True,
        )

    if has_proof and walkback_count == 0 and speculation_count > 0:
        # Proof present but speculation language used — downgrade by 1
        # (the "proof" is likely the agent labeling its own speculation as a finding)
        new_severity = _downgrade(severity, steps=1)
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=new_severity,
            downgraded=True,
            reason=(
                f"Proof indicator matched but {speculation_count} speculation indicators "
                f"suggest the proof is self-labeled, not demonstrated. "
                f"Downgraded {severity} -> {new_severity}"
            ),
            proof_present=False,
        )

    if walkback_count > 0:
        # Agent walked back its own finding — downgrade significantly
        new_severity = _downgrade(severity, steps=2)
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=new_severity,
            downgraded=True,
            reason=(
                f"Agent walked back finding ({walkback_count} walkback indicators). "
                f"Downgraded {severity} -> {new_severity}"
            ),
            proof_present=False,
        )

    if speculation_count >= 2 and not has_proof:
        # Heavy speculation without proof — downgrade
        new_severity = _downgrade(severity, steps=2)
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=new_severity,
            downgraded=True,
            reason=(
                f"Speculative finding ({speculation_count} speculation indicators, "
                f"0 proof indicators). Downgraded {severity} -> {new_severity}"
            ),
            proof_present=False,
        )

    if not has_proof:
        # No proof at this severity level — downgrade by one step
        new_severity = _downgrade(severity, steps=1)
        return ImpactVerdict(
            original_severity=severity,
            adjusted_severity=new_severity,
            downgraded=True,
            reason=(
                f"No impact proof for {severity} severity "
                f"(0/{len(proof_patterns)} proof patterns matched). "
                f"Downgraded to {new_severity}"
            ),
            proof_present=False,
        )

    return ImpactVerdict(
        original_severity=severity,
        adjusted_severity=severity,
        downgraded=False,
        reason="Passed impact evaluation",
        proof_present=has_proof,
    )


def _downgrade(severity: str, steps: int = 1) -> str:
    """Downgrade severity by N steps."""
    order = ["critical", "high", "medium", "low", "info"]
    try:
        idx = order.index(severity.lower())
        new_idx = min(idx + steps, len(order) - 1)
        return order[new_idx]
    except ValueError:
        return "info"


def gate_finding(finding: Finding, evidence_text: str = "") -> Finding:
    """Apply the impact gate to a finding before it enters the DB.

    Returns the finding with potentially adjusted severity.
    Does NOT modify the original finding object.
    """
    verdict = evaluate_finding_impact(finding, evidence_text)

    if verdict.downgraded:
        # Create a new finding with adjusted severity and annotated description
        return Finding(
            host=finding.host,
            port=finding.port,
            service=finding.service,
            finding_type=finding.finding_type,
            severity=verdict.adjusted_severity,
            title=finding.title,
            description=(
                f"{finding.description}\n\n"
                f"[Impact Gate: {verdict.reason}]"
            ),
            evidence=finding.evidence,
            evidence_path=finding.evidence_path,
            cve_id=finding.cve_id,
            agent=finding.agent,
            tags=finding.tags,
            exploitable=finding.exploitable if verdict.adjusted_severity in ("critical", "high") else False,
            exploited=finding.exploited,
        )

    return finding


# --- Inline rubric for agent prompts ---

IMPACT_RUBRIC = """
## Impact Self-Check (before reporting findings above LOW)
- CRITICAL/HIGH requires PROOF: show the response body with unauthorized data, the RCE output, or the auth bypass
- "Could/might/potentially" = speculation = INFO max, regardless of theoretical impact
- If impact SHRINKS as you investigate, the final (lowest) assessment is the real severity
- 500 error ≠ injection. Prove EVALUATION ({{7*7}}→49), not just crashes
- Config listed ≠ config accepted. Test alg:none JWTs, implicit flows, etc. — don't just report discovery docs
- API returning 401 = auth working. Recon data (endpoint maps, tech stack) = INFO, not a finding
- "Would a PM be surprised?" If no → feature working as designed → not a vulnerability

## Narrative Inflation Checks (MANDATORY)
- Do NOT bundle multiple informational items into a single medium/high finding
- "Intelligence goldmine" / "massive disclosure" / "critical discovery" = hype, not proof
- Each finding must demonstrate impact INDIVIDUALLY — bundling weak items doesn't increase severity
- Parameter in URL ≠ parameter consumed. Open redirect requires user LANDING on attacker URL
- Public JWK endpoints, OAuth client IDs in URLs, localhost in JS = by design, not findings
- "Useful for IDOR/brute-force/enumeration" = speculation unless you DEMONSTRATE the IDOR/brute/enum
- "Should be behind VPN" = only a finding if the exposed resource contains sensitive data you accessed

## Output Grounding (MANDATORY — anti-hallucination)
Before claiming ANY specific response code, error message, or behavioral difference:
- **QUOTE the exact output** — copy-paste the relevant response body, not your interpretation
- If curl returned HTML "Page Not Found" — that is what happened. Do NOT claim JSON error codes you didn't see
- If two requests returned identical responses — there is NO differential behavior, regardless of what you expected
- If the endpoint returned 404/HTML/connection refused — it does NOT exist. Do not build findings on dead endpoints
- NEVER claim "error 264" or "error 81107" unless those exact strings appear in your tool output
- Your finding must be grounded in what the tool RETURNED, not what you expected it to return
"""
