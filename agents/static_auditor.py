"""Static auditor agent — source code vulnerability analysis.

Runs automated scanners (Semgrep, CodeQL, grep patterns), parses results,
then uses LLM to validate findings through data flow tracing. Aggressively
filters false positives — scanner output is leads, not findings.

Language-specific strategies:
  C/C++: buffer overflows, format strings, integer overflows, use-after-free
  PHP: deserialization, SQLi, file inclusion, type juggling
  Python: pickle/yaml deser, SSTI, command injection, path traversal
  Node/JS: prototype pollution, SSRF, regex DoS
  Java: deserialization gadgets, JNDI, XXE, expression language injection
  Go: race conditions, unsafe pointer, command injection
"""

import json
import os
import re
import subprocess
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST
from research_engagement import ResearchEngagement, TargetProfile


# --- Dangerous patterns by language (grep-based, no external tools needed) ---

_DANGEROUS_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    # Each: (regex_pattern, sink_type, description)
    "c": [
        (r"\bstrcpy\s*\(", "buffer_overflow", "strcpy without length check"),
        (r"\bstrcat\s*\(", "buffer_overflow", "strcat without length check"),
        (r"\bsprintf\s*\(", "format_string", "sprintf without length limit (use snprintf)"),
        (r"\bvsprintf\s*\(", "format_string", "vsprintf without length limit"),
        (r"\bgets\s*\(", "buffer_overflow", "gets() is always unsafe — no length limit"),
        (r"\bmemcpy\s*\([^,]+,[^,]+,[^)]*\b(len|size|sz|n|count)\b", "buffer_overflow", "memcpy with variable length — verify bounds"),
        (r"\bscanf\s*\(\s*\"[^\"]*%s", "buffer_overflow", "scanf %s without width limit"),
        (r"\bsystem\s*\(", "command_injection", "system() with potential user input"),
        (r"\bpopen\s*\(", "command_injection", "popen() with potential user input"),
        (r"\bexecve?\s*\(", "command_injection", "exec family — check input sanitization"),
        (r"\bfree\s*\([^)]+\).*\bfree\s*\(", "double_free", "potential double-free pattern"),
        (r"\bmalloc\s*\([^)]*\*[^)]*\)", "integer_overflow", "multiplication in malloc size — check overflow"),
        (r"\batoi\s*\(.*\)\s*[\+\-\*]", "integer_overflow", "atoi result in arithmetic — no overflow check"),
    ],
    "cpp": [],  # inherits C patterns + additional
    "php": [
        (r"\bunserialize\s*\(", "deserialization", "unserialize() on untrusted data"),
        (r"\beval\s*\(", "code_injection", "eval() with potential user input"),
        (r"\bsystem\s*\(|passthru\s*\(|exec\s*\(|shell_exec\s*\(", "command_injection", "command execution function"),
        (r"\binclude\s*\(.*\$|require\s*\(.*\$", "file_inclusion", "include/require with variable path"),
        (r"\bmysqli?_query\s*\(.*\$|\bquery\s*\(.*\$", "sql_injection", "SQL query with variable interpolation"),
        (r"\bpreg_replace\s*\(['\"]/.*/e", "code_injection", "preg_replace with /e modifier (code execution)"),
        (r"==\s*['\"]0|==\s*false|==\s*null", "type_juggling", "loose comparison — potential type juggling"),
        (r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", "input_source", "direct use of superglobal input"),
    ],
    "python": [
        (r"\bpickle\.loads?\s*\(", "deserialization", "pickle deserialization of untrusted data"),
        (r"\byaml\.load\s*\((?!.*Loader)", "deserialization", "yaml.load without SafeLoader"),
        (r"\beval\s*\(", "code_injection", "eval() on potentially untrusted input"),
        (r"\bexec\s*\(", "code_injection", "exec() on potentially untrusted input"),
        (r"\bos\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True", "command_injection", "shell command with potential user input"),
        (r"\brender_template_string\s*\(", "ssti", "Jinja2 template rendering of user input (SSTI)"),
        (r"\bsqlite3?\.execute\s*\(.*%|\.execute\s*\(.*format|\.execute\s*\(.*f['\"]", "sql_injection", "SQL with string formatting"),
        (r"open\s*\(.*\+.*request|open\s*\(.*user", "path_traversal", "file open with potential user-controlled path"),
    ],
    "javascript": [
        (r"\beval\s*\(", "code_injection", "eval() on potentially untrusted input"),
        (r"\.innerHTML\s*=", "xss", "innerHTML assignment (DOM XSS)"),
        (r"\bchild_process\b.*exec\s*\(", "command_injection", "child_process exec with potential user input"),
        (r"__proto__|prototype\s*\[", "prototype_pollution", "prototype access/modification"),
        (r"new\s+Function\s*\(", "code_injection", "Function constructor (code execution)"),
        (r"\bdeserialize\s*\(|\bJSON\.parse\s*\(.*\breq\b", "deserialization", "deserialization of user input"),
        (r"res\.redirect\s*\(.*req\.", "open_redirect", "redirect with user-controlled URL"),
    ],
    "java": [
        (r"\bObjectInputStream\b", "deserialization", "Java deserialization — check for gadget chains"),
        (r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "command_injection", "Runtime.exec with potential user input"),
        (r"\bnew\s+ProcessBuilder\s*\(", "command_injection", "ProcessBuilder with potential user input"),
        (r"InitialContext\s*\(\)|lookup\s*\(", "jndi_injection", "JNDI lookup — potential injection (Log4Shell class)"),
        (r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory", "xxe", "XML parser — check for XXE prevention"),
        (r"SpEL|ExpressionParser|parseExpression", "expression_injection", "Spring Expression Language injection"),
    ],
    "go": [
        (r"\bexec\.Command\s*\(", "command_injection", "exec.Command with potential user input"),
        (r"\bunsafe\.Pointer\b", "memory_safety", "unsafe.Pointer use — manual memory management"),
        (r"\bgo\s+func\b.*\bmap\b|\bsync\.Mutex\b", "race_condition", "goroutine with shared state — check synchronization"),
        (r"template\.HTML\s*\(|template\.JS\s*\(", "xss", "unescaped template content"),
    ],
}

# C++ inherits all C patterns
_DANGEROUS_PATTERNS["cpp"] = _DANGEROUS_PATTERNS["c"] + [
    (r"\bdelete\b.*\bdelete\b", "double_free", "potential double delete"),
    (r"\bstd::system\s*\(", "command_injection", "std::system with potential user input"),
]


def _check_tool(name: str) -> bool:
    """Check if a tool is available."""
    try:
        subprocess.run(["which", name], capture_output=True, timeout=5)
        return subprocess.run(["which", name], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def grep_audit(target_path: str, language: str) -> list[dict]:
    """Run grep-based pattern matching for dangerous sinks.

    Always available — no external tools needed. Fast but high FP rate.
    Returns raw findings that need LLM validation.
    """
    patterns = _DANGEROUS_PATTERNS.get(language, [])
    if not patterns:
        return []

    # Map language to file extensions
    ext_map = {
        "c": ["*.c", "*.h"],
        "cpp": ["*.cpp", "*.cc", "*.cxx", "*.hpp", "*.h"],
        "php": ["*.php", "*.phtml"],
        "python": ["*.py"],
        "javascript": ["*.js", "*.mjs", "*.cjs"],
        "java": ["*.java"],
        "go": ["*.go"],
    }
    extensions = ext_map.get(language, ["*.*"])

    findings = []
    sink_id = 0
    path = Path(target_path)

    for pattern, sink_type, description in patterns:
        for ext in extensions:
            try:
                cmd = [
                    "grep", "-rnP", "--include", ext,
                    pattern, str(path),
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    # Parse grep output: file:line:content
                    match = re.match(r"^(.+?):(\d+):(.+)$", line)
                    if match:
                        sink_id += 1
                        findings.append({
                            "id": sink_id,
                            "file": match.group(1),
                            "line": int(match.group(2)),
                            "content": match.group(3).strip()[:200],
                            "sink_type": sink_type,
                            "description": description,
                            "source": "grep",
                            "confidence": "low",  # grep = low, needs LLM validation
                        })
            except Exception:
                continue

    return findings


def semgrep_audit(target_path: str, language: str) -> list[dict]:
    """Run Semgrep with auto rules. Returns SARIF-parsed findings."""
    if not _check_tool("semgrep"):
        return []

    findings = []
    try:
        result = subprocess.run(
            [
                "semgrep", "scan",
                "--config", "auto",
                "--sarif",
                "--quiet",
                "--timeout", "60",
                str(target_path),
            ],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode not in (0, 1):  # 1 = findings found
            return []

        sarif = json.loads(result.stdout)
        for run in sarif.get("runs", []):
            for r in run.get("results", []):
                rule_id = r.get("ruleId", "")
                message = r.get("message", {}).get("text", "")
                for loc in r.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {}).get("uri", "")
                    region = phys.get("region", {})
                    line = region.get("startLine", 0)
                    snippet = region.get("snippet", {}).get("text", "")

                    findings.append({
                        "id": len(findings) + 1,
                        "file": artifact,
                        "line": line,
                        "content": snippet[:200],
                        "sink_type": _classify_semgrep_rule(rule_id),
                        "description": f"[semgrep:{rule_id}] {message[:150]}",
                        "source": "semgrep",
                        "confidence": "low",  # still needs validation
                        "rule_id": rule_id,
                    })
    except Exception:
        pass

    return findings


def _classify_semgrep_rule(rule_id: str) -> str:
    """Map Semgrep rule ID to a sink type."""
    r = rule_id.lower()
    if "sqli" in r or "sql-injection" in r:
        return "sql_injection"
    if "xss" in r or "cross-site" in r:
        return "xss"
    if "cmdi" in r or "command-injection" in r or "os-command" in r:
        return "command_injection"
    if "deser" in r or "pickle" in r or "yaml" in r:
        return "deserialization"
    if "path-traversal" in r or "lfi" in r:
        return "path_traversal"
    if "ssrf" in r:
        return "ssrf"
    if "ssti" in r or "template" in r:
        return "ssti"
    if "xxe" in r:
        return "xxe"
    if "buffer" in r or "overflow" in r:
        return "buffer_overflow"
    return "other"


def validate_findings_llm(findings: list[dict], target_path: str,
                          language: str, on_status=None) -> list[dict]:
    """Use LLM to validate scanner findings by tracing data flows.

    Reads the actual source code around each finding and asks the LLM
    to determine if untrusted input can actually reach the dangerous sink.
    Aggressively filters — only findings with confirmed data flow survive.

    Returns validated findings with confidence upgraded to "medium" or "high".
    """
    if not findings:
        return []

    # Group findings by file to minimize file reads
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)

    validated = []
    batch_size = 8  # validate 8 findings per LLM call

    for file_path, file_findings in by_file.items():
        # Read the source file
        try:
            full_path = file_path if os.path.isabs(file_path) else os.path.join(target_path, file_path)
            source_lines = Path(full_path).read_text(errors="ignore").split("\n")
        except Exception:
            continue

        # Process in batches
        for i in range(0, len(file_findings), batch_size):
            batch = file_findings[i:i + batch_size]

            # Build context for each finding (±15 lines around the sink)
            finding_contexts = []
            for f in batch:
                line_num = f["line"]
                start = max(0, line_num - 16)
                end = min(len(source_lines), line_num + 15)
                context = "\n".join(
                    f"{n+1}: {source_lines[n]}"
                    for n in range(start, end)
                )
                finding_contexts.append(
                    f"### Finding {f['id']}: {f['description']}\n"
                    f"File: {f['file']}:{f['line']}\n"
                    f"Sink type: {f['sink_type']}\n"
                    f"```{language}\n{context}\n```"
                )

            prompt = f"""You are a vulnerability researcher validating static analysis findings.
For each finding below, determine if untrusted input (user input, network data,
file content, environment variables) can actually reach the dangerous sink.

AGGRESSIVELY FILTER. Most scanner findings are false positives. Only mark as
VALID if you can trace a realistic data flow from an input source to the sink.

{chr(10).join(finding_contexts)}

Respond in JSON array format only:
[
  {{"id": 1, "valid": true/false, "confidence": "high"/"medium", "data_flow": "input source → transforms → sink", "reason": "why valid or why FP"}},
  ...
]

Rules:
- If the sink only operates on hardcoded/constant data → FALSE POSITIVE
- If input is properly validated/sanitized before reaching the sink → FALSE POSITIVE
- If you can't determine the input source from the visible code → mark as "medium" confidence
- If clear untrusted input reaches the sink without sanitization → "high" confidence"""

            if on_status:
                on_status(f"[static_auditor] Validating {len(batch)} findings in {os.path.basename(file_path)}...")

            try:
                result = subprocess.run(
                    ["claude", "-p", "--output-format", "text",
                     "--max-turns", "1", "--model", MODEL_FAST],
                    input=prompt, capture_output=True, text=True, timeout=90,
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Parse JSON from response
                    text = result.stdout.strip()
                    json_match = re.search(r"\[[\s\S]*\]", text)
                    if json_match:
                        validations = json.loads(json_match.group())
                        valid_ids = {v["id"] for v in validations if v.get("valid")}
                        for v in validations:
                            if v.get("valid"):
                                # Find the original finding and upgrade it
                                for f in batch:
                                    if f["id"] == v["id"]:
                                        f["confidence"] = v.get("confidence", "medium")
                                        f["data_flow"] = v.get("data_flow", "")
                                        f["validation_reason"] = v.get("reason", "")
                                        validated.append(f)
                                        break
            except Exception:
                # On LLM failure, keep high-signal findings anyway
                for f in batch:
                    if f["sink_type"] in ("command_injection", "deserialization", "sql_injection"):
                        f["confidence"] = "low"
                        f["validation_reason"] = "LLM validation failed — kept due to high-risk sink type"
                        validated.append(f)

    return validated


def run_audit(engagement: ResearchEngagement, on_status=None) -> list[dict]:
    """Run full static audit pipeline on a research target.

    1. Grep-based pattern matching (always available)
    2. Semgrep scan (if installed)
    3. LLM validation of all findings (aggressive FP filtering)
    4. Update engagement state with validated sinks and bug candidates

    Returns list of validated findings.
    """
    target_path = engagement.target_path
    language = engagement.profile.language

    if on_status:
        on_status(f"[static_auditor] Starting audit of {engagement.target_name} ({language})")

    # Phase 1: Grep patterns
    if on_status:
        on_status("[static_auditor] Running pattern scan...")
    grep_findings = grep_audit(target_path, language)
    if on_status:
        on_status(f"[static_auditor] Pattern scan: {len(grep_findings)} raw hits")

    # Phase 2: Semgrep (if available)
    semgrep_findings = []
    if _check_tool("semgrep"):
        if on_status:
            on_status("[static_auditor] Running Semgrep...")
        semgrep_findings = semgrep_audit(target_path, language)
        if on_status:
            on_status(f"[static_auditor] Semgrep: {len(semgrep_findings)} raw hits")
    else:
        if on_status:
            on_status("[static_auditor] Semgrep not installed — skipping")

    # Combine and deduplicate by file:line
    all_findings = grep_findings + semgrep_findings
    seen = set()
    deduped = []
    for f in all_findings:
        key = f"{f['file']}:{f['line']}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if on_status:
        on_status(f"[static_auditor] {len(deduped)} unique findings — validating with LLM...")

    # Phase 3: LLM validation (aggressive FP filtering)
    validated = validate_findings_llm(deduped, target_path, language, on_status)

    if on_status:
        on_status(f"[static_auditor] {len(validated)} findings survived validation "
                  f"({len(deduped) - len(validated)} filtered as FP)")

    # Phase 4: Update engagement state
    for f in validated:
        engagement.sinks.append({
            "id": len(engagement.sinks) + 1,
            "file": f["file"],
            "line": f["line"],
            "function": "",  # could be extracted with more analysis
            "sink_type": f["sink_type"],
            "confidence": f["confidence"],
            "data_flow": f.get("data_flow", ""),
        })

        # High-confidence findings become bug candidates
        if f["confidence"] in ("high", "medium"):
            engagement.add_bug_candidate(
                type=f["sink_type"],
                cwe=_sink_to_cwe(f["sink_type"]),
                title=f["description"],
                location=f"{f['file']}:{f['line']}",
                what=f["description"],
                why=f.get("validation_reason", ""),
                data_flow=f.get("data_flow", ""),
                confidence=f["confidence"],
                evidence=f.get("content", ""),
            )

    engagement.current_phase = "audit"
    if "audit" not in engagement.completed_phases:
        engagement.completed_phases.append("audit")
    engagement.save()

    return validated


def _sink_to_cwe(sink_type: str) -> str:
    """Map sink type to CWE ID."""
    return {
        "buffer_overflow": "CWE-787",
        "format_string": "CWE-134",
        "command_injection": "CWE-78",
        "sql_injection": "CWE-89",
        "xss": "CWE-79",
        "deserialization": "CWE-502",
        "path_traversal": "CWE-22",
        "ssti": "CWE-1336",
        "xxe": "CWE-611",
        "file_inclusion": "CWE-98",
        "code_injection": "CWE-94",
        "type_juggling": "CWE-843",
        "integer_overflow": "CWE-190",
        "double_free": "CWE-415",
        "use_after_free": "CWE-416",
        "prototype_pollution": "CWE-1321",
        "ssrf": "CWE-918",
        "race_condition": "CWE-362",
        "memory_safety": "CWE-119",
        "open_redirect": "CWE-601",
        "jndi_injection": "CWE-917",
        "expression_injection": "CWE-917",
    }.get(sink_type, "")
