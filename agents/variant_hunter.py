"""Variant hunter agent — finds the same bug pattern in other locations.

Takes a confirmed vulnerability, extracts the pattern, builds detection
rules (grep/Semgrep), and scans for variants in the same codebase and
optionally in other targets.

This is where a single bug becomes a bug class.
"""

import json
import os
import re
import subprocess

import claude_client
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, MODEL_FAST
from research_engagement import ResearchEngagement


def extract_pattern(bug: dict, source_context: str = "",
                    on_status=None) -> dict:
    """Use LLM to extract a generalizable vulnerability pattern from a confirmed bug.

    Returns {pattern_description, grep_pattern, semgrep_rule, search_terms}.
    """
    prompt = f"""Analyze this confirmed vulnerability and extract the generalizable pattern
so we can find VARIANTS of the same bug in other code.

Bug: {bug.get('title', bug.get('type', '?'))}
CWE: {bug.get('cwe', '')}
Location: {bug.get('location', '?')}
Root cause: {bug.get('why', bug.get('root_cause', '?'))}
Data flow: {bug.get('data_flow', '')}
Evidence: {bug.get('evidence', '')[:300]}

{f'Source context:{chr(10)}{source_context[:2000]}' if source_context else ''}

Extract the PATTERN — what makes this code vulnerable, abstracted from this specific instance.

Respond in JSON:
{{
  "pattern_description": "one paragraph describing the vulnerable pattern in general terms",
  "grep_patterns": ["list of grep -P regex patterns that catch this bug class"],
  "semgrep_rule": "a YAML Semgrep rule (as a string) if applicable, or empty string",
  "search_terms": ["keywords to search for this pattern in other code"],
  "affected_functions": ["function names/APIs that are commonly misused this way"],
  "fix_pattern": "what the correct code looks like"
}}"""

    if on_status:
        on_status(f"[variant_hunter] Extracting pattern from BUG-{bug.get('id', '?')}...")

    try:
        result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            json_match = re.search(r"\{[\s\S]*\}", result.stdout)
            if json_match:
                return json.loads(json_match.group())
    except Exception:
        pass

    # Fallback: basic pattern from bug type
    return {
        "pattern_description": f"Potential {bug.get('type', 'vulnerability')} pattern",
        "grep_patterns": [],
        "semgrep_rule": "",
        "search_terms": [bug.get("type", "")],
        "affected_functions": [],
        "fix_pattern": "",
    }


def scan_for_variants(pattern: dict, target_path: str,
                      language: str = "", on_status=None) -> list[dict]:
    """Scan a codebase for variants matching the extracted pattern.

    Uses grep patterns first (fast), then validates with LLM (accurate).
    Returns list of variant candidates.
    """
    candidates = []

    # Map language to file extensions for grep
    ext_map = {
        "c": "*.c", "cpp": "*.cpp", "php": "*.php",
        "python": "*.py", "javascript": "*.js", "java": "*.java", "go": "*.go",
    }
    include = ext_map.get(language, "*.*")

    # Phase 1: Grep scan
    grep_patterns = pattern.get("grep_patterns", [])
    if not grep_patterns:
        # Use search terms as fallback
        grep_patterns = [re.escape(t) for t in pattern.get("search_terms", []) if t]

    raw_hits = []
    for gp in grep_patterns:
        try:
            result = subprocess.run(
                ["grep", "-rnP", "--include", include, gp, target_path],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                match = re.match(r"^(.+?):(\d+):(.+)$", line)
                if match:
                    raw_hits.append({
                        "file": match.group(1),
                        "line": int(match.group(2)),
                        "content": match.group(3).strip()[:200],
                        "pattern": gp[:50],
                    })
        except Exception:
            continue

    # Dedup by file:line
    seen = set()
    deduped = []
    for h in raw_hits:
        key = f"{h['file']}:{h['line']}"
        if key not in seen:
            seen.add(key)
            deduped.append(h)

    if not deduped:
        if on_status:
            on_status("[variant_hunter] No grep matches found")
        return []

    if on_status:
        on_status(f"[variant_hunter] {len(deduped)} potential matches — validating...")

    # Phase 2: Semgrep scan (if rule provided and tool available)
    semgrep_rule = pattern.get("semgrep_rule", "")
    if semgrep_rule:
        try:
            rule_path = Path("/tmp/variant_rule.yaml")
            rule_path.write_text(semgrep_rule)
            result = subprocess.run(
                ["semgrep", "scan", "--config", str(rule_path),
                 "--sarif", "--quiet", target_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode in (0, 1):
                sarif = json.loads(result.stdout)
                for run in sarif.get("runs", []):
                    for r in run.get("results", []):
                        for loc in r.get("locations", []):
                            phys = loc.get("physicalLocation", {})
                            file_path = phys.get("artifactLocation", {}).get("uri", "")
                            line = phys.get("region", {}).get("startLine", 0)
                            key = f"{file_path}:{line}"
                            if key not in seen:
                                seen.add(key)
                                deduped.append({
                                    "file": file_path,
                                    "line": line,
                                    "content": phys.get("region", {}).get("snippet", {}).get("text", "")[:200],
                                    "pattern": "semgrep_rule",
                                })
        except Exception:
            pass

    # Phase 3: LLM validation (batch)
    validated = _validate_variants_llm(deduped, pattern, target_path, language, on_status)

    return validated


def _validate_variants_llm(hits: list[dict], pattern: dict, target_path: str,
                           language: str, on_status=None) -> list[dict]:
    """Use LLM to validate if grep hits are real variants of the original bug."""
    if not hits:
        return []

    # Read source context for each hit
    hit_contexts = []
    for h in hits[:15]:  # cap at 15
        try:
            full_path = h["file"] if os.path.isabs(h["file"]) else os.path.join(target_path, h["file"])
            lines = Path(full_path).read_text(errors="ignore").split("\n")
            line_num = h["line"]
            start = max(0, line_num - 8)
            end = min(len(lines), line_num + 7)
            context = "\n".join(f"{n+1}: {lines[n]}" for n in range(start, end))
            hit_contexts.append(
                f"### {h['file']}:{h['line']}\n```{language}\n{context}\n```"
            )
        except Exception:
            hit_contexts.append(f"### {h['file']}:{h['line']}\n{h['content']}")

    prompt = f"""You are validating potential vulnerability variants.

The ORIGINAL bug pattern is:
{pattern.get('pattern_description', 'Unknown pattern')}

Fix pattern (what correct code looks like):
{pattern.get('fix_pattern', 'Not specified')}

Below are code locations that matched a grep search for this pattern.
For each, determine if it's a TRUE VARIANT (same bug class, exploitable)
or a FALSE POSITIVE (pattern matched but not actually vulnerable).

{chr(10).join(hit_contexts)}

Respond in JSON array:
[
  {{"file": "path", "line": N, "is_variant": true/false, "confidence": "high/medium/low",
    "reason": "why this is or isn't a variant", "severity": "same/higher/lower than original"}}
]

Be AGGRESSIVE in filtering. Only mark as variant if the code is clearly
vulnerable in the same way as the original bug."""

    try:
        result = claude_client.oneshot(prompt, model=MODEL_FAST, timeout=90)
        if result.returncode == 0 and result.stdout.strip():
            json_match = re.search(r"\[[\s\S]*\]", result.stdout)
            if json_match:
                validations = json.loads(json_match.group())
                return [v for v in validations if v.get("is_variant")]
    except Exception:
        pass

    return []


# --- Main pipeline ---

def hunt_variants(engagement: ResearchEngagement, additional_targets: list[str] = None,
                  on_status=None) -> dict:
    """Hunt for variants of all confirmed bugs.

    1. For each confirmed bug: extract pattern → scan → validate
    2. Optionally scan additional codebases
    3. Update engagement state

    Returns summary.
    """
    confirmed = engagement.confirmed_bugs
    if not confirmed:
        if on_status:
            on_status("[variant_hunter] No confirmed bugs to hunt variants for")
        return {"hunted": 0, "variants_found": 0}

    if on_status:
        on_status(f"[variant_hunter] Hunting variants for {len(confirmed)} confirmed bugs...")

    targets = [engagement.target_path]
    if additional_targets:
        targets.extend(additional_targets)

    summary = {"hunted": 0, "variants_found": 0, "by_bug": {}}

    for bug in confirmed:
        bug_id = bug.get("id", "?")

        # Read source context around the original bug
        source_context = ""
        location = bug.get("location", "")
        if ":" in location:
            file_path, line_str = location.rsplit(":", 1)
            try:
                line_num = int(re.search(r"\d+", line_str).group())
                full_path = file_path if os.path.isabs(file_path) else os.path.join(
                    engagement.target_path, file_path)
                lines = Path(full_path).read_text(errors="ignore").split("\n")
                start = max(0, line_num - 20)
                end = min(len(lines), line_num + 20)
                source_context = "\n".join(lines[start:end])
            except Exception:
                pass

        # Extract pattern
        pattern = extract_pattern(bug, source_context, on_status)

        # Save pattern rules for future use
        if pattern.get("grep_patterns"):
            rule_path = engagement.variant_dir / f"bug_{bug_id}_patterns.json"
            rule_path.write_text(json.dumps(pattern, indent=2))

        if pattern.get("semgrep_rule"):
            semgrep_path = engagement.variant_dir / f"bug_{bug_id}_rule.yaml"
            semgrep_path.write_text(pattern["semgrep_rule"])

        # Scan each target
        bug_variants = []
        for target in targets:
            if not os.path.exists(target):
                continue
            variants = scan_for_variants(
                pattern, target, engagement.profile.language, on_status
            )

            # Filter out the original bug location
            orig_loc = bug.get("location", "")
            variants = [v for v in variants
                        if f"{v.get('file', '')}:{v.get('line', '')}" != orig_loc]

            bug_variants.extend(variants)

        # Register variants in engagement state
        for v in bug_variants:
            engagement.variants.append({
                "id": len(engagement.variants) + 1,
                "original_bug_id": bug_id,
                "location": f"{v.get('file', '?')}:{v.get('line', '?')}",
                "status": "candidate",
                "confidence": v.get("confidence", "medium"),
                "reason": v.get("reason", ""),
                "severity": v.get("severity", "same"),
                "pattern": pattern.get("pattern_description", "")[:200],
            })

        summary["hunted"] += 1
        summary["variants_found"] += len(bug_variants)
        summary["by_bug"][str(bug_id)] = len(bug_variants)

        if on_status:
            on_status(f"[variant_hunter] BUG-{bug_id}: {len(bug_variants)} variants found")

    engagement.current_phase = "variant_hunt"
    if "variant_hunt" not in engagement.completed_phases:
        engagement.completed_phases.append("variant_hunt")
    engagement.save()

    if on_status:
        on_status(f"[variant_hunter] Done: {summary['variants_found']} variants "
                  f"across {summary['hunted']} bugs")
    return summary
