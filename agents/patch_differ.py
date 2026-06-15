"""Patch differ agent — finds security-relevant kernel patches and identifies unpatched versions.

Monitors kernel stable branch commits for security fixes, diffs them to understand
the vulnerability, and checks which stable/LTS branches are still affected.

Pipeline:
  1. Fetch recent commits from stable branches (git log)
  2. Filter for security-relevant commits (fixes tags, CVE references, known patterns)
  3. Diff each patch to identify: what was broken, how it was fixed
  4. LLM classifies severity and exploitability
  5. Check which other branches lack the fix
  6. Generate bug candidates for unpatched versions
"""

import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_FAST
from research_engagement import ResearchEngagement


# --- Kernel git helpers ---

def _git(args: list[str], cwd: str, timeout: int = 30) -> str:
    """Run a git command and return stdout."""
    try:
        result = subprocess.run(
            ["git"] + args, cwd=cwd,
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return ""


def get_stable_branches(kernel_src: str) -> list[str]:
    """List available stable/LTS branches in the kernel tree."""
    output = _git(["branch", "-r"], kernel_src)
    branches = []
    for line in output.strip().split("\n"):
        line = line.strip()
        # Match patterns like origin/linux-6.1.y, origin/linux-5.15.y
        if re.match(r"origin/linux-\d+\.\d+\.y", line):
            branches.append(line.replace("origin/", ""))
    return sorted(branches)


def get_recent_commits(kernel_src: str, branch: str = "HEAD",
                       days: int = 7, max_count: int = 200) -> list[dict]:
    """Get recent commits from a branch.

    Returns list of {hash, subject, body, author, date}.
    """
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    output = _git(
        ["log", branch, f"--since={since}", f"--max-count={max_count}",
         "--format=%H|||%s|||%b|||%an|||%ai", "--no-merges"],
        kernel_src, timeout=60,
    )

    commits = []
    for line in output.strip().split("\n"):
        if not line or "|||" not in line:
            continue
        parts = line.split("|||")
        if len(parts) >= 5:
            commits.append({
                "hash": parts[0],
                "subject": parts[1],
                "body": parts[2],
                "author": parts[3],
                "date": parts[4],
            })
    return commits


# --- Security-relevant commit detection ---

# Patterns that indicate a commit is security-relevant
_SECURITY_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE),
    re.compile(r"Fixes:\s+[0-9a-f]{12}", re.IGNORECASE),  # Fixes: <hash>
    re.compile(r"\b(use.after.free|buffer.overflow|out.of.bounds|null.pointer"
               r"|double.free|integer.overflow|race.condition|heap.overflow"
               r"|stack.overflow|privilege.escalation|information.leak"
               r"|memory.corruption|type.confusion|uninitialized)\b", re.IGNORECASE),
    re.compile(r"\b(fix|prevent|avoid|check|validate|sanitize|bounds)"
               r".*(overflow|underflow|oob|null|uaf|leak|corrupt)", re.IGNORECASE),
    re.compile(r"security|vulnerability|exploit", re.IGNORECASE),
]

# High-signal patterns (very likely security fix)
_HIGH_SIGNAL = [
    re.compile(r"CVE-\d{4}-\d+"),
    re.compile(r"use.after.free|buffer.overflow|out.of.bounds.write|privilege.escalation", re.IGNORECASE),
]


def is_security_relevant(commit: dict) -> tuple[bool, str]:
    """Check if a commit is security-relevant. Returns (is_relevant, reason)."""
    text = f"{commit['subject']} {commit['body']}"

    for pattern in _HIGH_SIGNAL:
        match = pattern.search(text)
        if match:
            return True, f"high_signal: {match.group()}"

    for pattern in _SECURITY_PATTERNS:
        match = pattern.search(text)
        if match:
            return True, f"pattern: {match.group()}"

    return False, ""


def filter_security_commits(commits: list[dict]) -> list[dict]:
    """Filter commits to only security-relevant ones."""
    results = []
    for commit in commits:
        relevant, reason = is_security_relevant(commit)
        if relevant:
            commit["security_reason"] = reason
            results.append(commit)
    return results


# --- Patch diffing ---

def get_commit_diff(kernel_src: str, commit_hash: str) -> str:
    """Get the full diff for a commit."""
    return _git(["show", "--stat", "--patch", commit_hash], kernel_src, timeout=30)


def get_fixed_commit(kernel_src: str, commit_hash: str) -> str | None:
    """Find the original commit that this one fixes (from Fixes: tag)."""
    body = _git(["log", "-1", "--format=%b", commit_hash], kernel_src)
    match = re.search(r"Fixes:\s+([0-9a-f]{12,})", body)
    if match:
        return match.group(1)
    return None


def check_branch_has_commit(kernel_src: str, branch: str, commit_hash: str) -> bool:
    """Check if a branch contains a specific commit."""
    output = _git(
        ["branch", "-r", "--contains", commit_hash],
        kernel_src, timeout=15,
    )
    return branch in output or f"origin/{branch}" in output


# --- LLM patch analysis ---

def analyze_patch(diff: str, commit: dict, on_status=None) -> dict:
    """Use LLM to analyze a security patch and assess the original vulnerability.

    Returns {vulnerability_type, severity, exploitability, affected_subsystem,
             description, impact, cwe}.
    """
    prompt = f"""Analyze this Linux kernel security patch. Determine what vulnerability it fixes.

Commit: {commit['hash'][:12]}
Subject: {commit['subject']}
Message: {commit['body'][:500]}

Patch diff:
{diff[:4000]}

Respond in JSON:
{{
  "vulnerability_type": "e.g., use-after-free, buffer overflow, race condition, etc.",
  "cwe": "CWE-XXX",
  "severity": "critical/high/medium/low",
  "exploitability": "weaponizable/promising/interesting/low_value",
  "affected_subsystem": "kernel subsystem (e.g., netfilter, io_uring, mm, fs/ext4)",
  "description": "plain language: what the vulnerability is and how it's triggered",
  "impact": "what an attacker can achieve (LPE, DoS, info leak, etc.)",
  "root_cause": "why the code was vulnerable (missing check, wrong type, race window)",
  "trigger_conditions": "how to trigger the bug (specific syscalls, configs, etc.)"
}}

If this is NOT a security fix (just a regular bug fix), set severity to "none"."""

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text",
             "--max-turns", "1", "--model", MODEL_FAST],
            input=prompt, capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            json_match = re.search(r"\{[\s\S]*\}", result.stdout)
            if json_match:
                return json.loads(json_match.group())
    except Exception:
        pass

    return {
        "vulnerability_type": "unknown",
        "severity": "unknown",
        "exploitability": "interesting",
        "description": commit["subject"],
    }


# --- Main pipeline ---

def diff_patches(kernel_src: str, engagement: ResearchEngagement,
                 days: int = 7, target_version: str = "",
                 on_status=None) -> dict:
    """Run full patch diffing pipeline.

    1. Fetch recent commits from mainline
    2. Filter security-relevant
    3. Diff and analyze each
    4. Check which stable branches lack the fix
    5. Generate bug candidates for unpatched versions

    Args:
        kernel_src: Path to kernel git tree
        days: How far back to search
        target_version: If set, only report bugs affecting this version

    Returns summary dict.
    """
    if on_status:
        on_status(f"[patch_differ] Scanning last {days} days of kernel commits...")

    # Step 1: Fetch recent commits
    commits = get_recent_commits(kernel_src, "HEAD", days)
    if on_status:
        on_status(f"[patch_differ] {len(commits)} commits in last {days} days")

    # Step 2: Filter security-relevant
    security = filter_security_commits(commits)
    if on_status:
        on_status(f"[patch_differ] {len(security)} security-relevant commits")

    if not security:
        return {"patches_analyzed": 0, "bugs_found": 0}

    # Step 3: Analyze each patch
    summary = {
        "patches_analyzed": 0,
        "bugs_found": 0,
        "unpatched_branches": {},
        "findings": [],
    }

    stable_branches = get_stable_branches(kernel_src)

    for commit in security[:30]:  # cap at 30 patches per run
        diff = get_commit_diff(kernel_src, commit["hash"])
        if not diff:
            continue

        if on_status:
            on_status(f"[patch_differ] Analyzing: {commit['subject'][:60]}")

        # LLM analysis
        analysis = analyze_patch(diff, commit, on_status)
        summary["patches_analyzed"] += 1

        # Skip non-security fixes
        if analysis.get("severity") == "none":
            continue

        # Step 4: Check which branches lack this fix
        unpatched = []
        fix_hash = commit["hash"]
        for branch in stable_branches:
            if not check_branch_has_commit(kernel_src, branch, fix_hash):
                unpatched.append(branch)

        # Filter to target version if specified
        if target_version and unpatched:
            matching = [b for b in unpatched if target_version in b]
            if not matching:
                continue  # fix exists in target version
            unpatched = matching

        if unpatched:
            summary["unpatched_branches"][commit["hash"][:12]] = unpatched

        # Step 5: Generate bug candidate
        cve_match = re.search(r"CVE-\d{4}-\d+", f"{commit['subject']} {commit['body']}")
        cve_id = cve_match.group() if cve_match else ""

        finding = {
            "commit": commit["hash"][:12],
            "subject": commit["subject"],
            "cve": cve_id,
            "analysis": analysis,
            "unpatched_branches": unpatched,
        }
        summary["findings"].append(finding)
        summary["bugs_found"] += 1

        # Add to engagement state
        engagement.add_bug_candidate(
            type=analysis.get("vulnerability_type", "unknown"),
            cwe=analysis.get("cwe", ""),
            title=f"[patch] {commit['subject'][:80]}",
            location=f"kernel commit {commit['hash'][:12]}",
            what=analysis.get("description", ""),
            why=analysis.get("root_cause", ""),
            impact=analysis.get("impact", ""),
            exploitability=analysis.get("exploitability", "interesting"),
            confidence="high" if cve_id else "medium",
            evidence=f"fix:{commit['hash'][:12]}",
        )

        if on_status:
            sev = analysis.get("severity", "?")
            branches_str = f" UNPATCHED: {', '.join(unpatched)}" if unpatched else ""
            on_status(f"[patch_differ] [{sev.upper()}] {commit['subject'][:60]}"
                      f"{' (' + cve_id + ')' if cve_id else ''}{branches_str}")

    engagement.current_phase = "patch_diff"
    if "patch_diff" not in engagement.completed_phases:
        engagement.completed_phases.append("patch_diff")
    engagement.save()

    if on_status:
        on_status(f"[patch_differ] Done: {summary['patches_analyzed']} patches analyzed, "
                  f"{summary['bugs_found']} security-relevant, "
                  f"{len(summary['unpatched_branches'])} with unpatched branches")

    return summary


def diff_single_commit(kernel_src: str, commit_hash: str,
                       on_status=None) -> dict:
    """Analyze a single commit for security relevance.

    Useful for manual investigation of a specific fix.
    """
    diff = get_commit_diff(kernel_src, commit_hash)
    if not diff:
        return {"error": "Could not get diff"}

    # Get commit info
    output = _git(
        ["log", "-1", "--format=%H|||%s|||%b|||%an|||%ai", commit_hash],
        kernel_src,
    )
    parts = output.strip().split("|||")
    commit = {
        "hash": parts[0] if parts else commit_hash,
        "subject": parts[1] if len(parts) > 1 else "",
        "body": parts[2] if len(parts) > 2 else "",
        "author": parts[3] if len(parts) > 3 else "",
        "date": parts[4] if len(parts) > 4 else "",
    }

    analysis = analyze_patch(diff, commit, on_status)

    # Check branches
    stable = get_stable_branches(kernel_src)
    unpatched = [b for b in stable if not check_branch_has_commit(kernel_src, b, commit_hash)]

    # Find the original broken commit
    fixed_commit = get_fixed_commit(kernel_src, commit_hash)

    return {
        "commit": commit,
        "analysis": analysis,
        "diff_preview": diff[:2000],
        "unpatched_branches": unpatched,
        "fixes_commit": fixed_commit,
    }
