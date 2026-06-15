#!/usr/bin/env python3
"""Test harness for validating the exit condition against a hardened target.

Runs the full orchestrator chain against a target expected to have no
vulnerabilities (e.g., fully patched VM with minimal services). Validates
that the system correctly identifies "nothing here" and exits gracefully
within budget constraints.

Usage:
    python3 tests/test_hardened_target.py --target <ip> [--max-cost 5.00] [--timeout 3600]

    # Dry run (tests exit evaluator with synthetic data, no real target)
    python3 tests/test_hardened_target.py --dry-run

Pass criteria:
    1. System exits autonomously (exit evaluator score >= threshold)
    2. Total cost stays within budget
    3. No false-positive high/critical findings in the DB
    4. Completes within timeout
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from engagement import Engagement
from agents.orchestrator import Orchestrator
from findings_db import FindingsDB
from exit_evaluator import ExitEvaluator, EXIT_THRESHOLD


@dataclass
class TestResult:
    passed: bool
    exit_score: float
    total_cost: float
    total_phases: int
    total_findings: int
    high_findings: int
    elapsed_seconds: float
    exit_reason: str
    phase_log: list
    details: dict


def run_dry_test() -> TestResult:
    """Test the exit evaluator with synthetic data — no real target needed.

    Simulates various engagement scenarios and verifies the exit evaluator
    produces correct scores.
    """
    print("=== DRY RUN: Testing exit evaluator with synthetic data ===\n")

    db = FindingsDB()
    db.clear()
    results = {}

    # Test 1: Empty engagement — all agents ran, zero findings
    print("Test 1: All core agents ran, zero findings...")
    phase_log = [
        {"agent": "recon", "stuck_killed": False, "turns": 15, "elapsed": "02:30", "time": datetime.now().isoformat()},
        {"agent": "cvehunter", "stuck_killed": False, "turns": 10, "elapsed": "01:45", "time": datetime.now().isoformat()},
        {"agent": "exploit", "stuck_killed": False, "turns": 12, "elapsed": "02:00", "time": datetime.now().isoformat()},
    ]
    ee = ExitEvaluator(db, phase_log)
    score = ee.evaluate()
    results["empty_all_agents"] = {
        "score": score.score,
        "should_exit": score.should_exit,
        "expected_exit": True,
        "pass": score.should_exit,
    }
    print(f"  Score: {score.score:.2f}, Should exit: {score.should_exit} (expected: True)")
    print(f"  Reasons: {score.reasons}")
    assert score.should_exit, f"Expected exit but got score {score.score}"
    print("  PASSED\n")

    # Test 2: Stuck agents — high error rate
    print("Test 2: Multiple stuck-killed agents...")
    phase_log_stuck = [
        {"agent": "recon", "stuck_killed": False, "turns": 15, "elapsed": "02:00", "time": datetime.now().isoformat()},
        {"agent": "exploit", "stuck_killed": True, "turns": 5, "elapsed": "01:00", "time": datetime.now().isoformat()},
        {"agent": "cvehunter", "stuck_killed": True, "turns": 3, "elapsed": "00:30", "time": datetime.now().isoformat()},
        {"agent": "exploit", "stuck_killed": True, "turns": 2, "elapsed": "00:15", "time": datetime.now().isoformat()},
    ]
    ee2 = ExitEvaluator(db, phase_log_stuck)
    score2 = ee2.evaluate()
    results["stuck_agents"] = {
        "score": score2.score,
        "should_exit": score2.should_exit,
        "expected_exit": True,
        "pass": score2.should_exit,
    }
    print(f"  Score: {score2.score:.2f}, Should exit: {score2.should_exit} (expected: True)")
    print(f"  Reasons: {score2.reasons}")
    assert score2.should_exit, f"Expected exit but got score {score2.score}"
    print("  PASSED\n")

    # Test 3: Active engagement with high findings — should NOT exit
    print("Test 3: Active engagement with high-severity findings (should continue)...")
    from findings_db import Finding
    db.add(Finding(host="10.10.10.5", port=445, service="smb", finding_type="vulnerability",
                   severity="high", title="MS17-010", agent="cvehunter", exploitable=True))
    db.add(Finding(host="10.10.10.5", port=80, service="http", finding_type="vulnerability",
                   severity="critical", title="RCE in Apache", agent="exploit", exploitable=True))

    phase_log_active = [
        {"agent": "recon", "stuck_killed": False, "turns": 15, "elapsed": "02:00", "time": datetime.now().isoformat()},
        {"agent": "exploit", "stuck_killed": False, "turns": 20, "elapsed": "05:00", "time": datetime.now().isoformat()},
    ]
    ee3 = ExitEvaluator(db, phase_log_active)
    score3 = ee3.evaluate()
    results["active_engagement"] = {
        "score": score3.score,
        "should_exit": score3.should_exit,
        "expected_exit": False,
        "pass": not score3.should_exit,
    }
    print(f"  Score: {score3.score:.2f}, Should exit: {score3.should_exit} (expected: False)")
    print(f"  Reasons: {score3.reasons}")
    assert not score3.should_exit, f"Expected continue but got exit at score {score3.score}"
    print("  PASSED\n")

    # Test 4: Info-only findings after many phases
    print("Test 4: Info-only findings after exhausting attack paths...")
    db.clear()
    db.add(Finding(host="10.10.10.5", port=22, service="ssh", finding_type="service",
                   severity="info", title="OpenSSH 8.9", agent="recon"))
    db.add(Finding(host="10.10.10.5", port=80, service="http", finding_type="service",
                   severity="info", title="nginx 1.24", agent="recon"))

    phase_log_exhausted = [
        {"agent": "recon", "stuck_killed": False, "turns": 15, "elapsed": "02:00", "time": datetime.now().isoformat()},
        {"agent": "cvehunter", "stuck_killed": False, "turns": 8, "elapsed": "01:00", "time": datetime.now().isoformat()},
        {"agent": "exploit", "stuck_killed": False, "turns": 10, "elapsed": "02:00", "time": datetime.now().isoformat()},
    ]
    ee4 = ExitEvaluator(db, phase_log_exhausted)
    score4 = ee4.evaluate()
    results["info_only_exhausted"] = {
        "score": score4.score,
        "should_exit": score4.should_exit,
        "expected_exit": True,
        "pass": score4.should_exit,
    }
    print(f"  Score: {score4.score:.2f}, Should exit: {score4.should_exit} (expected: True)")
    print(f"  Reasons: {score4.reasons}")
    assert score4.should_exit, f"Expected exit but got score {score4.score}"
    print("  PASSED\n")

    # Test 5: Early engagement — too early to exit
    print("Test 5: Early engagement, only recon done (should continue)...")
    db.clear()
    phase_log_early = [
        {"agent": "recon", "stuck_killed": False, "turns": 15, "elapsed": "02:00", "time": datetime.now().isoformat()},
    ]
    ee5 = ExitEvaluator(db, phase_log_early)
    score5 = ee5.evaluate()
    results["early_engagement"] = {
        "score": score5.score,
        "should_exit": score5.should_exit,
        "expected_exit": False,
        "pass": not score5.should_exit,
    }
    print(f"  Score: {score5.score:.2f}, Should exit: {score5.should_exit} (expected: False)")
    print(f"  Reasons: {score5.reasons}")
    assert not score5.should_exit, f"Expected continue but got exit at score {score5.score}"
    print("  PASSED\n")

    # Clean up
    db.clear()

    all_passed = all(r["pass"] for r in results.values())
    print(f"{'='*60}")
    print(f"DRY RUN RESULTS: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    for name, r in results.items():
        status = "PASS" if r["pass"] else "FAIL"
        print(f"  [{status}] {name}: score={r['score']:.2f}, exit={r['should_exit']} (expected={r['expected_exit']})")

    return TestResult(
        passed=all_passed,
        exit_score=0,
        total_cost=0,
        total_phases=0,
        total_findings=0,
        high_findings=0,
        elapsed_seconds=0,
        exit_reason="dry run",
        phase_log=[],
        details=results,
    )


def run_live_test(target: str, max_cost: float, timeout: int) -> TestResult:
    """Run the full chain against a real hardened target."""
    print(f"=== LIVE TEST: Running chain against {target} ===")
    print(f"  Max cost: ${max_cost:.2f}")
    print(f"  Timeout: {timeout}s")
    print(f"  Exit threshold: {EXIT_THRESHOLD}")
    print()

    # Set up engagement
    state = Engagement()
    state.set_target(target, scope=target)
    state.autonomous = True

    orchestrator = Orchestrator(state, autonomous=True)
    db = orchestrator.findings_db
    db.clear()  # Fresh DB for this test

    def on_status(msg):
        print(f"  {msg}")

    start_time = time.monotonic()
    exit_reason = "completed"

    try:
        result = orchestrator.run_chain(on_status=on_status, on_progress=None)
    except KeyboardInterrupt:
        exit_reason = "interrupted"
        result = ""
    except Exception as e:
        exit_reason = f"error: {e}"
        result = ""

    elapsed = time.monotonic() - start_time

    # Evaluate results
    total_cost = sum(a._last_cost for a in orchestrator._agents.values())
    total_findings = db.count()
    high_findings = db.count(min_severity="high")

    exit_eval = ExitEvaluator(db, orchestrator.phase_log)
    final_score = exit_eval.evaluate()

    # Pass criteria
    within_budget = total_cost <= max_cost
    within_timeout = elapsed <= timeout
    clean_exit = final_score.score >= EXIT_THRESHOLD
    no_false_positives = high_findings == 0

    passed = within_budget and within_timeout and clean_exit and no_false_positives

    print(f"\n{'='*60}")
    print(f"LIVE TEST RESULTS: {'PASSED' if passed else 'FAILED'}")
    print(f"  Exit score:    {final_score.score:.2f}/{EXIT_THRESHOLD} {'PASS' if clean_exit else 'FAIL'}")
    print(f"  Total cost:    ${total_cost:.4f}/${max_cost:.2f} {'PASS' if within_budget else 'FAIL'}")
    print(f"  Elapsed:       {elapsed:.0f}s/{timeout}s {'PASS' if within_timeout else 'FAIL'}")
    print(f"  Total findings: {total_findings}")
    print(f"  High+ findings: {high_findings} {'PASS' if no_false_positives else 'FAIL (false positives!)'}")
    print(f"  Phases:        {len(orchestrator.phase_log)}")
    print(f"  Exit reason:   {exit_reason}")
    print(f"  Exit factors:  {final_score.reasons}")

    if orchestrator.phase_log:
        print(f"\n  Phase breakdown:")
        for entry in orchestrator.phase_log:
            stuck_tag = " [STUCK]" if entry.get("stuck_killed") else ""
            print(f"    {entry['agent']}: {entry.get('elapsed', '??')} "
                  f"({entry.get('turns', '?')} turns, ${entry.get('cost', 0):.4f}){stuck_tag}")

    return TestResult(
        passed=passed,
        exit_score=final_score.score,
        total_cost=total_cost,
        total_phases=len(orchestrator.phase_log),
        total_findings=total_findings,
        high_findings=high_findings,
        elapsed_seconds=elapsed,
        exit_reason=exit_reason,
        phase_log=orchestrator.phase_log,
        details={
            "within_budget": within_budget,
            "within_timeout": within_timeout,
            "clean_exit": clean_exit,
            "no_false_positives": no_false_positives,
            "exit_score_reasons": final_score.reasons,
        },
    )


def main():
    parser = argparse.ArgumentParser(description="Test exit condition against a hardened target")
    parser.add_argument("--target", type=str, help="IP of the hardened target")
    parser.add_argument("--max-cost", type=float, default=5.0, help="Max USD to spend (default: 5.00)")
    parser.add_argument("--timeout", type=int, default=3600, help="Max seconds (default: 3600)")
    parser.add_argument("--dry-run", action="store_true", help="Test exit evaluator with synthetic data only")
    args = parser.parse_args()

    if args.dry_run:
        result = run_dry_test()
    elif args.target:
        result = run_live_test(args.target, args.max_cost, args.timeout)
    else:
        parser.print_help()
        print("\nEither --target <ip> or --dry-run is required.")
        sys.exit(1)

    # Save test results
    results_path = Path(__file__).parent / "test_results.json"
    results_path.write_text(json.dumps({
        "passed": result.passed,
        "exit_score": result.exit_score,
        "total_cost": result.total_cost,
        "total_phases": result.total_phases,
        "total_findings": result.total_findings,
        "high_findings": result.high_findings,
        "elapsed_seconds": result.elapsed_seconds,
        "exit_reason": result.exit_reason,
        "timestamp": datetime.now().isoformat(),
        "details": result.details,
    }, indent=2))
    print(f"\nResults saved to: {results_path}")

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
