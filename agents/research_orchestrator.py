"""Research pipeline orchestrator — coordinates vulnerability research agents.

Pipeline: classify → audit → fuzz ↔ triage → poc → variant

Phase transitions:
  classify → audit:   always (need to understand code before fuzzing)
  audit → fuzz:       when sinks identified (harness targets known)
  fuzz → triage:      when crash threshold hit
  triage → poc:       when exploitable crashes confirmed
  triage → fuzz:      feedback loop (new seeds from triage inform next fuzz round)
  poc → variant:      when confirmed bugs have generalizable patterns
  variant → audit:    feedback loop (variants in new locations need validation)

Human-in-the-loop pauses:
  After classify — operator confirms target profile and pipeline
  After triage   — operator reviews exploitability before PoC investment

Parallel execution:
  audit + fuzz can run in parallel for source targets (audit finds sinks
  while fuzzer tests entry points)
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from research_engagement import ResearchEngagement, TargetProfile, format_bug
from engagement_logger import EngagementLogger
from agents.target_classifier import classify_target, classify_with_llm


# Phase definitions
PHASES = [
    "classify",
    "audit",
    "fuzz",
    "triage",
    "poc",
    "variant",
]


class ResearchOrchestrator:
    """Orchestrates the full vulnerability research pipeline."""

    def __init__(self, engagement: ResearchEngagement, autonomous: bool = False):
        self.engagement = engagement
        self.autonomous = autonomous
        self._log = EngagementLogger(engagement.dir, "research")
        self._on_status = None
        self._on_confirm = None  # callback for HITL pauses

    def _status(self, msg: str):
        if self._on_status:
            self._on_status(msg)

    def _confirm(self, msg: str) -> bool:
        """Ask operator for confirmation. Returns True to proceed.

        In autonomous mode, always proceeds.
        """
        if self.autonomous:
            return True
        if self._on_confirm:
            return self._on_confirm(msg)
        return True

    # --- Phase runners ---

    def _run_classify(self, target_path: str) -> bool:
        """Phase 1: Classify the target."""
        self._status("[research] Phase: CLASSIFY")
        self._log.info("phase_start", phase="classify", target=target_path)

        profile = classify_target(target_path)
        if not profile.target_type:
            self._status(f"[research] Failed to classify: {target_path}")
            self._log.error("classify_failed", target=target_path)
            return False

        # LLM enhancement for entry points
        listing = ""
        p = Path(target_path)
        if p.is_dir():
            try:
                import subprocess
                result = subprocess.run(
                    ["find", str(p), "-type", "f", "-name", "*.c", "-o",
                     "-name", "*.h", "-o", "-name", "*.py", "-o",
                     "-name", "*.php", "-o", "-name", "*.js"],
                    capture_output=True, text=True, timeout=5,
                )
                listing = result.stdout[:3000]
            except Exception:
                pass

        self._status("[research] Analyzing attack surface...")
        profile = classify_with_llm(profile, listing)

        self.engagement.profile = profile
        self.engagement.pipeline = profile.recommended_pipeline
        self.engagement.current_phase = "classify"
        if "classify" not in self.engagement.completed_phases:
            self.engagement.completed_phases.append("classify")
        self.engagement.save()

        self._status(
            f"[research] Classified: {profile.target_type} | {profile.language} | "
            f"{profile.estimated_loc} LOC | Pipeline: {' → '.join(profile.recommended_pipeline)}"
        )
        self._log.info("classify_complete", target_type=profile.target_type,
                       language=profile.language, loc=profile.estimated_loc,
                       pipeline=", ".join(profile.recommended_pipeline))

        # HITL pause: confirm classification
        if not self._confirm(
            f"Target classified as {profile.target_type} ({profile.language}). "
            f"Pipeline: {' → '.join(profile.recommended_pipeline)}. Proceed?"
        ):
            self._status("[research] Operator paused after classify")
            return False

        return True

    def _run_audit(self) -> bool:
        """Phase 2: Static analysis / source audit."""
        if "static_auditor" not in self.engagement.pipeline:
            self._status("[research] Skipping audit (not in pipeline)")
            return True

        self._status("[research] Phase: AUDIT")
        self._log.info("phase_start", phase="audit")

        from agents.static_auditor import run_audit
        findings = run_audit(self.engagement, on_status=self._on_status)

        self._status(f"[research] Audit complete: {len(findings)} validated findings, "
                     f"{len(self.engagement.sinks)} sinks, "
                     f"{len(self.engagement.bug_candidates)} bug candidates")
        self._log.info("audit_complete", findings=len(findings),
                       sinks=len(self.engagement.sinks),
                       candidates=len(self.engagement.bug_candidates))
        return True

    def _run_re(self) -> bool:
        """Phase 2b: Reverse engineering (for binary/firmware targets)."""
        if "re_agent" not in self.engagement.pipeline:
            self._status("[research] Skipping RE (not in pipeline)")
            return True

        self._status("[research] Phase: REVERSE ENGINEERING")
        self._log.info("phase_start", phase="re_analysis")

        from agents.re_agent import run_re_analysis
        summary = run_re_analysis(self.engagement, on_status=self._on_status)

        self._status(f"[research] RE complete: {summary.get('binaries_analyzed', 0)} binaries, "
                     f"{len(summary.get('findings', []))} findings")
        self._log.info("re_complete", binaries=summary.get("binaries_analyzed", 0),
                       findings=len(summary.get("findings", [])))
        return True

    def _run_fuzz(self) -> bool:
        """Phase 3: Fuzzing."""
        if "fuzzer" not in self.engagement.pipeline:
            self._status("[research] Skipping fuzzing (not in pipeline)")
            return True

        self._status("[research] Phase: FUZZ")
        self._log.info("phase_start", phase="fuzz")

        from agents.fuzzer_agent import run_fuzzing

        # Pass sinks as fuzzing targets
        sinks = self.engagement.sinks
        entry_points = self.engagement.profile.entry_points

        summary = run_fuzzing(
            self.engagement,
            entry_points=entry_points,
            sinks=sinks,
            on_status=self._on_status,
        )

        if summary.get("error"):
            self._status(f"[research] Fuzzing error: {summary['error']}")
            self._log.error("fuzz_error", error=summary["error"])
            return False

        crashes = summary.get("total_crashes", 0)
        self._status(f"[research] Fuzzing complete: {crashes} crashes in "
                     f"{summary.get('duration', 0):.0f}s")
        self._log.info("fuzz_complete", crashes=crashes,
                       duration=f"{summary.get('duration', 0):.0f}s")
        return crashes > 0  # proceed to triage only if crashes found

    def _run_triage(self) -> bool:
        """Phase 4: Crash triage."""
        if "crash_triager" not in self.engagement.pipeline:
            self._status("[research] Skipping triage (not in pipeline)")
            return True

        untriaged = [c for c in self.engagement.crash_corpus if not c.get("triaged")]
        if not untriaged:
            self._status("[research] No crashes to triage")
            return True

        self._status(f"[research] Phase: TRIAGE ({len(untriaged)} crashes)")
        self._log.info("phase_start", phase="triage", crashes=len(untriaged))

        from agents.crash_triager import triage_crashes
        summary = triage_crashes(self.engagement, on_status=self._on_status)

        self._status(f"[research] Triage complete: {json.dumps(summary.get('by_exploitability', {}))}")
        self._log.info("triage_complete", **summary.get("by_exploitability", {}))

        # HITL pause: review before PoC investment
        weaponizable = summary.get("by_exploitability", {}).get("weaponizable", 0)
        promising = summary.get("by_exploitability", {}).get("promising", 0)
        if weaponizable + promising > 0:
            if not self._confirm(
                f"Triage found {weaponizable} weaponizable + {promising} promising crashes. "
                f"Proceed to PoC development?"
            ):
                self._status("[research] Operator paused after triage")
                return False

        return True

    def _run_poc(self) -> bool:
        """Phase 5: PoC development."""
        if "poc_builder" not in self.engagement.pipeline:
            self._status("[research] Skipping PoC (not in pipeline)")
            return True

        # Need confirmed bugs or high-confidence candidates
        targets = self.engagement.confirmed_bugs + [
            b for b in self.engagement.bug_candidates
            if b.get("exploitability") in ("weaponizable", "promising")
            and b["status"] == "candidate"
        ]
        if not targets:
            self._status("[research] No bugs ready for PoC development")
            return True

        self._status(f"[research] Phase: POC ({len(targets)} bugs)")
        self._log.info("phase_start", phase="poc", bugs=len(targets))

        from agents.poc_builder import build_pocs
        summary = build_pocs(self.engagement, on_status=self._on_status)

        self._status(f"[research] PoC complete: {summary.get('built', 0)} built, "
                     f"maturity: {json.dumps(summary.get('by_maturity', {}))}")
        self._log.info("poc_complete", built=summary.get("built", 0),
                       advisories=summary.get("advisories", 0),
                       **summary.get("by_maturity", {}))
        return True

    def _run_variant(self) -> bool:
        """Phase 6: Variant hunting."""
        if "variant_hunter" not in self.engagement.pipeline:
            self._status("[research] Skipping variant hunt (not in pipeline)")
            return True

        if not self.engagement.confirmed_bugs:
            self._status("[research] No confirmed bugs — skipping variant hunt")
            return True

        self._status(f"[research] Phase: VARIANT HUNT ({len(self.engagement.confirmed_bugs)} bugs)")
        self._log.info("phase_start", phase="variant", bugs=len(self.engagement.confirmed_bugs))

        from agents.variant_hunter import hunt_variants
        summary = hunt_variants(self.engagement, on_status=self._on_status)

        self._status(f"[research] Variant hunt complete: {summary.get('variants_found', 0)} variants")
        self._log.info("variant_complete", variants=summary.get("variants_found", 0))
        return True

    def _run_syzkaller(self, kernel_src: str, subsystems: list[str] = None) -> bool:
        """Phase 3b: Kernel fuzzing with syzkaller."""
        self._status("[research] Phase: SYZKALLER (kernel fuzzing)")
        self._log.info("phase_start", phase="syzkaller",
                       subsystems=", ".join(subsystems or []))

        from agents.syzkaller_agent import run_syzkaller
        summary = run_syzkaller(
            self.engagement, kernel_src,
            subsystems=subsystems, on_status=self._on_status,
        )

        if summary.get("error"):
            self._status(f"[research] Syzkaller error: {summary['error']}")
            self._log.error("syzkaller_error", error=summary["error"])
            return False

        crashes = summary.get("crashes", 0)
        self._status(f"[research] Syzkaller complete: {crashes} crashes, "
                     f"{summary.get('reproducers', 0)} reproducers")
        self._log.info("syzkaller_complete", crashes=crashes,
                       reproducers=summary.get("reproducers", 0),
                       duration=f"{summary.get('duration', 0):.0f}s")
        return crashes > 0

    def _run_patch_diff(self, kernel_src: str, days: int = 7,
                        target_version: str = "") -> bool:
        """Phase 0: Patch diffing (runs before audit for kernel targets)."""
        self._status(f"[research] Phase: PATCH DIFF (last {days} days)")
        self._log.info("phase_start", phase="patch_diff", days=days)

        from agents.patch_differ import diff_patches
        summary = diff_patches(
            kernel_src, self.engagement,
            days=days, target_version=target_version,
            on_status=self._on_status,
        )

        self._status(f"[research] Patch diff complete: {summary.get('bugs_found', 0)} security patches, "
                     f"{len(summary.get('unpatched_branches', {}))} with unpatched branches")
        self._log.info("patch_diff_complete",
                       analyzed=summary.get("patches_analyzed", 0),
                       security=summary.get("bugs_found", 0))
        return True

    def _is_kernel_target(self) -> bool:
        """Check if the target is a Linux kernel source tree."""
        target = Path(self.engagement.target_path)
        indicators = ["Kconfig", "Makefile", "kernel", "drivers", "fs", "net", "mm"]
        if target.is_dir():
            matches = sum(1 for i in indicators if (target / i).exists())
            return matches >= 4
        return False

    # --- Feedback loops ---

    def _detect_kernel_subsystems(self) -> list[str]:
        """Detect which kernel subsystems to target based on audit findings.

        Maps sink locations to subsystem names for syzkaller targeting.
        """
        subsystems = set()
        subsystem_map = {
            "net/": "network",
            "fs/": "filesystem",
            "io_uring/": "io_uring",
            "mm/": "memory",
            "ipc/": "ipc",
            "kernel/bpf/": "bpf",
            "net/netfilter/": "netfilter",
            "net/vmw_vsock/": "vsock",
            "drivers/": "filesystem",  # broad, but driver bugs are common
        }

        for sink in self.engagement.sinks:
            file_path = sink.get("file", "")
            for prefix, subsystem in subsystem_map.items():
                if prefix in file_path:
                    subsystems.add(subsystem)

        # Default: fuzz the most productive subsystems if no sinks found
        if not subsystems:
            subsystems = {"io_uring", "memory", "filesystem", "network"}

        return sorted(subsystems)

    def _should_refuzz(self) -> bool:
        """Check if we should run another fuzz round based on triage results.

        Re-fuzz if: triage found weaponizable bugs AND we haven't hit max rounds.
        """
        fuzz_rounds = self.engagement.completed_phases.count("fuzz")
        if fuzz_rounds >= 3:
            return False  # max 3 fuzz rounds

        weaponizable = len([c for c in self.engagement.crash_corpus
                            if c.get("exploitability") == "weaponizable"])
        # If we found weaponizable crashes, there might be more — fuzz again
        return weaponizable > 0 and len(self.engagement.crash_corpus) < 20

    def _should_re_audit(self) -> bool:
        """Check if variant findings warrant re-auditing new locations."""
        new_variants = [v for v in self.engagement.variants
                        if v.get("status") == "candidate"
                        and v.get("confidence") == "high"]
        return len(new_variants) >= 3  # re-audit if 3+ high-confidence variants

    # --- Main pipeline ---

    def run(self, target_path: str = "", on_status=None, on_confirm=None) -> dict:
        """Run the full research pipeline.

        Resumes from the last completed phase if the engagement has state.

        Args:
            target_path: Path to target (required for new engagements)
            on_status: Callback for status messages
            on_confirm: Callback for HITL confirmations (returns bool)

        Returns summary dict.
        """
        self._on_status = on_status
        self._on_confirm = on_confirm
        start_time = time.monotonic()

        summary = {
            "phases_completed": [],
            "bugs_found": 0,
            "crashes": 0,
            "pocs": 0,
            "variants": 0,
        }

        self._log.info("pipeline_start", target=self.engagement.target_name,
                       autonomous=self.autonomous)
        self._status(f"[research] Starting pipeline for {self.engagement.target_name}")

        # Determine which phases to run
        completed = set(self.engagement.completed_phases)
        path = target_path or self.engagement.target_path

        is_kernel = self._is_kernel_target()

        try:
            # Phase 1: Classify (if not done)
            if "classify" not in completed:
                if not path:
                    self._status("[research] No target path — cannot classify")
                    return summary
                if not self._run_classify(path):
                    return summary
                summary["phases_completed"].append("classify")

                # Auto-detect kernel and adjust pipeline
                if is_kernel:
                    self._status("[research] Kernel source detected — adding syzkaller + patch_differ")
                    pipeline = self.engagement.pipeline
                    if "syzkaller" not in pipeline:
                        # Insert syzkaller after fuzzer or add if no fuzzer
                        if "fuzzer" in pipeline:
                            idx = pipeline.index("fuzzer") + 1
                            pipeline.insert(idx, "syzkaller")
                        else:
                            pipeline.append("syzkaller")
                    if "patch_differ" not in pipeline:
                        # Patch differ runs early, before audit
                        pipeline.insert(0, "patch_differ")
                    self.engagement.pipeline = pipeline
                    self.engagement.save()

            # Phase 0 (kernel only): Patch diffing
            if is_kernel and "patch_diff" not in completed and "patch_differ" in self.engagement.pipeline:
                self._run_patch_diff(path, days=14)
                summary["phases_completed"].append("patch_diff")

            # Phase 2: Audit / RE (based on pipeline)
            if "audit" not in completed and "static_auditor" in self.engagement.pipeline:
                if self._run_audit():
                    summary["phases_completed"].append("audit")

            if "re_analysis" not in completed and "re_agent" in self.engagement.pipeline:
                if self._run_re():
                    summary["phases_completed"].append("re_analysis")

            # Phase 3: Fuzz (AFL++ for userspace, syzkaller for kernel)
            fuzz_round = 0
            while True:
                fuzz_key = "fuzz" if fuzz_round == 0 else f"fuzz_round_{fuzz_round}"
                if fuzz_key not in completed and "fuzzer" in self.engagement.pipeline:
                    if self._run_fuzz():
                        summary["phases_completed"].append(fuzz_key)

                        # Phase 4: Triage (after each fuzz round)
                        triage_key = "triage" if fuzz_round == 0 else f"triage_round_{fuzz_round}"
                        if "crash_triager" in self.engagement.pipeline:
                            if self._run_triage():
                                summary["phases_completed"].append(triage_key)

                        # Feedback: should we fuzz again?
                        if self._should_refuzz():
                            fuzz_round += 1
                            self._status(f"[research] Feedback loop: starting fuzz round {fuzz_round + 1}")
                            self._log.info("feedback_refuzz", round=fuzz_round + 1)
                            continue
                break

            # Phase 3b (kernel only): Syzkaller
            if is_kernel and "syzkaller" not in completed and "syzkaller" in self.engagement.pipeline:
                # Determine subsystems to target from audit findings
                subsystems = self._detect_kernel_subsystems()
                if self._run_syzkaller(path, subsystems):
                    summary["phases_completed"].append("syzkaller")
                    # Triage syzkaller crashes too
                    if "crash_triager" in self.engagement.pipeline:
                        self._run_triage()

            # Phase 5: PoC
            if "poc" not in completed and "poc_builder" in self.engagement.pipeline:
                if self._run_poc():
                    summary["phases_completed"].append("poc")

            # Phase 6: Variant hunt
            if "variant" not in completed and "variant_hunter" in self.engagement.pipeline:
                if self._run_variant():
                    summary["phases_completed"].append("variant")

                    # Feedback: re-audit if many variants found
                    if self._should_re_audit():
                        self._status("[research] Feedback loop: re-auditing based on variant findings")
                        self._log.info("feedback_re_audit")
                        self._run_audit()

        except KeyboardInterrupt:
            self._status("[research] Pipeline interrupted by operator (Ctrl+C)")
            self._log.warn("pipeline_interrupted", phase=self.engagement.current_phase)
            self.engagement.save()
            raise
        except Exception as e:
            self._status(f"[research] Pipeline error: {e}")
            self._log.crash("research_orchestrator", str(e))
            self.engagement.save()

        # Final summary
        elapsed = time.monotonic() - start_time
        self.engagement.total_time_secs += elapsed
        self.engagement.save()

        summary["bugs_found"] = len(self.engagement.confirmed_bugs)
        summary["crashes"] = len(self.engagement.crash_corpus)
        summary["pocs"] = len(self.engagement.pocs)
        summary["variants"] = len(self.engagement.variants)
        summary["elapsed"] = elapsed
        summary["cost"] = self.engagement.total_cost

        self._log.info("pipeline_complete",
                       phases=", ".join(summary["phases_completed"]),
                       bugs=summary["bugs_found"],
                       crashes=summary["crashes"],
                       pocs=summary["pocs"],
                       variants=summary["variants"],
                       elapsed=f"{elapsed:.0f}s")

        self._status(
            f"\n[research] Pipeline complete: "
            f"{summary['bugs_found']} confirmed bugs, "
            f"{summary['crashes']} crashes, "
            f"{summary['pocs']} PoCs, "
            f"{summary['variants']} variants "
            f"({elapsed:.0f}s, ${summary['cost']:.2f})"
        )

        return summary

    def run_phase(self, phase: str, on_status=None) -> bool:
        """Run a single phase manually.

        Useful for re-running a specific phase or debugging.
        """
        self._on_status = on_status
        self._on_confirm = lambda msg: True  # auto-confirm for single phase

        self._log.info("phase_manual", phase=phase)

        target = self.engagement.target_path
        runners = {
            "classify": lambda: self._run_classify(target),
            "audit": self._run_audit,
            "re": self._run_re,
            "re_analysis": self._run_re,
            "fuzz": self._run_fuzz,
            "triage": self._run_triage,
            "poc": self._run_poc,
            "variant": self._run_variant,
            "syzkaller": lambda: self._run_syzkaller(target, self._detect_kernel_subsystems()),
            "patch_diff": lambda: self._run_patch_diff(target),
        }

        runner = runners.get(phase)
        if not runner:
            self._status(f"[research] Unknown phase: {phase}. "
                         f"Available: {', '.join(runners.keys())}")
            return False

        return runner()
