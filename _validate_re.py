"""End-to-end validation of the 3-layer RE pipeline against ctxusbmon.sys."""
import json
import time
import agents.re_agent as ra
from agents.re_backbone import analyze as backbone_analyze

B = "/media/sf_research_bins/ctxusbmon.sys"


def status(m):
    print(f"  {m}", flush=True)


t0 = time.time()
print("== Layer 1: backbone ==", flush=True)
rep = backbone_analyze(B, on_status=status).to_dict()
print(f"  backbone done in {time.time()-t0:.0f}s: "
      f"{rep['functions_count']} funcs, {len(rep['ioctl_map'])} IOCTLs, "
      f"{len(rep['reachability_paths'])} paths", flush=True)

print("\n== Layer 2/3: agentic RE loop (Opus over rebin MCP) ==", flush=True)
t1 = time.time()
findings = ra.run_agentic_re(B, rep, on_status=status,
                             transcript_path="/tmp/re_transcript.jsonl")
print(f"\n  agentic loop done in {time.time()-t1:.0f}s", flush=True)

print("\n== GROUNDED FINDINGS ==", flush=True)
print(json.dumps(findings, indent=2), flush=True)
print(f"\nTOTAL: {len(findings)} grounded finding(s) in {time.time()-t0:.0f}s", flush=True)
