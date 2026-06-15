# RedOps

Red team agent framework powered by Claude. Handles recon through post-ex with specialized agents that actually run tools, not just suggest them.

> Research mode is still in beta and not available on this build.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    main.py (Interactive CLI)                  │
│   /auto, /target, /status, /c2, /report, /research, /blitz  │
└──────────────┬───────────────────┬───────────────────────────┘
               │                   │
               v                   v
  ┌────────────────────┐  ┌────────────────────┐
  │  Interactive Agent  │  │   Orchestrator     │
  │  (agent.py)         │  │  (orchestrator.py) │
  │                     │  │                    │
  │  Micro-dispatch     │  │  Phase FSM         │
  │  1-N turns          │  │  Agent dispatch    │
  │  Conversation loop  │  │  HITL decisions    │
  │  Stuck detection    │  │  Cost tracking     │
  └────────────────────┘  │  Attack planning   │
                          │  Task decomposition │
                          └────────┬───────────┘
                                   │
          ┌────────────────────────┼────────────────────┐
          v                        v                    v
  ┌──────────────┐     ┌──────────────────┐    ┌──────────────┐
  │  Specialist   │     │  KnowledgeBase   │    │  FindingsDB  │
  │  Agents (30+) │     │  (ChromaDB RAG)  │    │  (SQLite)    │
  └──────────────┘     └──────────────────┘    └──────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  Engagement State  (per-target, per-mode)                │
  │  state.json | checkpoint.json | findings.db | vault.enc  │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  Support: Secret Vault | Sliver C2 | OPSEC Scorer        │
  │  Scope Enforcer | Learner | Bounty Monitor | CVE Feed    │
  └──────────────────────────────────────────────────────────┘
```

### Execution modes

**Interactive** (`python main.py`) — REPL with tab completion for 70+ commands. You talk to the agent, it runs tools, you steer. Micro-dispatch (`/auto <agent>`) gives a specialist 3 turns to do one thing. Chain execution (`/auto chain`) hands off to the orchestrator for 12+ turn autonomous runs.

**Orchestrator** (`python main.py --orchestrator --target <target>`) — Phase-driven autonomous loop. Walks through recon → triage → exploit → post-ex → lateral → reporting. Each phase dispatches the right specialist agent, extracts attack primitives from the output, syncs findings to the DB, and decides the next move. Confidence scoring controls when it acts autonomously vs when it pauses for operator input.

**CTF** (`/ctf`) — Stripped-down prompts and auth headers tuned to avoid API policy filter noise in lab environments. Secret vault disabled. Exit conditions based on flag capture instead of engagement objectives.

### Agent system

Every agent inherits from `BaseAgent` which handles the Claude CLI backend, turn budgeting, stuck detection, tool access control, and engagement state binding.

Stuck detection tracks command patterns across turns — if an agent repeats similar commands 5+ times, gets stuck in category-specific loops (e.g. 6 turns of SQLi with no progress), or starts escalating complexity without results, it gets killed and the orchestrator pivots.

Specialist agents:

| Agent | What it does |
|-------|-------------|
| Recon | OSINT + scanning, adapts to target type (IP/domain/webapp/internal) |
| Exploit | Initial access |
| PostEx | Generic post-exploitation |
| WindowsPostEx / LinuxPostEx | OS-specific privesc and enumeration |
| WindowsLateral / LinuxLateral | Pivoting, AD attacks |
| CodeReview | Source code security analysis (Semgrep, Bandit, manual) |
| CVEHunter | Known vuln scanning + PoC research |
| Triage | Target ranking and prioritization |
| ParamAnalyzer | URL parameter attack surface mapping |
| Synthesis | Combinatorial attack path discovery (analysis only, no execution) |
| PoCBuilder | Reproducible exploit development |
| VariantHunter | Find similar bugs across codebases |
| PatchDiffer | Analyze patches for reversible 0-days |
| CrashTriager | Exploitability grading for fuzzer crashes |
| FuzzerAgent | Harness building + fuzzer execution |
| StaticAuditor | SAST + manual code review |
| NoiseFilter | Deduplication + severity grading |
| SanityChecker | Output validation, anti-hallucination |
| Report | Finding formatting + quality checks |

### Orchestrator decision loop

```
Agent finishes
  → Extract primitives (haiku, 1 turn)
  → Sync to FindingsDB
  → Exit evaluator scores readiness (deterministic, no LLM)
  → If score > 0.7: ask operator to continue or stop
  → If score < 0.7:
      → Sanity check the output
      → LLM decides next agent + task (with RAG context)
      → Confidence > 70%: auto-dispatch
      → Confidence < 70%: pause for operator approval
  → Loop
```

The orchestrator maintains an attack plan across sessions — ranked paths, known blockers, priority targets, and lessons learned. Task decomposition breaks broad objectives into parallel subtasks with dependency resolution.

### Engagement state

Each engagement is isolated under `data/engagements/<mode>/<target>/` with its own state file, findings DB, evidence directory, and encrypted credential vault. State tracks 22 fields including credentials, compromised hosts, attack surfaces, trust relationships, capabilities, service configs, defenses, and a full task ledger.

A phase tracker records time spent in each phase. Scope enforcement parses CIDRs, domains, wildcards, and exclusions — hard enforcement blocks dispatch outside scope, soft enforcement audits commands for target leakage.

### Knowledge base (RAG)

ChromaDB-backed retrieval over offensive security content. Queries get decomposed and batched, results are cached per-session, and there's a distance threshold to filter irrelevant chunks.

The learner runs async after milestones, engagement completion, or stuck-kills — it extracts what worked, what failed, and why using haiku, then ingests it back into the KB with engagement-scoped metadata. This creates a closed loop where the system gets better at targets similar to ones it's seen before.

### Secret vault

In LE/RT modes, the vault tokenizes credentials before they hit the API. `register_credential(user, pass)` returns tokens like `CRED_001_USER`. The agent sees and reasons about tokens, outputs commands with tokens, and the system dereferences them locally before execution. Fernet encryption with a machine-derived key. Disabled in CTF mode.

### C2 integration

Sliver C2 management through `sliver-py` — start/stop daemon, manage listeners (mTLS, HTTP, HTTPS, DNS, WireGuard), generate implants, interact with sessions/beacons, file transfer, screenshots. Exposed both as CLI commands and through the MCP server.

### Evaluators

All evaluators are deterministic (no LLM):

- **Exit evaluator** — Scores engagement completion readiness (0-1) based on finding staleness, severity distribution, stuck-kill rate, and phase progress
- **Impact gate** — Checks findings for proof keywords before allowing severity ratings. Downgrades anything with speculation indicators ("could", "might", "potential"). Prevents agents from narrative-building on non-findings
- **OPSEC scorer** — Rates commands by detection risk (low → critical) based on tool signatures and EDR/IDS patterns

### Bounty monitor & CVE feed

Background polling across HackerOne, Bugcrowd, Intigriti, and YesWeHack for new programs and scope changes. CVE feed syncs from NVD, CISA KEV, and exploit sources with automatic RAG ingestion.

## Setup

```bash
pip install -r requirements.txt
./setup.sh
```

## Running

```bash
# interactive
python main.py

# orchestrator
python main.py --orchestrator --target <target>
```

## Config

All env vars with sane defaults:

```
REDOPS_MODEL          — primary model (default: claude-opus-4-8)
REDOPS_MODEL_EXPLOIT  — exploitation turns (default: claude-sonnet-4-6)
REDOPS_MODEL_FAST     — parsing/extraction (default: claude-haiku-4-5-20251001)
REDOPS_MAX_TURNS      — interactive turn cap (default: 25)
REDOPS_CHAIN_TURNS    — chain execution budget (default: 12)
REDOPS_TIMEOUT        — command timeout in seconds (default: 1800)
```

## License

Private. Not for distribution.
