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
  │  Conversation loop  │  │  human-in-the-loop decisions    │
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

### Engagement modes

Three engagement modes that control how the system handles secrets, prompts, and exit conditions:

**CTF** (`/ctf`) — Fully autonomous by default. Stripped-down prompts and auth headers tuned to avoid API policy filter noise in lab environments. Secret vault and OPSEC scoring disabled. Permission prompts skipped. Auto-continue limit is 1000 turns (vs 200 in other modes) — runs until flags or Ctrl+C. Auto-restarts with fresh context when stuck instead of returning to the operator, and auto-retries on execution errors. Flag capture detection scans agent output for 32-char hex strings near root.txt/user.txt mentions and marks the engagement solved when found.

**LE (Live Environment)** (`/mode le`) — The most restrictive mode, designed for bug bounty and real pentests. Human-in-the-loop required — not autonomous, permission prompts stay active. Secret vault tokenizes all credentials and host identifiers before they reach the API. Scope enforcement is strict. Every finding requires a reproducible PoC or gets marked unconfirmed — the agent won't claim a vuln without running proof. "No findings" is treated as a valid result so the agent won't hallucinate vulnerabilities to justify its run. Evidence collection is mandatory. Findings are written with CVSS 3.1 severity ratings and remediation guidance. No persistence, no data exfiltration, no service disruption.

**Red Team** (`/mode redteam`) — Same secret vault and scope enforcement as LE mode. Tuned for longer-running engagements with persistence across sessions. Attack planning tracks paths, blockers, and lessons learned across multiple operator sessions. OPSEC scoring reflects real-world detection risk against EDR/IDS. Exit conditions are based on engagement objectives.

### Agent system

Every agent inherits from `BaseAgent` which handles the Claude CLI backend, turn budgeting, stuck detection, tool access control, and engagement state binding.

Stuck detection tracks command patterns across turns — if an agent repeats similar commands 5+ times, gets stuck in category-specific loops (e.g. 6 turns of SQLi with no progress), or starts escalating complexity without results, it gets killed and the orchestrator pivots. The detector classifies commands into 20+ attack categories and enforces per-category turn limits.

Specialist agents:

| Agent | What it does |
|-------|-------------|
| Recon | OSINT + scanning, adapts to target type (IP/domain/webapp/internal) |
| Exploit | Initial access |
| PostEx | Generic post-exploitation |
| WindowsPostEx / LinuxPostEx | OS-specific privesc and enumeration |
| WindowsLateral / LinuxLateral | Pivoting, AD attacks, Kerberos, PTH |
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
| Summarizer | Engagement summaries |
| REAgent / REBackbone | Reverse engineering (IDA/Ghidra integration) |

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

The orchestrator maintains an attack plan across sessions — ranked paths, known blockers, priority targets, and lessons learned. Task decomposition breaks broad objectives into parallel subtasks with dependency resolution. `/auto continue` runs synthesis on current findings and executes the best chain without repeating recon. `/auto resume` picks up from the last checkpoint after an interruption.

### Multi-target blitz

`/blitz <ip1> <ip2> ...` runs parallel CTF exploitation across multiple targets simultaneously. Each target gets its own engagement state. `/blitz status` shows progress across all targets, `/blitz stop` kills running agents.

### Engagement management

Full engagement lifecycle through the CLI:

- `/target <ip>` — set the current target
- `/retarget <new_ip>` — change target IP but keep all state (for box resets)
- `/scope` — define scope (CIDRs, domains, wildcards, exclusions)
- `/roe` — set rules of engagement
- `/save` / `/load <target>` — persist and switch between engagements
- `/targets` — multi-target status table
- `/engagements` — list all saved engagements with status
- `/nuke [target]` — wipe an engagement completely
- `/new <target>` — fresh agent session, keeps engagement state
- `/autonomous` — toggle autonomous mode (no human-in-the-loop pauses)

### Credential and host tracking

- `/addcred <user> <secret> <type>` — register credentials (password, hash, ticket, key)
- `/addhost <hostname> [ip] [level]` — register compromised hosts with access level
- `/creds` — list all discovered credentials
- `/hosts` — list all compromised hosts
- `/note` — add freeform notes to engagement state

Credentials are automatically extracted from agent output. In LE/RT modes they're tokenized through the secret vault before reaching the API.

### Task ledger

Built-in task tracking for the current engagement:

- `/tasks` — view all tasks with status
- `/tasks add <objective>` — create a task
- `/tasks start|done|fail|block|skip <id>` — update task status

Tasks have dependencies, agent assignments, and phase tracking. The orchestrator uses the ledger to avoid repeating work.

### Attack planning

`/plan` generates or updates a strategic attack plan based on current findings. The plan tracks:

- Ranked attack paths with status (active/blocked/exhausted)
- Known blockers and what's needed to clear them
- Priority targets and high-value accounts
- Lessons learned from failed attempts (capped at 20)

Plans persist across sessions and are loaded automatically when resuming an engagement.

### Findings database

SQLite per-engagement findings DB with structured fields: host, port, service, type, severity, CVE, exploitability, PoC status, evidence paths.

- `/findings` — query findings with filters (host, port, severity, type)
- Findings are auto-synced from agent output via primitive extraction
- Impact gate checks proof keywords before allowing severity ratings — downgrades anything speculative

### Report generation

`/report` reviews all findings and rewrites them to submission quality. `/report fix` bulk-rewrites findings. Can also target individual finding files for rewriting. Formats output using the standard finding template (title, severity with CVSS, affected asset, description, business impact, steps to reproduce, evidence, remediation, references).

### Code review

`/review [path] [task]` runs the CodeReview agent against source code. Combines Semgrep, Bandit, and manual LLM-driven review. Can target specific files/directories or review a whole project.

### Knowledge base (RAG)

ChromaDB-backed retrieval over offensive security content. Queries get decomposed and batched, results are cached per-session, and there's a distance threshold to filter irrelevant chunks.

- `/ingest-url <url>` — fetch an article/page and add it to the KB
- `/learn` — retroactive learning from past engagements

The learner runs async after milestones, engagement completion, or stuck-kills — it extracts what worked, what failed, and why using haiku, then ingests it back into the KB with engagement-scoped metadata. This creates a closed loop where the system gets better at targets similar to ones it's seen before.

### Secret vault

In LE/RT modes, the vault tokenizes credentials before they hit the API. `register_credential(user, pass)` returns tokens like `CRED_001_USER`. The agent sees and reasons about tokens, outputs commands with tokens, and the system dereferences them locally before execution. Fernet encryption with a machine-derived key. Disabled in CTF mode.

### C2 integration

Full Sliver C2 management through `sliver-py`:

| Command | What it does |
|---------|-------------|
| `/c2 start` / `stop` | Start/stop Sliver daemon |
| `/c2 status` | Full C2 status overview |
| `/c2 listen <proto> [host] [port]` | Start listener (mTLS, HTTP, HTTPS, DNS, WireGuard) |
| `/c2 jobs` / `kill <id>` | List/kill listeners |
| `/c2 generate <url> [flags]` | Generate implant (--os, --arch, --type, --format, --name, --interval, --jitter) |
| `/c2 builds` | List generated implants |
| `/c2 sessions` / `beacons` | List active sessions/beacons |
| `/c2 exec <id> <cmd>` | Execute on session |
| `/c2 task <id> <cmd>` | Queue command on beacon |
| `/c2 screenshot <id>` | Screenshot from session |
| `/c2 ps <id>` | Process list from session |
| `/c2 upload` / `download` | File transfer |

Also exposed as an MCP server for direct Claude Code integration — tools for C2 ops, OPSEC scoring, and KB queries without going through the REPL.

### Ghidra integration

`ghidra_scripts/RedopsDecompile.java` — headless Ghidra script for batch decompilation. Used by the RE agents for binary analysis workflows.

### CVE intelligence

`/cve-sync` pulls from NVD, CISA KEV, and exploit sources. Tracks CVSS scores, affected products, wild exploitation status, and PoC references. Auto-ingests into the RAG pipeline. Used by CVEHunter for target-specific vuln scanning.

### Bounty monitor

Background polling across HackerOne, Bugcrowd, Intigriti, and YesWeHack:

- `/bounty start` / `stop` — toggle monitoring
- `/bounty scan` — immediate poll cycle
- `/bounty filter` — set min bounty, paid-only, platform filters, keyword exclusions
- `/bounty programs` — list tracked programs
- `/bounty history` — scope change detection history

### Evaluators

All evaluators are deterministic (no LLM):

- **Exit evaluator** — Scores engagement completion readiness (0-1) based on finding staleness, severity distribution, stuck-kill rate, and phase progress
- **Impact gate** — Checks findings for proof keywords before allowing severity ratings. Downgrades anything with speculation indicators ("could", "might", "potential"). Prevents agents from narrative-building on non-findings
- **OPSEC scorer** (`/opsec score <cmd>`) — Rates commands by detection risk (low → critical) based on tool signatures and EDR/IDS patterns

### Scope enforcement

Parses CIDRs, IPs, domains, wildcards, URL prefixes, and exclusions from the scope definition. Hard enforcement blocks agent dispatch outside scope. Soft enforcement extracts IPs/domains from commands and warns before execution. Uses `ipaddress` module for CIDR matching and regex for domain/URL patterns.

### CLI features

- Tab completion for all commands and subcommands
- Fast-path regex for state queries (target, creds, hosts) — answers instantly without calling the LLM
- `/fast` toggles between Opus (planning) and Sonnet (exploitation)
- `/verbose` shows real-time progress with turn counter, tool usage, and OPSEC scoring
- `/compact` trims old conversation history to free context
- `/reset` clears conversation completely

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
REDOPS_MODEL_PLANNER  — batch planning (default: claude-sonnet-4-6)
REDOPS_MAX_TURNS      — interactive turn cap (default: 25)
REDOPS_AGENT_MAX_TURNS — micro-agent dispatch limit (default: 3)
REDOPS_CHAIN_TURNS    — chain execution budget (default: 12)
REDOPS_SOFT_TURNS     — strategy reassessment trigger (default: 2)
REDOPS_TIMEOUT        — command timeout in seconds (default: 1800)
```

## License

Private. Not for distribution.
