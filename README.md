# RedOps

Red team agent framework powered by Claude. Handles recon through post-ex with specialized agents that actually run tools, not just suggest them.

> Research mode is still in beta and not available on this build.

## What it does

RedOps runs offensive security operations through an orchestrator that coordinates task-specific agents (recon, exploit, post-ex, lateral movement, RE, fuzzing, etc). It integrates with Sliver for C2, has a RAG pipeline for pulling from offensive knowledge bases, and includes a secret vault so creds don't leak to the API.

Two modes:
- **Interactive** — CLI with engagement tracking and opsec scoring
- **Orchestrator** — point it at a target and let it run

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

Everything is controlled through env vars. The defaults work fine for most setups.

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
