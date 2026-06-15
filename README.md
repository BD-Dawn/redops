# RedOps

AI-powered red team agent framework built on Claude. Automates offensive security workflows — recon, exploitation, post-exploitation, lateral movement, and reporting — through specialized agents coordinated by an orchestrator.

> **Note:** Research mode is still in beta and not available on this build.

## Features

- **Interactive CLI** with engagement management and opsec scoring
- **Orchestrator mode** for autonomous multi-phase operations
- **Sliver C2 integration** for implant management
- **Specialized agents:** recon, exploit, post-exploitation (Windows/Linux), lateral movement, code review, vulnerability hunting, reverse engineering, fuzzing, crash triage, PoC building, and more
- **RAG retrieval** over offensive security knowledge base
- **Secret vault** to prevent credential leakage to the API
- **Scope enforcement** and engagement logging
- **MCP server** for tool integration

## Setup

```bash
pip install -r requirements.txt
./setup.sh
```

## Usage

### Interactive mode
```bash
python main.py
```

### Orchestrator mode
```bash
python main.py --orchestrator --target <target>
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDOPS_MODEL` | `claude-opus-4-8` | Primary model |
| `REDOPS_MODEL_EXPLOIT` | `claude-sonnet-4-6` | Exploitation model |
| `REDOPS_MODEL_FAST` | `claude-haiku-4-5-20251001` | Parsing/extraction |
| `REDOPS_MAX_TURNS` | `25` | Interactive turn cap |
| `REDOPS_CHAIN_TURNS` | `12` | Chain execution budget |
| `REDOPS_TIMEOUT` | `1800` | Command timeout (seconds) |

## License

Private — not for distribution.
