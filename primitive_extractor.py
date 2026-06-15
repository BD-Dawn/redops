"""Attack Primitive Extractor — auto-extracts findings from agent output.

Parses agent responses to identify and save:
- Attack surfaces (services, endpoints, writable paths)
- Trust relationships (what trusts what)
- Capabilities (what each owned account can do)
- Service configurations (WSUS, ADCS, DNS, GPO)

Runs via haiku (fast/cheap) after each agent dispatch. Extracted primitives
are saved to engagement state for the synthesis agent to use.
"""

import json
import subprocess
from config import MODEL_FAST


def extract_primitives(agent_output: str, engagement_state) -> dict:
    """Extract attack primitives from agent output and save to engagement state.

    Args:
        agent_output: The agent's response text
        engagement_state: Engagement to update

    Returns:
        Dict with counts of extracted items per category
    """
    if not agent_output or len(agent_output) < 100:
        return {"extracted": 0}

    prompt = f"""Extract attack primitives from this penetration test output. Return ONLY valid JSON.

## Output to analyze
{agent_output[:4000]}

## Existing known data (do NOT duplicate these)
Credentials: {[c['username'] for c in engagement_state.credentials[:10]]}
Hosts: {engagement_state.discovered_hosts[:10]}

Extract NEW findings only. Return this JSON structure (empty arrays if nothing new found):
{{
    "attack_surfaces": [
        {{"type": "service|endpoint|writable_path|share", "target": "hostname/IP", "detail": "what it is", "access": "who can access it"}}
    ],
    "trust_relationships": [
        {{"source": "what trusts", "target": "what is trusted", "type": "wsus|dns|adcs|delegation|gpo", "detail": "how the trust works"}}
    ],
    "capabilities": [
        {{"account": "who", "capability": "what they can do", "target": "on what object", "detail": "specifics"}}
    ],
    "service_configs": [
        {{"service": "WSUS|ADCS|DNS|GPO|ScheduledTask", "key": "config key", "value": "config value", "implication": "why it matters"}}
    ],
    "notes": [
        "one-line factual findings worth remembering"
    ]
}}

Rules:
- Only extract CONCRETE findings (hostnames, paths, permissions, configs)
- Do NOT extract speculation or planned actions
- Do NOT duplicate data already in the existing known data
- Include the FULL detail (exact paths, exact hostnames, exact permissions)
- For trust relationships: specify WHAT trusts WHAT and HOW"""

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text", "--max-turns", "1",
             "--model", MODEL_FAST],
            input=prompt, capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"extracted": 0}

        text = result.stdout.strip()
        # Strip markdown fences
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]

        data = json.loads(text.strip())
        counts = {"extracted": 0}

        # Merge new findings into engagement state (deduplicate by detail)
        for category in ["attack_surfaces", "trust_relationships", "capabilities", "service_configs"]:
            new_items = data.get(category, [])
            if not new_items:
                continue

            existing = getattr(engagement_state, category, [])
            existing_details = {
                json.dumps(item, sort_keys=True) for item in existing
            }

            for item in new_items:
                item_key = json.dumps(item, sort_keys=True)
                if item_key not in existing_details:
                    existing.append(item)
                    existing_details.add(item_key)
                    counts["extracted"] += 1
                    counts[category] = counts.get(category, 0) + 1

            setattr(engagement_state, category, existing)

        # Add new notes — filter out state-changing keywords that could
        # falsely trigger engagement lifecycle transitions (e.g. is_solved).
        _BANNED_NOTE_PATTERNS = ("SOLVED", "OBJECTIVE COMPLETE", "ENGAGEMENT COMPLETE",
                                 "FLAGS CAPTURED", "CTF COMPLETE")
        new_notes = data.get("notes", [])
        for note in new_notes:
            if not note or note in engagement_state.notes:
                continue
            if any(banned in note.upper() for banned in _BANNED_NOTE_PATTERNS):
                continue  # Never let extracted notes trigger solved state
            engagement_state.notes.append(note)
            counts["extracted"] += 1

        # Persist if anything was extracted
        if counts["extracted"] > 0:
            try:
                engagement_state.save()
            except Exception:
                pass

        return counts

    except (json.JSONDecodeError, Exception):
        return {"extracted": 0}


def extract_primitives_async(agent_output: str, engagement_state) -> None:
    """Non-blocking version — runs in the learner thread pool."""
    try:
        from learner import _run_async
        _run_async(extract_primitives, agent_output, engagement_state)
    except Exception:
        pass
