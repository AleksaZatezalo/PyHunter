"""Skill: generate a minimal proof-of-concept payload."""
from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import async_call_claude

_SYSTEM = """\
You are a penetration tester generating proof-of-concept payloads for defensive security research.

Given the vulnerable code, produce the SMALLEST possible input that demonstrates exploitability without causing real harm.

Rules:
- Respond with ONLY the raw payload string
- No explanation, no markdown, no surrounding quotes
- Use safe commands only (e.g. `id`, `whoami`, `echo pwned`)
- If a safe payload cannot be constructed, respond with exactly: SAFE_DEMO_ONLY
"""


async def poc(finding: Finding) -> Finding:
    user = (
        f"Vulnerability: {finding.rule_id}\n"
        f"Sink: {finding.sink}\n"
        f"Source: {finding.source or 'unknown'}\n\n"
        f"```python\n{finding.snippet}\n```"
    )
    result      = await async_call_claude(_SYSTEM, user, max_tokens=150)
    finding.poc = None if result.strip() == "SAFE_DEMO_ONLY" else result
    return finding
