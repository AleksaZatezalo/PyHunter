"""Skill: analyse whether the vulnerability is standalone or requires chaining."""
from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import async_call_claude

_SYSTEM = """\
You are a senior security researcher writing an exploitation context analysis.

Given the vulnerability details and demo script, produce a concise markdown analysis with exactly these two sections:

### Standalone or Chained?
State clearly whether this can be exploited on its own, or requires chaining with another weakness.

### Exploitation Prerequisites
List the specific conditions an attacker needs:
- Network/access level required (unauthenticated remote, local, authenticated, etc.)
- Whether the vulnerable component must be enabled or configured a certain way
- Which input vectors or entry points reach the sink
- Any other constraints

Keep the total response under 200 words. Use only the two headings above and bullet points.
"""


async def context(finding: Finding) -> Finding:
    user = (
        f"Vulnerability: {finding.rule_id}\n"
        f"Sink: {finding.sink}\n"
        f"Source: {finding.source or 'unknown'}\n"
        f"Analysis: {finding.analysis or 'N/A'}\n\n"
        f"Demo script:\n```python\n{finding.demo or 'N/A'}\n```"
    )
    finding.context = await async_call_claude(_SYSTEM, user, max_tokens=350)
    return finding
