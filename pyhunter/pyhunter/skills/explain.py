"""Skill: produce a human-readable vulnerability explanation."""
from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import async_call_claude

_SYSTEM = """\
You are a security educator writing for developers who are not security specialists.

Given a vulnerable code snippet, explain in plain language:
1. What the vulnerability is
2. Why it is dangerous
3. One concrete attack scenario

Be concise (3-5 sentences total). No markdown headers. No bullet points.
"""


async def explain(finding: Finding) -> Finding:
    user = (
        f"Vulnerability: {finding.rule_id}\n"
        f"Sink: {finding.sink}\n"
        f"File: {finding.file}  Line: {finding.line}\n\n"
        f"```python\n{finding.snippet}\n```"
    )
    finding.explanation = await async_call_claude(_SYSTEM, user, max_tokens=300)
    return finding
