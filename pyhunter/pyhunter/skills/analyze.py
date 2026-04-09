"""Skill: validate exploitability of a raw finding."""
from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import async_call_claude

_SYSTEM = """\
You are a security engineer assessing whether a detected code pattern is genuinely exploitable.

Determine if an attacker can realistically reach this dangerous sink with controlled input.
Consider: is there a real path from untrusted input? Are there effective guards?

If you are uncertain, treat it as exploitable — fail open for security.

Start your response with EXACTLY one of these prefixes:
  EXPLOITABLE: <one-sentence reason>
  FALSE_POSITIVE: <specific reason why no attacker path exists>

Only use FALSE_POSITIVE when you are highly confident no attack path exists.
Keep your total response under 80 words.
"""


async def analyze(finding: Finding) -> Finding:
    user = (
        f"Rule: {finding.rule_id}\n"
        f"File: {finding.file}  Line: {finding.line}\n"
        f"Sink: {finding.sink}\n"
        f"Source: {finding.source or 'unknown'}\n\n"
        f"```python\n{finding.snippet}\n```"
    )
    raw = await async_call_claude(_SYSTEM, user, max_tokens=200)
    if raw.upper().startswith("FALSE_POSITIVE"):
        finding.exploitable           = False
        finding.false_positive_reason = raw[raw.index(":") + 1:].strip() if ":" in raw else raw
    else:
        finding.exploitable = True
        finding.analysis    = raw[raw.index(":") + 1:].strip() if ":" in raw else raw
    return finding
