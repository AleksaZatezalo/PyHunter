"""Skill: validate exploitability of a raw finding."""
from __future__ import annotations

import re

from pyhunter.models import Finding
from pyhunter.skills import async_call_claude

_SYSTEM = """\
You are a security engineer assessing whether a detected code pattern is genuinely exploitable.

Determine if an attacker can realistically reach this dangerous sink with controlled input.
Consider: is there a real path from untrusted input? Are there effective guards?

If you are uncertain, treat it as exploitable — fail open for security.

Start your response with EXACTLY one of these prefixes (replace N.N with confidence 0.0–1.0):
  EXPLOITABLE:N.N: <one-sentence reason>
  FALSE_POSITIVE:N.N: <specific reason why no attacker path exists>

Only use FALSE_POSITIVE when you are highly confident no attack path exists.
Keep your total response under 80 words.
"""

_PATTERN = re.compile(
    r"^(EXPLOITABLE|FALSE_POSITIVE)(?::(\d+(?:\.\d+)?))?[:\s]+(.*)",
    re.IGNORECASE | re.DOTALL,
)


async def analyze(finding: Finding) -> Finding:
    user = (
        f"Rule: {finding.rule_id}\n"
        f"File: {finding.file}  Line: {finding.line}\n"
        f"Sink: {finding.sink}\n"
        f"Source: {finding.source or 'unknown'}\n\n"
        f"```python\n{finding.snippet}\n```"
    )
    raw = await async_call_claude(_SYSTEM, user, max_tokens=200)

    m = _PATTERN.match(raw)
    if m:
        verdict, conf_str, text = m.group(1).upper(), m.group(2), m.group(3).strip()
        if conf_str:
            try:
                finding.confidence = float(conf_str)
            except ValueError:
                pass
        if verdict == "FALSE_POSITIVE":
            finding.exploitable           = False
            finding.false_positive_reason = text
        else:
            finding.exploitable = True
            finding.analysis    = text
    else:
        # Fallback: parse old-style prefix without confidence score.
        if raw.upper().startswith("FALSE_POSITIVE"):
            finding.exploitable           = False
            finding.false_positive_reason = raw[raw.index(":") + 1:].strip() if ":" in raw else raw
        else:
            finding.exploitable = True
            finding.analysis    = raw[raw.index(":") + 1:].strip() if ":" in raw else raw

    return finding
