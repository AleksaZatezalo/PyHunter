"""Skill: analyze - validate exploitability of a raw finding."""

from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import call_claude

_SYSTEM = """\
You are a senior application security engineer specialising in Python vulnerability analysis.
Given a code snippet and context, determine whether the vulnerability is actually exploitable
by an attacker. Consider:
- Is user input reaching the dangerous sink?
- Are there any effective sanitisation or validation guards?
- Is the code reachable from an untrusted entry point?

Respond ONLY with a JSON object in this exact format (no markdown, no extra text):
{
  "exploitable": true|false,
  "confidence": "high"|"medium"|"low",
  "reason": "<one sentence>"
}
"""


def analyze(finding: Finding) -> Finding:
    """
    Call Claude to validate whether *finding* is actually exploitable.
    Mutates and returns the same finding object.
    """
    user = f"""\
Rule: {finding.rule_id}
File: {finding.file}  Line: {finding.line}
Sink: {finding.sink}
Source (if known): {finding.source or "unknown"}

Code snippet:
```python
{finding.snippet}
```

Is this exploitable?
"""
    import json
    raw = call_claude(_SYSTEM, user, max_tokens=256)
    try:
        data = json.loads(raw)
        finding.exploitable = data.get("exploitable", True)
        if not finding.exploitable:
            finding.false_positive_reason = data.get("reason", "")
        finding.extra["analyze_confidence"] = data.get("confidence", "medium")
    except json.JSONDecodeError:
        # Fail open - keep as potentially exploitable
        finding.exploitable = True

    return finding
