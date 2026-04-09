"""Skill: explain - produce a human-readable vulnerability explanation."""

from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import call_claude

_SYSTEM = """\
You are a security educator writing for developers who are not security specialists.
Given a vulnerable Python code snippet, explain:
1. What the vulnerability is
2. Why it is dangerous
3. A concrete attack scenario (one sentence)

Be concise (3-5 sentences total). No markdown headers or bullet points.
"""


def explain(finding: Finding) -> Finding:
    """Populate finding.explanation via Claude."""
    user = f"""\
Vulnerability type: {finding.rule_id}
Sink: {finding.sink}
File: {finding.file}  Line: {finding.line}

Code:
```python
{finding.snippet}
```
"""
    finding.explanation = call_claude(_SYSTEM, user, max_tokens=300)
    return finding
