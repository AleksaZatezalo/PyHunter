"""Skill: poc - generate a minimal, non-destructive exploit payload."""

from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import call_claude

_SYSTEM = """\
You are a penetration tester generating proof-of-concept payloads for defensive security research.
Given the vulnerable code context, produce the SMALLEST possible payload that demonstrates
exploitability without causing real harm (e.g. run `id`, not `rm -rf`).

Respond with ONLY the raw payload string, no explanation, no markdown, no surrounding quotes.
If a payload cannot be safely demonstrated, respond with: SAFE_DEMO_ONLY
"""


def poc(finding: Finding) -> Finding:
    """Populate finding.poc with a minimal exploit payload."""
    user = f"""\
Vulnerability: {finding.rule_id}
Sink: {finding.sink}
Source: {finding.source or "unknown"}

Vulnerable code:
```python
{finding.snippet}
```

Generate a minimal proof-of-concept payload.
"""
    result = call_claude(_SYSTEM, user, max_tokens=150)
    finding.poc = result if result != "SAFE_DEMO_ONLY" else None
    return finding
