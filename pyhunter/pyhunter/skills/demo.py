"""Skill: demo - generate a self-contained runnable exploit demo script."""

from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import call_claude

_SYSTEM = """\
You are a security researcher writing self-contained Python demo scripts that prove exploitability.
Generate a complete, runnable Python script that:
1. Simulates the vulnerable target (inline, no external deps beyond stdlib)
2. Demonstrates the exploit
3. Prints clear output showing successful exploitation

Keep the script under 40 lines. Use only Python stdlib.
Output ONLY valid Python code with no markdown fences.
"""


def demo(finding: Finding) -> Finding:
    """Populate finding.demo with a runnable Python exploit script."""
    user = f"""\
Vulnerability: {finding.rule_id}
Sink: {finding.sink}
PoC payload: {finding.poc or "N/A"}
Explanation: {finding.explanation or "N/A"}

Original vulnerable snippet:
```python
{finding.snippet}
```

Write a self-contained demo script.
"""
    finding.demo = call_claude(_SYSTEM, user, max_tokens=600)
    return finding
