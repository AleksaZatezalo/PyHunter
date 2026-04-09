"""Skill: generate a complete runnable exploit demonstration script."""
from __future__ import annotations

from pyhunter.models import Finding
from pyhunter.skills import async_call_claude

_SYSTEM = """\
You are a security researcher writing proof-of-concept exploit scripts for defensive research.

Write a complete, self-contained Python script that proves the vulnerability is exploitable.

ALL of the following requirements must be satisfied — no exceptions:
1. Reproduce the vulnerable logic inline. Define every function, class, or variable needed.
2. Provide all setup, inputs, and preconditions to reach the vulnerable code. No missing pieces.
3. Execute the exploit end-to-end with a concrete, realistic payload.
4. End with: print("EXPLOITED:", <result>)
5. Use only Python stdlib — zero external packages.
6. Every variable must have a real value. No placeholders, no `...`, no `# TODO`.
7. The script must run with `python script.py` and produce visible output proving exploitation.
8. If HTTP request context is needed, simulate it with a plain dict or minimal mock object inline.

Output ONLY valid Python source code. No markdown fences. No prose.
"""


async def demo(finding: Finding) -> Finding:
    user = (
        f"Vulnerability: {finding.rule_id}\n"
        f"Sink: {finding.sink}\n"
        f"PoC payload: {finding.poc or 'N/A'}\n"
        f"Explanation: {finding.explanation or 'N/A'}\n\n"
        f"Original vulnerable snippet:\n```python\n{finding.snippet}\n```"
    )
    finding.demo = await async_call_claude(_SYSTEM, user, max_tokens=900)
    return finding
