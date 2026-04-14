"""Skill: generate a Claude-written attack chain narrative for a set of findings."""
from __future__ import annotations

import json
import re
from typing import List, Optional

from pyhunter.models import ExploitChain, Finding, Severity
from pyhunter.skills import async_call_claude

_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

_SYSTEM = """\
You are a senior penetration tester writing an attack chain report for defensive security research.

You will receive a list of confirmed vulnerabilities from the same Python application, \
presented in suggested exploitation order. Write an attack chain narrative explaining \
how an attacker combines them into a complete attack — be specific about which file and \
function each step targets, and how each vulnerability enables the next.

Respond with ONLY a JSON object. No markdown fences, no prose outside the JSON:
{
  "title": "short chain title, e.g. 'AUTH-BYPASS + SSTI → RCE → Container Escape'",
  "narrative": "3-7 sentence step-by-step attack story, specific to these findings",
  "prerequisites": "one sentence: minimum access level the attacker needs to start",
  "impact": "one sentence: the final capability the attacker achieves"
}
"""


def _format_taint_path(taint_path: list[dict]) -> str:
    return " → ".join(
        f"`{s['variable']}`(L{s['line']})" for s in taint_path
    )


def _build_user_prompt(steps: List[Finding]) -> str:
    lines = ["Confirmed vulnerabilities (suggested chain order):\n"]
    for i, f in enumerate(steps, 1):
        analysis = f.analysis or "confirmed exploitable"
        entry = (
            f"{i}. [{f.severity.value}] {f.rule_id}  {f.file}:{f.line}\n"
            f"   Sink: {f.sink or '?'}  |  Source: {f.source or 'unknown'}\n"
            f"   Analysis: {analysis}\n"
        )
        if f.taint_path:
            entry += f"   Taint path: {_format_taint_path(f.taint_path)}\n"
        if f.sanitized and f.sanitizer:
            entry += f"   Sanitizer: {f.sanitizer} applied (bypass risk exists)\n"
        if f.taint_assessment:
            # Include chain-potential paragraph only (last section of the assessment)
            chain_idx = f.taint_assessment.find("### Chain Potential")
            if chain_idx != -1:
                entry += f"   Chain potential: {f.taint_assessment[chain_idx + 19:].strip()[:300]}\n"
        lines.append(entry)
    return "\n".join(lines)


def _parse_json(raw: str) -> Optional[dict]:
    text = raw.strip()
    # Strip markdown code fences if present
    m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Last resort: find first { … } block
    m = re.search(r"\{[\s\S]+\}", text)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return None


async def chain_skill(steps: List[Finding], chain_id: str) -> Optional[ExploitChain]:
    """Call Claude to narrate an exploit chain and return an ExploitChain object."""
    if not steps:
        return None

    raw  = await async_call_claude(_SYSTEM, _build_user_prompt(steps), max_tokens=600)
    data = _parse_json(raw)

    if not data:
        # Fallback: treat raw response as narrative
        data = {
            "title":         " → ".join(f.rule_id for f in steps),
            "narrative":     raw,
            "prerequisites": "See individual findings.",
            "impact":        "See individual findings.",
        }

    severity = max(
        (f.severity for f in steps),
        key=lambda s: _SEV_RANK.get(s.value, 0),
    )

    return ExploitChain(
        id=chain_id,
        title=data.get("title", " → ".join(f.rule_id for f in steps)),
        severity=severity,
        steps=steps,
        narrative=data.get("narrative", ""),
        prerequisites=data.get("prerequisites", ""),
        impact=data.get("impact", ""),
    )
