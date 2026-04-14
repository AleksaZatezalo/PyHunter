"""Skill: analyse a taint flow — sanitizer bypass risk and chain potential.

Layer 3 of the taint analysis pipeline.

Input:   TaintPath  (typed Layer 2 → Layer 3 contract)
Output:  TaintAnalysis  (typed Layer 3 → Layer 4 contract)

The skill never touches AST nodes or raw dict lists — it works exclusively
with the typed contracts defined in taint/types.py.
"""
from __future__ import annotations

import re
from typing import Optional

from pyhunter.skills import async_call_claude, load_prompt
from pyhunter.taint.types import TaintAnalysis, TaintPath

_SYSTEM = load_prompt("taint")


# ── Message formatting ────────────────────────────────────────────────────────

def _format_steps(path: TaintPath) -> str:
    lines = []
    for i, step in enumerate(path.steps, 1):
        lines.append(
            f"  {i}. Line {step.location.line}"
            f" — `{step.variable}`"
            f" [{step.kind.value}]"
            f" — {step.description}"
        )
    return "\n".join(lines) or "No path recorded."


def _build_user_message(path: TaintPath) -> str:
    sanitizer_line = (
        f"Sanitizer applied: {path.sanitizer} — BYPASS RISK MUST BE ASSESSED"
        if path.sanitized and path.sanitizer
        else "No sanitizer detected — flow is unguarded"
    )
    return (
        f"Vulnerability: {path.rule_id}\n"
        f"Sink: {path.sink_label}\n"
        f"Source: {path.source_label or 'unknown'}\n"
        f"Function: {path.function_name}\n"
        f"{sanitizer_line}\n\n"
        f"Propagation path:\n{_format_steps(path)}"
    )


# ── Response parsing ──────────────────────────────────────────────────────────

def _extract_section(text: str, heading: str) -> str:
    """Extract body text under a ``### Heading`` section."""
    pattern = rf"###\s+{re.escape(heading)}\s*(.*?)(?=###|\Z)"
    m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _parse_response(response: str, path: TaintPath) -> TaintAnalysis:
    bypass_risk = (
        _extract_section(response, "Sanitizer Analysis") or None
        if path.sanitized
        else None
    )
    chain = _extract_section(response, "Chain Potential") or response
    return TaintAnalysis(
        path_id               = path.id,
        sanitizer_bypass_risk = bypass_risk,
        chain_potential       = chain,
        assessment            = response,
    )


# ── Public entry point ────────────────────────────────────────────────────────

async def analyze_taint_path(path: TaintPath) -> TaintAnalysis:
    """Run the taint-path LLM skill on a typed TaintPath.

    This is the Layer 3 entry point: takes a TaintPath, returns a TaintAnalysis.
    Neither AST nodes nor untyped dicts cross this boundary.
    """
    user = _build_user_message(path)
    response = await async_call_claude(_SYSTEM, user, max_tokens=450)
    return _parse_response(response, path)
