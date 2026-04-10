"""Rule: CMD-INJECT — OS command injection via user-controlled input.

Covers all supported web-framework request sources flowing into os.system,
os.popen, subprocess.* (with shell=True), pty.spawn, and the legacy
commands module. Requires the command argument to be tainted from a
framework request source — bare os.system("ls") is not flagged.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain, is_tainted_expr, collect_taint

# These are dangerous regardless of shell= flag
_ALWAYS_DANGEROUS: set[tuple[str, str]] = {
    ("os",       "system"),
    ("os",       "popen"),
    ("os",       "popen2"),
    ("os",       "popen3"),
    ("os",       "popen4"),
    ("pty",      "spawn"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),
}

# These are only dangerous when called with shell=True
_SHELL_FLAG_FUNCS: set[tuple[str, str]] = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
}


def _has_shell_true(call: ast.Call) -> bool:
    return any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in call.keywords
    )


def _sink_label(call: ast.Call) -> str | None:
    """Return a human-readable sink label, or None if not a command sink."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    chain = attr_chain(func.value)
    mod   = chain[-1] if chain else ""
    if (mod, func.attr) in _ALWAYS_DANGEROUS:
        return f"{mod}.{func.attr}"
    if (mod, func.attr) in _SHELL_FLAG_FUNCS and _has_shell_true(call):
        return f"{mod}.{func.attr}(shell=True)"
    return None


class CommandInjectionRule(BaseRule):
    """Template Method: implements BaseRule.check() for OS command sinks."""

    rule_id     = "CMD-INJECT"
    description = (
        "User input passed to an OS command executor — "
        "allows arbitrary shell command execution"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    def _check_fn(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        tainted, _ = collect_taint(func)
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            label   = _sink_label(node)
            cmd_arg = node.args[0] if node.args else None
            if label and cmd_arg and is_tainted_expr(cmd_arg, tainted):
                seen.add(node.lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{node.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink=label,
                ))

        return findings
