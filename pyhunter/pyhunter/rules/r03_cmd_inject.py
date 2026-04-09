"""Rule 03 — CMD-INJECT: OS command injection.

Covers all framework request sources → os.system / os.popen /
subprocess.* (with shell=True) / popen2 / pty.spawn / paramiko exec_command.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, is_tainted_expr, collect_taint,
)

# Always dangerous regardless of arguments
_ALWAYS_DANGEROUS: set[tuple[str | None, str]] = {
    ("os",      "system"),
    ("os",      "popen"),
    ("os",      "popen2"),
    ("os",      "popen3"),
    ("os",      "popen4"),
    ("pty",     "spawn"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),
}

# Dangerous only when shell=True
_SHELL_FLAG_FUNCS: set[tuple[str, str]] = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
}


def _sink_label(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute):
        chain = attr_chain(func.value)
        mod = chain[-1] if chain else ""
        if (mod, func.attr) in _ALWAYS_DANGEROUS:
            return f"{mod}.{func.attr}"
        if (mod, func.attr) in _SHELL_FLAG_FUNCS and _has_shell_true(call):
            return f"{mod}.{func.attr}(shell=True)"
    return None


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


class CmdInjectRule(BaseRule):
    rule_id     = "CMD-INJECT"
    description = (
        "User input passed to an OS command executor — "
        "allows arbitrary shell command execution"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    def _check_fn(self, func, source_lines, filepath):
        tainted, _ = collect_taint(func)
        findings = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            label = _sink_label(node)
            if label is None:
                continue
            # Check first positional arg (the command)
            cmd_arg = node.args[0] if node.args else None
            if cmd_arg and is_tainted_expr(cmd_arg, tainted):
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
