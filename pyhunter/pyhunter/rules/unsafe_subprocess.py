"""Rule: unsafe subprocess calls where the command argument is dynamic."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_SUBPROCESS_CALLS = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("subprocess", "Popen"),
}


def _attr_pair(call: ast.Call) -> tuple[str, str] | None:
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _command_is_dynamic(call: ast.Call) -> bool:
    """Return True if the command argument (first positional) is not a plain string literal."""
    if not call.args:
        return False
    arg = call.args[0]
    # Static string literal — safe
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return False
    # List where every element is a string literal — safe
    if isinstance(arg, ast.List):
        return not all(
            isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            for elt in arg.elts
        )
    # Anything else (variable, f-string, join, etc.) — dynamic
    return True


class UnsafeSubprocessRule(BaseRule):
    rule_id     = "UNSAFE-SUBPROCESS"
    description = "Subprocess call with a dynamically constructed command"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            pair = _attr_pair(node)
            if pair not in _SUBPROCESS_CALLS:
                continue
            if not _command_is_dynamic(node):
                continue
            findings.append(Finding(
                id=f"{self.rule_id}-{node.lineno:04d}",
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                file=filepath,
                line=node.lineno,
                snippet=self._snippet(source_lines, node.lineno),
                sink=f"{pair[0]}.{pair[1]}",
            ))
        return findings
