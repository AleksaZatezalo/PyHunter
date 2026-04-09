"""Rule: SQL injection via string-formatted queries."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_EXECUTE_METHODS = {"execute", "executemany", "executescript"}


def _contains_name(node: ast.expr) -> bool:
    return any(isinstance(n, ast.Name) for n in ast.walk(node))


def _is_dynamic_query(node: ast.expr) -> bool:
    """Return True if the node is a dynamically constructed string (not a safe literal)."""
    if isinstance(node, ast.JoinedStr):          # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _contains_name(node)              # concat/% with a variable
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":           # "...".format(...)
            return True
    return False


class SQLInjectionRule(BaseRule):
    rule_id     = "SQL-INJECT"
    description = "SQL query built with dynamic string content instead of parameterised values"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in _EXECUTE_METHODS:
                continue
            if not node.args:
                continue
            if _is_dynamic_query(node.args[0]):
                findings.append(Finding(
                    id=f"{self.rule_id}-{node.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink=func.attr,
                ))
        return findings
