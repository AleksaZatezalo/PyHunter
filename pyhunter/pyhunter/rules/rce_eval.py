"""Rule: Dynamic Code Execution (eval / exec / compile)."""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


_DANGEROUS_CALLS = {"eval", "exec", "compile"}


class DynamicCodeExecutionRule(BaseRule):
    rule_id = "RCE-EVAL"
    description = "Detects eval/exec/compile calls that may execute user-controlled input."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._call_name(node)
            if func_name not in _DANGEROUS_CALLS:
                continue

            counter += 1
            findings.append(Finding(
                id=f"PY-RCE-{counter:03d}",
                rule_id=self.rule_id,
                severity=Severity.CRITICAL,
                file=filepath,
                line=node.lineno,
                snippet=self._snippet(source_lines, node.lineno),
                sink=func_name,
            ))

        return findings

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""
