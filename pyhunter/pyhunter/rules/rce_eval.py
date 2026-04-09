"""Rule: dynamic code execution via eval / exec / compile."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_SINKS = {"eval", "exec", "compile"}


class DynamicCodeExecutionRule(BaseRule):
    rule_id     = "RCE-EVAL"
    description = "Dynamic code execution via eval/exec/compile"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in _SINKS:
                continue
            findings.append(Finding(
                id=f"{self.rule_id}-{node.lineno:04d}",
                rule_id=self.rule_id,
                severity=Severity.CRITICAL,
                file=filepath,
                line=node.lineno,
                snippet=self._snippet(source_lines, node.lineno),
                sink=node.func.id,
            ))
        return findings
