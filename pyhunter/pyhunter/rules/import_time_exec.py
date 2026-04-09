"""Rule: Import-Time Code Execution (malicious logic in __init__.py / module level)."""

from __future__ import annotations
import ast
from pathlib import Path
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Calls that are suspicious at module top-level (outside any function/class)
_SUSPICIOUS = {"eval", "exec", "compile", "system", "popen", "Popen"}


class ImportTimeExecRule(BaseRule):
    rule_id = "RCE-IMPORT"
    description = "Detects code executed at import time that may run during pip install or import."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        # Only flag __init__.py and setup.py — the highest-risk import-time surfaces
        name = Path(filepath).name
        if name not in ("__init__.py", "setup.py"):
            return []

        findings: List[Finding] = []
        counter = 0

        # Walk only top-level statements (not inside functions or classes)
        for node in ast.iter_child_nodes(tree):
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                func_name = self._func_name(call)
                if func_name in _SUSPICIOUS:
                    counter += 1
                    findings.append(Finding(
                        id=f"PY-IMPORT-{counter:03d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=call.lineno,
                        snippet=self._snippet(source_lines, call.lineno),
                        sink=func_name,
                        extra={"context": "import-time"},
                    ))

        return findings

    @staticmethod
    def _func_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""
