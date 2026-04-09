"""Rule: dangerous calls executed at import time in __init__.py / setup.py."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_TARGETS      = {"__init__.py", "setup.py"}
_DANGER_NAMES = {"eval", "exec", "compile", "system", "popen", "Popen"}


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


class ImportTimeExecRule(BaseRule):
    rule_id     = "RCE-IMPORT"
    description = "Dangerous code executed at import time"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        if Path(filepath).name not in _TARGETS:
            return []
        findings = []
        for stmt in ast.iter_child_nodes(tree):
            for call in ast.walk(stmt):
                if not isinstance(call, ast.Call):
                    continue
                name = _call_name(call)
                if name in _DANGER_NAMES:
                    findings.append(Finding(
                        id=f"{self.rule_id}-{call.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=call.lineno,
                        snippet=self._snippet(source_lines, call.lineno),
                        sink=name,
                    ))
        return findings
