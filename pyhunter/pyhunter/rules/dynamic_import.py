"""Rule: dynamic module imports with non-literal names."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


class DynamicImportRule(BaseRule):
    rule_id     = "INJ-IMPORT"
    description = "Dynamic import with attacker-controlled module name"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            finding = self._check_builtin(node, source_lines, filepath) \
                   or self._check_importlib(node, source_lines, filepath)
            if finding:
                findings.append(finding)
        return findings

    def _check_builtin(self, call: ast.Call, source_lines: List[str], filepath: str) -> Finding | None:
        if not isinstance(call.func, ast.Name) or call.func.id != "__import__":
            return None
        if call.args and isinstance(call.args[0], ast.Constant):
            return None
        return Finding(
            id=f"{self.rule_id}-{call.lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=filepath,
            line=call.lineno,
            snippet=self._snippet(source_lines, call.lineno),
            sink="__import__",
        )

    def _check_importlib(self, call: ast.Call, source_lines: List[str], filepath: str) -> Finding | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        if call.func.attr != "import_module":
            return None
        if call.args and isinstance(call.args[0], ast.Constant):
            return None
        return Finding(
            id=f"{self.rule_id}-{call.lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=filepath,
            line=call.lineno,
            snippet=self._snippet(source_lines, call.lineno),
            sink="importlib.import_module",
        )
