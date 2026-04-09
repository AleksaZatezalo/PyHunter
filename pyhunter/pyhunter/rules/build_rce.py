"""Rule: Build/Install-Time RCE (setup.py cmdclass, pyproject hooks)."""

from __future__ import annotations
import ast
from pathlib import Path
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# setup() kwargs that execute arbitrary code during installation
_DANGEROUS_KWARGS = {"cmdclass", "ext_modules", "distclass"}


class BuildInstallRCERule(BaseRule):
    rule_id = "RCE-BUILD"
    description = "Detects build/install-time code execution vectors in setup.py."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        if Path(filepath).name != "setup.py":
            return []

        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._func_name(node)
            if func_name != "setup":
                continue

            for kw in node.keywords:
                if kw.arg in _DANGEROUS_KWARGS:
                    counter += 1
                    findings.append(Finding(
                        id=f"PY-BUILD-{counter:03d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=f"setup({kw.arg}=...)",
                        extra={"kwarg": kw.arg},
                    ))

        return findings

    @staticmethod
    def _func_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""
