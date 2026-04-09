"""Rule: build-time RCE via dangerous setup() arguments in setup.py."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_DANGEROUS_KWARGS = {"cmdclass", "ext_modules", "distclass"}


def _is_setup_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id == "setup"
    if isinstance(call.func, ast.Attribute):
        return call.func.attr == "setup"
    return False


class BuildInstallRCERule(BaseRule):
    rule_id     = "RCE-BUILD"
    description = "Build-time RCE via dangerous setup() arguments"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        if Path(filepath).name != "setup.py":
            return []
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_setup_call(node):
                continue
            for kw in node.keywords:
                if kw.arg in _DANGEROUS_KWARGS:
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=f"setup({kw.arg}=...)",
                    ))
        return findings
