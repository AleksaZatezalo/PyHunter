"""Rule: path traversal via dynamic open() paths and Zip Slip."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


class PathTraversalRule(BaseRule):
    rule_id     = "PATH-TRAVERSAL"
    description = "Path traversal via unsanitised file paths"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            finding = self._check_open(node, source_lines, filepath) \
                   or self._check_zip(node, source_lines, filepath)
            if finding:
                findings.append(finding)
        return findings

    def _check_open(self, call: ast.Call, source_lines: List[str], filepath: str) -> Finding | None:
        if not isinstance(call.func, ast.Name) or call.func.id != "open":
            return None
        if not call.args or isinstance(call.args[0], ast.Constant):
            return None
        return Finding(
            id=f"{self.rule_id}-{call.lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=filepath,
            line=call.lineno,
            snippet=self._snippet(source_lines, call.lineno),
            sink="open",
        )

    def _check_zip(self, call: ast.Call, source_lines: List[str], filepath: str) -> Finding | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        if call.func.attr not in {"extract", "extractall"}:
            return None
        return Finding(
            id=f"{self.rule_id}-{call.lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=filepath,
            line=call.lineno,
            snippet=self._snippet(source_lines, call.lineno),
            sink=f"ZipFile.{call.func.attr}",
        )
