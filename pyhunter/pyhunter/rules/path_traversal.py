"""Rule: Path Traversal & File Abuse (user-controlled paths, Zip Slip)."""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# open() modes that write/truncate — reads are lower risk
_WRITE_MODES = {"w", "wb", "a", "ab", "x", "xb", "w+", "r+"}


class PathTraversalRule(BaseRule):
    rule_id = "PATH-TRAVERSAL"
    description = "Detects user-controlled file paths that may enable path traversal."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # open() with a non-literal first argument
            if self._is_open_with_dynamic_path(node):
                counter += 1
                findings.append(Finding(
                    id=f"PY-PATH-{counter:03d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink="open",
                ))

            # ZipFile.extract / extractall with no path filter — Zip Slip
            if self._is_zip_extract(node):
                counter += 1
                findings.append(Finding(
                    id=f"PY-PATH-{counter:03d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink="ZipFile.extractall",
                ))

        return findings

    @staticmethod
    def _is_open_with_dynamic_path(node: ast.Call) -> bool:
        if not (isinstance(node.func, ast.Name) and node.func.id == "open"):
            return False
        if not node.args:
            return False
        # Flag when the first argument is not a string literal
        return not isinstance(node.args[0], ast.Constant)

    @staticmethod
    def _is_zip_extract(node: ast.Call) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("extract", "extractall")
        )
