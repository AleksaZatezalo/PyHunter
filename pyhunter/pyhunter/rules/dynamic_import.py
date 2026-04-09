"""Rule: Dynamic Imports & Module Injection (__import__, importlib with user input)."""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


class DynamicImportRule(BaseRule):
    rule_id = "INJ-IMPORT"
    description = "Detects dynamic imports with non-literal module names that may allow injection."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # __import__("user_value")
            if self._is_builtin_import(node):
                counter += 1
                findings.append(Finding(
                    id=f"PY-IMPORT-DYN-{counter:03d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink="__import__",
                ))

            # importlib.import_module(user_value)
            if self._is_importlib(node):
                counter += 1
                findings.append(Finding(
                    id=f"PY-IMPORT-DYN-{counter:03d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink="importlib.import_module",
                ))

        return findings

    @staticmethod
    def _is_builtin_import(node: ast.Call) -> bool:
        if not (isinstance(node.func, ast.Name) and node.func.id == "__import__"):
            return False
        # Only flag when arg is not a plain string literal
        return bool(node.args) and not isinstance(node.args[0], ast.Constant)

    @staticmethod
    def _is_importlib(node: ast.Call) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
            and node.func.attr == "import_module"
            and bool(node.args)
            and not isinstance(node.args[0], ast.Constant)
        )
