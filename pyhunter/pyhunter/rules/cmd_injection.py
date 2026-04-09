"""Rule: Command Injection (os.system / subprocess shell=True)."""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


class CommandInjectionRule(BaseRule):
    rule_id = "CMD-INJECT"
    description = "Detects shell command execution that may be vulnerable to injection."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # os.system(...)
            if self._is_attr_call(node, "os", "system"):
                counter += 1
                findings.append(self._finding(counter, filepath, node, source_lines, "os.system"))
                continue

            # subprocess.* with shell=True
            if self._is_subprocess_shell(node):
                counter += 1
                func = self._attr_name(node)
                findings.append(self._finding(counter, filepath, node, source_lines, f"subprocess.{func}"))

        return findings

    # ------------------------------------------------------------------ helpers

    def _finding(self, n: int, filepath: str, node: ast.Call, lines: List[str], sink: str) -> Finding:
        return Finding(
            id=f"PY-CMD-{n:03d}",
            rule_id=self.rule_id,
            severity=Severity.CRITICAL,
            file=filepath,
            line=node.lineno,
            snippet=self._snippet(lines, node.lineno),
            sink=sink,
        )

    @staticmethod
    def _is_attr_call(node: ast.Call, obj: str, method: str) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == obj
            and node.func.attr == method
        )

    @staticmethod
    def _attr_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return "run"

    @staticmethod
    def _is_subprocess_shell(node: ast.Call) -> bool:
        """Return True if this is a subprocess.* call with shell=True."""
        if not (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):
            return False

        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False
