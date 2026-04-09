"""Rule: Unsafe Deserialization (pickle, yaml.load, dill, jsonpickle)."""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


# module -> dangerous methods
_TARGETS = {
    "pickle": {"loads", "load"},
    "dill": {"loads", "load"},
    "jsonpickle": {"decode"},
    "yaml": {"load"},          # yaml.safe_load is fine
}


class UnsafeDeserializationRule(BaseRule):
    rule_id = "DESER-UNSAFE"
    description = "Detects unsafe deserialization that may lead to RCE."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if not isinstance(node.func.value, ast.Name):
                continue

            module = node.func.value.id
            method = node.func.attr

            if module in _TARGETS and method in _TARGETS[module]:
                # Skip yaml.safe_load
                if module == "yaml" and method == "safe_load":
                    continue
                counter += 1
                findings.append(Finding(
                    id=f"PY-DESER-{counter:03d}",
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink=f"{module}.{method}",
                ))

        return findings
