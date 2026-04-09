"""Rule: Python Object Model Abuse (__class__, __mro__, __subclasses__)."""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


_DANGEROUS_ATTRS = {"__class__", "__mro__", "__subclasses__", "__globals__", "__builtins__"}


class DunderAbuseRule(BaseRule):
    rule_id = "DUNDER-ABUSE"
    description = "Detects dangerous dunder attribute access that may enable sandbox escapes."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            # Attribute access: foo.__class__
            if isinstance(node, ast.Attribute) and node.attr in _DANGEROUS_ATTRS:
                counter += 1
                findings.append(Finding(
                    id=f"PY-DUNDER-{counter:03d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink=node.attr,
                ))

        return findings
