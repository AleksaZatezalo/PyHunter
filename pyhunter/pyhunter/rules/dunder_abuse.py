"""Rule: access to dangerous dunder attributes enabling sandbox escape."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_DANGEROUS = {
    "__class__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__import__",
    "__code__", "__func__",
}


class DunderAbuseRule(BaseRule):
    rule_id     = "DUNDER-ABUSE"
    description = "Access to dangerous dunder attributes"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in _DANGEROUS:
                findings.append(Finding(
                    id=f"{self.rule_id}-{node.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink=node.attr,
                ))
        return findings
