"""Rule: debug mode enabled in production configuration."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Top-level DEBUG = True (Django settings pattern)
_DEBUG_VAR_NAMES = {"DEBUG", "FLASK_DEBUG", "APP_DEBUG"}

# app.run(debug=True) — Flask dev server
# app.debug = True   — Flask attribute assignment


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


class DebugEnabledRule(BaseRule):
    rule_id     = "DEBUG-ENABLED"
    description = (
        "Debug mode enabled — exposes stack traces, interactive consoles, "
        "and detailed error pages in production"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # Pattern 1: DEBUG = True  (module-level or class-level)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in _DEBUG_VAR_NAMES:
                        if _is_true(node.value):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.MEDIUM,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=target.id,
                            ))

            # Pattern 2: app.debug = True
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "debug":
                        if _is_true(node.value):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.MEDIUM,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink="app.debug=True",
                            ))

            # Pattern 3: app.run(debug=True)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "run":
                    for kw in node.keywords:
                        if kw.arg == "debug" and _is_true(kw.value):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.MEDIUM,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink="app.run(debug=True)",
                            ))
                            break

        return findings
