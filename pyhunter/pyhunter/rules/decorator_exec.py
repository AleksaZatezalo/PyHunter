"""Rule: dangerous or dynamic expressions used as function decorators."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_DANGEROUS = {"eval", "exec", "run", "call", "apply", "getattr", "setattr"}
_ROUTES    = {"route", "get", "post", "put", "delete", "patch"}


def _decorator_name(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Call):
        if isinstance(dec.func, ast.Name):
            return dec.func.id
        if isinstance(dec.func, ast.Attribute):
            return dec.func.attr
    return None


def _is_dynamic(arg: ast.expr) -> bool:
    return not isinstance(arg, (ast.Constant, ast.JoinedStr))


class DecoratorExecutionRule(BaseRule):
    rule_id     = "EXEC-DECORATOR"
    description = "Dangerous or dynamic expression used as a decorator"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for dec in node.decorator_list:
                finding = self._check(dec, source_lines, filepath)
                if finding:
                    findings.append(finding)
        return findings

    def _check(self, dec: ast.expr, source_lines: List[str], filepath: str) -> Finding | None:
        name = _decorator_name(dec)
        if name is None:
            return None

        # Bare @eval / @exec with no arguments
        if isinstance(dec, ast.Name) and name in _DANGEROUS:
            return Finding(
                id=f"{self.rule_id}-{dec.lineno:04d}",
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                file=filepath,
                line=dec.lineno,
                snippet=self._snippet(source_lines, dec.lineno),
                sink=f"@{name}",
            )

        if isinstance(dec, ast.Call):
            # @eval(dynamic_expr) or @run(user_input)
            if name in _DANGEROUS and any(_is_dynamic(a) for a in dec.args):
                return Finding(
                    id=f"{self.rule_id}-{dec.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=dec.lineno,
                    snippet=self._snippet(source_lines, dec.lineno),
                    sink=f"@{name}(dynamic_arg)",
                )
            # @app.route(user_variable)
            if name in _ROUTES and dec.args and _is_dynamic(dec.args[0]):
                return Finding(
                    id=f"{self.rule_id}-{dec.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    file=filepath,
                    line=dec.lineno,
                    snippet=self._snippet(source_lines, dec.lineno),
                    sink=f"@{name}(dynamic_route)",
                )
        return None
