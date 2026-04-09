"""
Rule: Decorator-Based Execution (EXEC-001)

Detects execution hidden inside decorators — a pattern that static
analysis tools commonly miss because decorators are called at class/function
definition time, not invocation time.

Examples caught:
    @run(user_input)
    @app.route(user_controlled_path)
    @eval(expr)
    @getattr(obj, user_method)
"""

from __future__ import annotations
import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


# Decorator names whose arguments may execute user-controlled code
_DANGEROUS_DECORATOR_CALLS = {
    "eval", "exec", "run", "call", "apply", "getattr", "setattr",
}

# Framework decorators that accept user-controlled route strings
_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}


def _is_dynamic_arg(node: ast.expr) -> bool:
    """Return True if the expression is not a plain string/bytes/number literal."""
    return not isinstance(node, (ast.Constant, ast.JoinedStr))


class DecoratorExecutionRule(BaseRule):
    rule_id = "EXEC-DECORATOR"
    description = "Detects dangerous or user-controlled expressions used as decorator arguments."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        counter = 0

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            for decorator in node.decorator_list:
                finding = self._check_decorator(decorator, source_lines, filepath, counter)
                if finding:
                    counter += 1
                    findings.append(finding)

        return findings

    def _check_decorator(
        self,
        decorator: ast.expr,
        source_lines: List[str],
        filepath: str,
        counter: int,
    ) -> Finding | None:
        # @eval(expr) / @exec(code) / @run(user_input)
        if isinstance(decorator, ast.Call):
            func_name = self._func_name(decorator)

            if func_name in _DANGEROUS_DECORATOR_CALLS:
                if any(_is_dynamic_arg(a) for a in decorator.args):
                    return Finding(
                        id=f"PY-EXEC-{counter + 1:03d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=decorator.lineno,
                        snippet=self._snippet(source_lines, decorator.lineno),
                        sink=f"@{func_name}(dynamic_arg)",
                        extra={"decorator": func_name},
                    )

            # @app.route(user_var) — dynamic route string is suspicious
            if func_name in _ROUTE_DECORATORS:
                if decorator.args and _is_dynamic_arg(decorator.args[0]):
                    return Finding(
                        id=f"PY-EXEC-{counter + 1:03d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=decorator.lineno,
                        snippet=self._snippet(source_lines, decorator.lineno),
                        sink=f"@{func_name}(dynamic_route)",
                        extra={"decorator": func_name},
                    )

        # Bare decorator that is itself a dangerous call: @eval  (no parens)
        if isinstance(decorator, ast.Name) and decorator.id in _DANGEROUS_DECORATOR_CALLS:
            return Finding(
                id=f"PY-EXEC-{counter + 1:03d}",
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                file=filepath,
                line=decorator.lineno,
                snippet=self._snippet(source_lines, decorator.lineno),
                sink=f"@{decorator.id}",
                extra={"decorator": decorator.id},
            )

        return None

    @staticmethod
    def _func_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""
