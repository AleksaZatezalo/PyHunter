"""Rule: HTTP response header injection via user-controlled values."""
from __future__ import annotations

import ast
from typing import List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_TAINT_SOURCES: set[tuple[str, ...]] = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "values"), ("request", "headers"),
    ("sys", "argv"), ("os", "environ"),
}
_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {"get", "get_json", "get_data"}

# Header assignment sinks
_HEADER_SET_METHODS = {"set", "add", "append"}


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _is_taint_source(node: ast.expr) -> bool:
    chain = _attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in _TAINT_SOURCES):
        return True
    if isinstance(node, ast.Subscript) and _is_taint_source(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _SOURCE_CALLS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in _SOURCE_METHODS and _is_taint_source(func.value):
            return True
    return False


def _names(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_tainted(node: ast.expr, tainted: set[str]) -> bool:
    return _is_taint_source(node) or bool(_names(node) & tainted)


def _is_headers_attr(node: ast.expr) -> bool:
    """Return True if node looks like response.headers / headers."""
    chain = _attr_chain(node)
    return bool(chain) and chain[-1] == "headers"


class HeaderInjectionRule(BaseRule):
    rule_id     = "HEADER-INJECT"
    description = "User-controlled value written into an HTTP response header"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function(node, source_lines, filepath))
        return findings

    def _check_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        tainted: set[str] = set()
        findings: List[Finding] = []
        seen: set[int] = set()

        for stmt in ast.walk(func):
            # Track taint propagation
            if isinstance(stmt, ast.Assign) and _is_tainted(stmt.value, tainted):
                for target in stmt.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            tainted.add(n.id)

            # Pattern 1: response.headers["X-Header"] = user_input   (ast.Assign)
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and _is_headers_attr(target.value)
                        and _is_tainted(stmt.value, tainted)
                        and stmt.lineno not in seen
                    ):
                        seen.add(stmt.lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{stmt.lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=stmt.lineno,
                            snippet=self._snippet(source_lines, stmt.lineno),
                            sink="response.headers",
                        ))

            # Pattern 2: response.headers.set/add/append("X", user_input)
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                func_node = node.func
                if (
                    isinstance(func_node, ast.Attribute)
                    and func_node.attr in _HEADER_SET_METHODS
                    and _is_headers_attr(func_node.value)
                    and node.args
                    and _is_tainted(node.args[-1], tainted)
                    and node.lineno not in seen
                ):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=f"headers.{func_node.attr}",
                    ))

        return findings
