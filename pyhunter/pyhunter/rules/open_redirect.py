"""Rule: open redirect — user-controlled URL passed to redirect functions."""
from __future__ import annotations

import ast
from typing import List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_TAINT_SOURCES: set[tuple[str, ...]] = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "values"), ("sys", "argv"),
    ("request", "GET"), ("request", "POST"),   # Django
    ("os", "environ"),
}
_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {"get", "get_json", "get_data"}

# Redirect sinks
_REDIRECT_FUNCS   = {"redirect", "Redirect"}
_REDIRECT_CLASSES = {"HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}


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


def _is_redirect_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _REDIRECT_FUNCS | _REDIRECT_CLASSES
    if isinstance(func, ast.Attribute):
        return func.attr in _REDIRECT_FUNCS | _REDIRECT_CLASSES
    return False


class OpenRedirectRule(BaseRule):
    rule_id     = "OPEN-REDIRECT"
    description = "User-controlled URL passed to a redirect function — open redirect vulnerability"

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
        tainted: dict[str, str] = {}
        findings: List[Finding] = []
        seen: set[int] = set()

        for stmt in ast.walk(func):
            # Taint propagation
            if isinstance(stmt, ast.Assign):
                if _is_taint_source(stmt.value) or bool(_names(stmt.value) & tainted.keys()):
                    for target in stmt.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name):
                                tainted[n.id] = "user input"

            # Detect redirect with tainted URL
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call) or not _is_redirect_call(node):
                    continue
                if node.lineno in seen:
                    continue

                url_arg = node.args[0] if node.args else None
                for kw in node.keywords:
                    if kw.arg in ("url", "location"):
                        url_arg = kw.value

                if url_arg is None:
                    continue

                if _is_taint_source(url_arg) or bool(_names(url_arg) & tainted.keys()):
                    seen.add(node.lineno)
                    func_node = node.func
                    sink = func_node.id if isinstance(func_node, ast.Name) else func_node.attr
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="user input",
                        sink=sink,
                    ))

        return findings
