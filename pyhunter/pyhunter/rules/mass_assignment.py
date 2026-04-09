"""Rule: mass assignment — request data unpacked directly into model constructors."""
from __future__ import annotations

import ast
from typing import List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Sources of user-supplied dict data
_DICT_SOURCES: set[tuple[str, ...]] = {
    ("request", "json"),
    ("request", "form"),
    ("request", "args"),
    ("request", "values"),
    ("request", "data"),
}
_DICT_SOURCE_METHODS = {"get_json", "json"}


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _is_request_dict(node: ast.expr) -> bool:
    """Return True if node is a request dict source (request.json, request.form, etc.)."""
    chain = _attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in _DICT_SOURCES):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _DICT_SOURCE_METHODS:
            return True
    return False


def _names(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _has_starstar_unpack(node: ast.Call) -> ast.expr | None:
    """Return the dict expression used in **unpack if any kwarg is a ** unpack."""
    for kw in node.keywords:
        if kw.arg is None:  # **kw — double-star unpack
            return kw.value
    return None


class MassAssignmentRule(BaseRule):
    rule_id     = "MASS-ASSIGN"
    description = (
        "Request data unpacked directly into a model or function call with **kwargs — "
        "allows attackers to set arbitrary fields"
    )

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
            # Track taint from request dict sources
            if isinstance(stmt, ast.Assign):
                if _is_request_dict(stmt.value) or bool(_names(stmt.value) & tainted):
                    for target in stmt.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name):
                                tainted.add(n.id)

            # Find ** unpacking of request data
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                unpacked = _has_starstar_unpack(node)
                if unpacked is None:
                    continue
                if node.lineno in seen:
                    continue

                if _is_request_dict(unpacked) or bool(_names(unpacked) & tainted):
                    seen.add(node.lineno)
                    func_node = node.func
                    if isinstance(func_node, ast.Name):
                        sink = func_node.id
                    elif isinstance(func_node, ast.Attribute):
                        sink = func_node.attr
                    else:
                        sink = "unknown"
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="request data",
                        sink=f"{sink}(**...)",
                    ))

        return findings
