"""Rule 12 — MASS-ASSIGN: Mass assignment / parameter pollution.

Covers: Flask (**request.json), Django (ModelForm all fields, .filter(**GET.dict())),
DRF (serializer.save(**request.data)), FastAPI (Model(**body.dict())).

Chains into: privilege escalation within the app (user → admin),
business logic bypass (setting is_paid=True, role=superuser).
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, names, is_source, is_tainted_expr, collect_taint,
    fastapi_tainted_params,
)

_DICT_SOURCES: set[tuple[str, ...]] = {
    ("request", "json"),
    ("request", "form"),
    ("request", "args"),
    ("request", "values"),
    ("request", "data"),
    ("request", "POST"),
    ("request", "GET"),
    ("request", "query_params"),
}

_DICT_METHODS = {"get_json", "json", "dict", "model_dump"}


def _is_request_dict(node: ast.expr) -> bool:
    chain = attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in _DICT_SOURCES):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _DICT_METHODS:
            return True
    return False


def _starstar_value(call: ast.Call) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg is None:
            return kw.value
    return None


class MassAssignRule(BaseRule):
    rule_id     = "MASS-ASSIGN"
    description = (
        "Request data unpacked into a model or function with ** — "
        "allows attackers to set arbitrary fields (is_admin, role, price)"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    def _check_fn(self, func, source_lines, filepath):
        tainted: set[str] = fastapi_tainted_params(func)   # seed FastAPI params
        findings = []
        seen: set[int] = set()

        for stmt in ast.walk(func):
            if isinstance(stmt, ast.Assign) and (_is_request_dict(stmt.value) or bool(names(stmt.value) & tainted)):
                for target in stmt.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            tainted.add(n.id)

            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call) or node.lineno in seen:
                    continue
                unpacked = _starstar_value(node)
                if unpacked is None:
                    continue
                if _is_request_dict(unpacked) or bool(names(unpacked) & tainted):
                    seen.add(node.lineno)
                    fn = node.func
                    sink = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else "?"
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="request data",
                        sink=f"{sink}(**request_data)",
                    ))

        return findings
