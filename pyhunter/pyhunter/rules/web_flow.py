"""Rule: web/CLI user input flowing into dangerous sinks within function scope."""
from __future__ import annotations

import ast
from typing import Generator, List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_TAINT_SOURCES: set[tuple[str, ...]] = {
    ("request", "args"),
    ("request", "form"),
    ("request", "json"),
    ("request", "data"),
    ("request", "files"),
    ("request", "values"),
    ("sys", "argv"),
    ("os", "environ"),
}

_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {"getenv", "get_json", "get_data", "get"}

_SINKS: set[tuple[str | None, str]] = {
    (None,         "eval"),
    (None,         "exec"),
    (None,         "compile"),
    (None,         "open"),
    ("os",         "system"),
    ("os",         "popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("pickle",     "loads"),
    ("yaml",       "load"),
}


# ── Taint helpers ─────────────────────────────────────────────────────────────

def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _is_source(node: ast.expr) -> bool:
    chain = _attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in _TAINT_SOURCES):
        return True
    if isinstance(node, ast.Subscript) and _is_source(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _SOURCE_CALLS:
            return True
        if isinstance(func, ast.Attribute):
            if func.attr in _SOURCE_METHODS and _is_source(func.value):
                return True
    return False


def _names(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _sink_key(call: ast.Call) -> tuple[str | None, str] | None:
    if isinstance(call.func, ast.Name):
        return (None, call.func.id)
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _walk_stmts(stmts: list[ast.stmt]) -> Generator[ast.stmt, None, None]:
    for stmt in stmts:
        yield stmt
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                yield child


# ── Rule ──────────────────────────────────────────────────────────────────────

class WebInputFlowRule(BaseRule):
    rule_id     = "FLOW-WEB"
    description = "Web/CLI user input flowing into a dangerous sink"

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
        tainted: dict[str, str] = {}   # name → source description
        findings: List[Finding] = []

        for stmt in _walk_stmts(func.body):
            rhs = self._rhs_of(stmt)
            if rhs is not None and self._is_tainted(rhs, tainted):
                desc = self._source_desc(rhs, tainted)
                for name in self._assigned_names(stmt):
                    tainted[name] = desc

            for call in self._calls_in(stmt):
                key = _sink_key(call)
                if key not in _SINKS:
                    continue
                arg_names = {n for arg in call.args for n in _names(arg)}
                arg_names |= {n for kw in call.keywords for n in _names(kw.value)}
                hit = arg_names & tainted.keys()
                if hit:
                    module, name = key
                    findings.append(Finding(
                        id=f"{self.rule_id}-{call.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=call.lineno,
                        snippet=self._snippet(source_lines, call.lineno),
                        source=", ".join(sorted(tainted[n] for n in hit)),
                        sink=f"{module}.{name}" if module else name,
                    ))

        return findings

    def _is_tainted(self, expr: ast.expr, tainted: dict) -> bool:
        return _is_source(expr) or bool(_names(expr) & tainted.keys())

    def _source_desc(self, expr: ast.expr, tainted: dict) -> str:
        if _is_source(expr):
            if isinstance(expr, ast.Call):
                chain = _attr_chain(expr.func)
            else:
                chain = _attr_chain(expr)
            return ".".join(chain) if chain else "user input"
        for n in _names(expr) & tainted.keys():
            return tainted[n]
        return "user input"

    def _rhs_of(self, stmt: ast.stmt) -> ast.expr | None:
        if isinstance(stmt, ast.Assign):
            return stmt.value
        if isinstance(stmt, ast.AnnAssign) and stmt.value:
            return stmt.value
        if isinstance(stmt, ast.AugAssign):
            return stmt.value
        return None

    def _assigned_names(self, stmt: ast.stmt) -> list[str]:
        if isinstance(stmt, ast.Assign):
            return [n.id for t in stmt.targets for n in ast.walk(t) if isinstance(n, ast.Name)]
        if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            return [n.id for n in ast.walk(stmt.target) if isinstance(n, ast.Name)]
        return []

    def _calls_in(self, stmt: ast.stmt) -> list[ast.Call]:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return [stmt.value]
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            return [stmt.value]
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            return [stmt.value]
        return []
