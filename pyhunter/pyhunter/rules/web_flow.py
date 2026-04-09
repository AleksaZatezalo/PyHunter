"""
Rule: Web Input → Sink Flows (FLOW-001)

Tracks user input from HTTP request objects and CLI arguments into dangerous
sinks within the same function scope, using a linear statement-order walk
to correctly propagate taint through assignment chains.
"""

from __future__ import annotations
import ast
from typing import Generator, List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


_TAINT_CHAINS: set[tuple[str, ...]] = {
    ("request", "args"),
    ("request", "form"),
    ("request", "json"),
    ("request", "data"),
    ("request", "files"),
    ("request", "values"),
    ("request", "get_json"),
    ("request", "get_data"),
    ("sys", "argv"),
    ("os", "environ"),
}

_SOURCE_CALLS: set[str] = {"input"}
_SOURCE_METHODS: set[str] = {"getenv", "get_json", "get_data", "get"}

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
    if chain and any(chain[: len(s)] == s for s in _TAINT_CHAINS):
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
            if _is_source(func):
                return True
    return False


def _names_in(node: ast.expr) -> Set[str]:
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


class WebInputFlowRule(BaseRule):
    rule_id = "FLOW-WEB"
    description = "Tracks HTTP/CLI user input flowing into dangerous sinks within function scope."

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for func in ast.walk(tree):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function(func, source_lines, filepath))
        return findings

    def _check_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        tainted: dict[str, str] = {}   # name → source description
        findings: List[Finding] = []
        counter = 0

        for stmt in _walk_stmts(func.body):
            rhs = self._rhs(stmt)
            if rhs is not None and self._expr_tainted(rhs, tainted):
                for target in self._targets(stmt):
                    tainted[target] = self._source_desc(rhs, tainted)

            # Check sink calls in this statement
            for call in self._calls_in(stmt):
                key = _sink_key(call)
                if key not in _SINKS:
                    continue
                arg_names = self._call_arg_names(call)
                hit = arg_names & tainted.keys()
                if hit:
                    counter += 1
                    module, name = key
                    sink_str = f"{module}.{name}" if module else name
                    findings.append(Finding(
                        id=f"PY-FLOW-{counter:03d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=call.lineno,
                        snippet=self._snippet(source_lines, call.lineno),
                        source=", ".join(sorted(hit)),
                        sink=sink_str,
                        extra={"tainted_vars": sorted(hit), "function": func.name},
                    ))

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _expr_tainted(self, expr: ast.expr, tainted: dict) -> bool:
        if _is_source(expr):
            return True
        return bool(_names_in(expr) & tainted.keys())

    def _source_desc(self, expr: ast.expr, tainted: dict) -> str:
        if _is_source(expr):
            chain = _attr_chain(expr)
            return ".".join(chain) if chain else "user input"
        for name in _names_in(expr) & tainted.keys():
            return tainted[name]
        return "user input"

    def _rhs(self, stmt: ast.stmt) -> ast.expr | None:
        if isinstance(stmt, ast.Assign):
            return stmt.value
        if isinstance(stmt, ast.AnnAssign) and stmt.value:
            return stmt.value
        if isinstance(stmt, ast.AugAssign):
            return stmt.value
        return None

    def _targets(self, stmt: ast.stmt) -> list[str]:
        names: list[str] = []
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                names.extend(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            names.extend(n.id for n in ast.walk(stmt.target) if isinstance(n, ast.Name))
        return names

    def _calls_in(self, stmt: ast.stmt) -> list[ast.Call]:
        calls: list[ast.Call] = []
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            calls.append(stmt.value)
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            calls.append(stmt.value)
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            calls.append(stmt.value)
        return calls

    def _call_arg_names(self, call: ast.Call) -> Set[str]:
        names: Set[str] = set()
        for arg in call.args:
            names |= _names_in(arg)
        for kw in call.keywords:
            names |= _names_in(kw.value)
        return names
