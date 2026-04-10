"""Rule: FLOW-WEB — web/CLI user input flowing into a dangerous sink.

This rule performs intra-function taint tracking: it traces user-controlled
values from framework request sources to a fixed set of dangerous sinks.
It is the catch-all complement to the more specialised DESER-RCE and
CMD-INJECT rules — it catches multi-hop flows (request → var → eval) that
simpler per-sink rules may miss.
"""
from __future__ import annotations

import ast
from typing import Generator, List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain, is_source, names

# Dangerous sinks tracked by this rule.
# (None, name)   → bare function call: eval(x)
# (module, name) → attribute call:    os.system(x)
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


def _sink_key(call: ast.Call) -> tuple[str | None, str] | None:
    if isinstance(call.func, ast.Name):
        return (None, call.func.id)
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _walk_stmts(stmts: list[ast.stmt]) -> Generator[ast.stmt, None, None]:
    """Yield each statement and its immediate children recursively."""
    for stmt in stmts:
        yield stmt
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                yield child


class WebInputFlowRule(BaseRule):
    """Template Method: implements BaseRule.check() for web-input taint flows."""

    rule_id     = "FLOW-WEB"
    description = "Web/CLI user input flowing into a dangerous sink"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    # ── per-function taint scan ───────────────────────────────────────────────

    def _check_fn(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        tainted: dict[str, str] = {}
        findings: List[Finding] = []

        for stmt in _walk_stmts(func.body):
            # Propagate taint through assignments
            rhs = self._rhs_of(stmt)
            if rhs is not None and self._is_tainted(rhs, tainted):
                desc = self._source_desc(rhs, tainted)
                for var in self._assigned_names(stmt):
                    tainted[var] = desc

            # Check sink calls within this statement
            for call in self._sink_calls_in(stmt):
                key = _sink_key(call)
                if key not in _SINKS:
                    continue
                arg_names = {n for arg in call.args for n in names(arg)}
                arg_names |= {n for kw in call.keywords for n in names(kw.value)}
                hit = arg_names & tainted.keys()
                if hit:
                    module, name_ = key
                    findings.append(Finding(
                        id=f"{self.rule_id}-{call.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=call.lineno,
                        snippet=self._snippet(source_lines, call.lineno),
                        source=", ".join(sorted(tainted[n] for n in hit)),
                        sink=f"{module}.{name_}" if module else name_,
                    ))

        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_tainted(self, expr: ast.expr, tainted: dict) -> bool:
        return is_source(expr) or bool(names(expr) & tainted.keys())

    def _source_desc(self, expr: ast.expr, tainted: dict) -> str:
        if is_source(expr):
            chain = attr_chain(expr.func if isinstance(expr, ast.Call) else expr)
            return ".".join(chain) if chain else "user input"
        for n in names(expr) & tainted.keys():
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

    def _sink_calls_in(self, stmt: ast.stmt) -> list[ast.Call]:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return [stmt.value]
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            return [stmt.value]
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            return [stmt.value]
        return []
