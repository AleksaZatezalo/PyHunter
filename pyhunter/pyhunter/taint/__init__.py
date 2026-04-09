"""Intra-procedural taint tracking engine.

Propagates user-controlled values from sources to sinks within a single
function body by walking statements in linear order.

Sources: request.*, sys.argv, os.environ, input()
Sinks:   eval, exec, compile, open, os.system, subprocess.*, pickle.*, yaml.load
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Generator, List, Set


@dataclass
class TaintFlow:
    source_expr:   str
    sink:          str
    file:          str
    source_line:   int
    sink_line:     int
    tainted_vars:  List[str] = field(default_factory=list)
    function_name: str = ""


# ── Source / sink tables ──────────────────────────────────────────────────────

_SOURCE_CHAINS: set[tuple[str, ...]] = {
    ("request", "args"),   ("request", "form"),
    ("request", "json"),   ("request", "data"),
    ("request", "files"),  ("request", "values"),
    ("sys", "argv"),       ("os", "environ"),
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
    ("pickle",     "load"),
    ("yaml",       "load"),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

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
    if chain and any(chain[: len(s)] == s for s in _SOURCE_CHAINS):
        return True
    if isinstance(node, ast.Subscript) and _is_source(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _SOURCE_CALLS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in _SOURCE_METHODS and _is_source(func.value):
            return True
    return False


def _names(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_tainted(expr: ast.expr, tainted: dict) -> bool:
    return _is_source(expr) or bool(_names(expr) & tainted.keys())


def _source_desc(expr: ast.expr, tainted: dict) -> tuple[int | None, str]:
    if _is_source(expr):
        chain = _attr_chain(expr)
        return None, ".".join(chain) if chain else "user input"
    for name in _names(expr) & tainted.keys():
        return tainted[name]
    return None, "unknown"


def _sink_key(call: ast.Call) -> tuple[str | None, str] | None:
    if isinstance(call.func, ast.Name):
        return (None, call.func.id)
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _unpack_names(target: ast.expr) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def _walk_stmts(stmts: list[ast.stmt]) -> Generator[ast.stmt, None, None]:
    for stmt in stmts:
        yield stmt
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                yield child


# ── Engine ────────────────────────────────────────────────────────────────────

class TaintEngine:
    def analyze(self, tree: ast.AST, source_lines: list[str], filepath: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                flows.extend(self._analyze_function(node, filepath))
        return flows

    def _analyze_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        filepath: str,
    ) -> List[TaintFlow]:
        tainted: dict[str, tuple[int, str]] = {}
        flows:   List[TaintFlow]            = []

        for stmt in _walk_stmts(func.body):
            if isinstance(stmt, ast.Assign) and _is_tainted(stmt.value, tainted):
                src_line, src_desc = _source_desc(stmt.value, tainted)
                for target in stmt.targets:
                    for name in _unpack_names(target):
                        tainted[name] = (src_line or stmt.lineno, src_desc)
                if isinstance(stmt.value, ast.Call):
                    flow = self._check_sink(stmt.value, tainted, func.name, filepath)
                    if flow:
                        flows.append(flow)

            elif isinstance(stmt, ast.AnnAssign) and stmt.value and _is_tainted(stmt.value, tainted):
                src_line, src_desc = _source_desc(stmt.value, tainted)
                for name in _unpack_names(stmt.target):
                    tainted[name] = (src_line or stmt.lineno, src_desc)

            elif isinstance(stmt, ast.AugAssign) and _is_tainted(stmt.value, tainted) and isinstance(stmt.target, ast.Name):
                src_line, src_desc = _source_desc(stmt.value, tainted)
                tainted[stmt.target.id] = (src_line or stmt.lineno, src_desc)

            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                flow = self._check_sink(stmt.value, tainted, func.name, filepath)
                if flow:
                    flows.append(flow)

            elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                flow = self._check_sink(stmt.value, tainted, func.name, filepath)
                if flow:
                    flows.append(flow)

        return flows

    def _check_sink(
        self,
        call:      ast.Call,
        tainted:   dict,
        func_name: str,
        filepath:  str,
    ) -> TaintFlow | None:
        key = _sink_key(call)
        if key not in _SINKS:
            return None

        arg_names: Set[str] = set()
        for arg in call.args:
            arg_names |= _names(arg)
        for kw in call.keywords:
            arg_names |= _names(kw.value)

        tainted_args = arg_names & tainted.keys()
        if not tainted_args:
            return None

        src_line, src_desc = min(
            (tainted[n] for n in tainted_args), key=lambda t: t[0] or 0
        )
        module, name = key
        sink_label = f"{module}.{name}" if module else name

        return TaintFlow(
            source_expr=src_desc,
            sink=sink_label,
            file=filepath,
            source_line=src_line or call.lineno,
            sink_line=call.lineno,
            tainted_vars=sorted(tainted_args),
            function_name=func_name,
        )
