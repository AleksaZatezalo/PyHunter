"""
pyhunter/taint/__init__.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Intra-procedural taint tracking engine.

Tracks user-controlled values from *sources* to *sinks* within a single
function body by propagating a tainted-name set through assignments using
a linear statement-order walk.

Architecture
------------
TaintEngine.analyze(tree, source_lines, filepath)
    └── _analyze_function(func_node)
            ├── _walk_stmts() — linear, order-preserving statement iterator
            ├── Pass per-statement: propagate taint through assignments
            └── Pass per-statement: flag sink calls whose args are tainted

Sources (expressions that introduce taint):
    request.args / request.form / request.json / request.data
    request.form["key"]  (Subscript on a source object)
    request.get_json() / request.get_data()
    sys.argv / os.environ / os.getenv(...)
    input()

Sinks (dangerous when tainted args reach them):
    eval / exec / compile / open
    os.system / os.popen
    subprocess.run / subprocess.call / subprocess.Popen
    pickle.loads / pickle.load / yaml.load

Propagation rules (conservative — taint flows forward):
    x = <source>            → x tainted
    x = tainted_var         → x tainted
    x = f(tainted)          → x tainted (calls propagate taint through return)
    x = tainted + literal   → x tainted
    x = tainted[key]        → x tainted (subscript preserves taint)
    x, y = tainted_tuple    → x, y tainted
    x = tainted.attr        → x tainted

Limitation: intra-procedural only. Cross-function taint tracked in Phase 2.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Generator, List, Set


# ── Public types ───────────────────────────────────────────────────────────────

@dataclass
class TaintFlow:
    """A confirmed taint flow from a source to a sink within one function."""
    source_expr: str        # human-readable origin description
    sink: str               # e.g. "eval", "os.system"
    file: str
    source_line: int
    sink_line: int
    tainted_vars: List[str] = field(default_factory=list)
    function_name: str = ""


# ── Source / sink tables ───────────────────────────────────────────────────────

# Attribute chain prefixes whose value is user-controlled
_SOURCE_CHAINS: set[tuple[str, ...]] = {
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

# Bare function names that return user-controlled values
_SOURCE_CALLS: set[str] = {"input"}

# Attribute method names on any object that return user-controlled values
_SOURCE_METHODS: set[str] = {"getenv", "get_json", "get_data", "get"}

# (module_or_None, method) pairs that are dangerous sinks
_SINK_TABLE: set[tuple[str | None, str]] = {
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


# ── Helpers ────────────────────────────────────────────────────────────────────

def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    """Return ('a', 'b', 'c') for a.b.c, else ()."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _is_source_expr(node: ast.expr) -> bool:
    """Return True if *node* evaluates to user-controlled input."""
    # Direct attribute chain: request.args, sys.argv, …
    chain = _attr_chain(node)
    if chain and any(chain[: len(src)] == src for src in _SOURCE_CHAINS):
        return True

    # Subscript on a source: request.form["key"], request.args.get("x")
    if isinstance(node, ast.Subscript) and _is_source_expr(node.value):
        return True

    # Call expression
    if isinstance(node, ast.Call):
        func = node.func
        # Bare call: input()
        if isinstance(func, ast.Name) and func.id in _SOURCE_CALLS:
            return True
        # Method on a source: request.get_json(), os.getenv(…)
        if isinstance(func, ast.Attribute):
            if func.attr in _SOURCE_METHODS and _is_source_expr(func.value):
                return True
            # Whole chain is a source: request.get_json()
            if _is_source_expr(func):
                return True

    return False


def _names_in(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _rhs_references_tainted(value: ast.expr, tainted: dict) -> bool:
    """True if value is itself a source OR references at least one tainted name."""
    if _is_source_expr(value):
        return True
    return bool(_names_in(value) & tainted.keys())


def _source_description(value: ast.expr, tainted: dict) -> tuple[int | None, str]:
    """Return (line, description) for the originating taint."""
    if _is_source_expr(value):
        chain = _attr_chain(value)
        return None, ".".join(chain) if chain else "user input"
    for name in _names_in(value) & tainted.keys():
        return tainted[name]
    return None, "unknown"


def _sink_key(call: ast.Call) -> tuple[str | None, str] | None:
    if isinstance(call.func, ast.Name):
        return (None, call.func.id)
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _sink_label(key: tuple[str | None, str]) -> str:
    module, name = key
    return f"{module}.{name}" if module else name


def _unpack_targets(target: ast.expr) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def _walk_stmts(stmts: list[ast.stmt]) -> Generator[ast.stmt, None, None]:
    """
    Yield statements in linear execution order, descending into compound
    statements (if/for/while/with/try bodies) depth-first.
    """
    for stmt in stmts:
        yield stmt
        # Descend into nested blocks so inner assignments propagate taint
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, list):
                yield from _walk_stmts(child)
            elif isinstance(child, ast.stmt):
                yield child


# ── Engine ─────────────────────────────────────────────────────────────────────

class TaintEngine:
    """
    Intra-procedural taint engine.

    Usage:
        engine = TaintEngine()
        flows = engine.analyze(ast_tree, source_lines, filepath)
    """

    def analyze(self, tree: ast.AST, source_lines: list[str], filepath: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                flows.extend(self._analyze_function(node, source_lines, filepath))
        return flows

    def _analyze_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: list[str],
        filepath: str,
    ) -> List[TaintFlow]:
        # tainted: name → (source_line, source_description)
        tainted: dict[str, tuple[int, str]] = {}
        flows: List[TaintFlow] = []

        for stmt in _walk_stmts(func.body):
            # ── Regular assignment: x = <expr> ──────────────────────────────
            if isinstance(stmt, ast.Assign):
                if _rhs_references_tainted(stmt.value, tainted):
                    src_line, src_desc = _source_description(stmt.value, tainted)
                    for target in stmt.targets:
                        for name in _unpack_targets(target):
                            tainted[name] = (src_line or stmt.lineno, src_desc)
                # Check if the RHS is a tainted sink call (result = eval(tainted))
                if isinstance(stmt.value, ast.Call):
                    flow = self._check_sink_call(stmt.value, tainted, func.name, filepath)
                    if flow:
                        flows.append(flow)

            # ── Annotated assignment: x: T = <expr> ─────────────────────────
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                if _rhs_references_tainted(stmt.value, tainted):
                    src_line, src_desc = _source_description(stmt.value, tainted)
                    for name in _unpack_targets(stmt.target):
                        tainted[name] = (src_line or stmt.lineno, src_desc)

            # ── Augmented assignment: x += tainted ──────────────────────────
            elif isinstance(stmt, ast.AugAssign):
                if _rhs_references_tainted(stmt.value, tainted) and isinstance(stmt.target, ast.Name):
                    src_line, src_desc = _source_description(stmt.value, tainted)
                    tainted[stmt.target.id] = (src_line or stmt.lineno, src_desc)

            # ── Expression statement: eval(x) / os.system(x) / … ───────────
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                flow = self._check_sink_call(stmt.value, tainted, func.name, filepath)
                if flow:
                    flows.append(flow)

            # ── Return with a sink call: return eval(x) ─────────────────────
            elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                flow = self._check_sink_call(stmt.value, tainted, func.name, filepath)
                if flow:
                    flows.append(flow)

        return flows

    def _check_sink_call(
        self,
        call: ast.Call,
        tainted: dict,
        func_name: str,
        filepath: str,
    ) -> TaintFlow | None:
        key = _sink_key(call)
        if key not in _SINK_TABLE:
            return None

        arg_names: Set[str] = set()
        for arg in call.args:
            arg_names |= _names_in(arg)
        for kw in call.keywords:
            arg_names |= _names_in(kw.value)

        tainted_args = arg_names & tainted.keys()
        if not tainted_args:
            return None

        src_line, src_desc = min(
            (tainted[n] for n in tainted_args), key=lambda t: t[0] or 0
        )

        return TaintFlow(
            source_expr=src_desc,
            sink=_sink_label(key),
            file=filepath,
            source_line=src_line or call.lineno,
            sink_line=call.lineno,
            tainted_vars=sorted(tainted_args),
            function_name=func_name,
        )
