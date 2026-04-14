"""Intra-procedural taint-tracking engine (legacy linear analysis).

Design pattern: Visitor
  TaintEngine.analyze() visits every function in an AST and, for each one,
  walks its statement list in linear order to propagate taint from sources
  to sinks.  The engine produces TaintFlow records.

Taint model:
  Sources    — user-controlled inputs: request.*, sys.argv, os.environ, input()
  Sinks      — dangerous call sites: eval, exec, open, os.system, subprocess.*,
               pickle.loads, yaml.load
  Sanitizers — functions that neutralise taint: shlex.quote, html.escape,
               re.escape, bleach.clean, markupsafe.escape, etc.
               Sanitized taint is still tracked so bypass risk can be assessed.

The legacy TaintEngine / TaintFlow / TaintStep names are preserved for
backward compatibility with test_taint.py and any external callers.

New CFG-based analysis: see taint/cfg.py + taint/analysis.py.
Public facade: CFGAnalyzer (defined at the bottom of this module).
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Generator, List, Optional, Set

# Shared AST helpers and tables live in _helpers.py to avoid circular imports
# between this module and cfg.py (which also needs them).
from pyhunter.taint._helpers import (
    _SANITIZER_KEYS, _SINKS, _SOURCE_CALLS, _SOURCE_CHAINS, _SOURCE_METHODS,
    _attr_chain, _call_arg_names, _call_key, _is_source, _is_tainted,
    _names, _source_desc, _unpack_names,
)


# ── Legacy dataclasses (backward-compatible) ──────────────────────────────────

@dataclass
class TaintStep:
    """One hop in a taint propagation path from source to sink."""

    line:        int
    variable:    str
    description: str


@dataclass
class TaintFlow:
    """A single resolved taint path from source to sink within one function."""

    source_expr:   str
    sink:          str
    file:          str
    source_line:   int
    sink_line:     int
    tainted_vars:  List[str] = field(default_factory=list)
    function_name: str = ""
    path:          List[TaintStep] = field(default_factory=list)
    sanitized:     bool            = False
    sanitizer:     Optional[str]   = None


# ── AST helpers (kept as module-level names for backward compat) ──────────────

# Backward-compatible alias used by Scanner
_sink_key = _call_key


def _walk_stmts(stmts: list[ast.stmt]) -> Generator[ast.stmt, None, None]:
    for stmt in stmts:
        yield stmt
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                yield child


# ── Legacy TaintEngine ────────────────────────────────────────────────────────

class TaintEngine:
    """Legacy visitor: walks every function in an AST and records taint flows.

    Retained unchanged for test_taint.py backward compatibility.
    New code should use CFGAnalyzer instead.
    """

    def analyze(self, tree: ast.AST, source_lines: list[str], filepath: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                flows.extend(self._visit_function(node, filepath))
        return flows

    def _visit_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        filepath: str,
    ) -> List[TaintFlow]:
        tainted: dict[str, tuple[int, str]] = {}
        taint_path: dict[str, list[TaintStep]] = {}
        sanitized_vars: dict[str, str] = {}
        flows: List[TaintFlow] = []

        for stmt in _walk_stmts(func.body):

            # ── Sanitizer application: z = shlex.quote(x) ────────────────────
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                san_key = _call_key(stmt.value)
                if san_key in _SANITIZER_KEYS:
                    arg_names    = _call_arg_names(stmt.value)
                    tainted_args = arg_names & tainted.keys()
                    if tainted_args:
                        san_name = (
                            f"{san_key[0]}.{san_key[1]}" if san_key[0] else san_key[1]
                        )
                        best = min(tainted_args, key=lambda n: tainted[n][0] or 0)
                        src_line, src_desc = tainted[best]
                        prev_path = list(taint_path.get(best, []))
                        for target in stmt.targets:
                            for name in _unpack_names(target):
                                tainted[name]        = (src_line, src_desc)
                                sanitized_vars[name] = san_name
                                taint_path[name]     = prev_path + [
                                    TaintStep(
                                        stmt.lineno, name,
                                        f"sanitized by {san_name}() → `{name}`",
                                    )
                                ]
                        continue

            # ── Normal assignment: x = <tainted expr> ────────────────────────
            if isinstance(stmt, ast.Assign) and _is_tainted(stmt.value, tainted):
                src_line, src_desc2 = _source_desc(stmt.value, tainted)
                for target in stmt.targets:
                    for name in _unpack_names(target):
                        tainted[name] = (src_line or stmt.lineno, src_desc2)
                        if _is_source(stmt.value):
                            taint_path[name] = [
                                TaintStep(
                                    stmt.lineno, name,
                                    f"assigned from {src_desc2}",
                                )
                            ]
                        else:
                            prev_names = _names(stmt.value) & tainted.keys()
                            best_prev  = (
                                min(prev_names, key=lambda n: tainted[n][0] or 0)
                                if prev_names else None
                            )
                            prev_path  = list(taint_path.get(best_prev, [])) if best_prev else []
                            taint_path[name] = prev_path + [
                                TaintStep(stmt.lineno, name, f"propagated to `{name}`")
                            ]
                if isinstance(stmt.value, ast.Call):
                    flow = self._check_sink(
                        stmt.value, tainted, taint_path, sanitized_vars,
                        func.name, filepath,
                    )
                    if flow:
                        flows.append(flow)

            elif isinstance(stmt, ast.AnnAssign) and stmt.value and _is_tainted(stmt.value, tainted):
                src_line, src_desc2 = _source_desc(stmt.value, tainted)
                for name in _unpack_names(stmt.target):
                    tainted[name] = (src_line or stmt.lineno, src_desc2)
                    prev_names = _names(stmt.value) & tainted.keys()
                    best_prev  = (
                        min(prev_names, key=lambda n: tainted[n][0] or 0)
                        if prev_names else None
                    )
                    prev_path  = list(taint_path.get(best_prev, [])) if best_prev else []
                    taint_path[name] = prev_path + [
                        TaintStep(stmt.lineno, name, f"annotated assignment to `{name}`")
                    ]

            elif (isinstance(stmt, ast.AugAssign)
                  and _is_tainted(stmt.value, tainted)
                  and isinstance(stmt.target, ast.Name)):
                src_line, src_desc2 = _source_desc(stmt.value, tainted)
                name      = stmt.target.id
                prev_path = list(taint_path.get(name, []))
                tainted[name]    = (src_line or stmt.lineno, src_desc2)
                taint_path[name] = prev_path + [
                    TaintStep(stmt.lineno, name, f"augmented assignment to `{name}`")
                ]

            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                flow = self._check_sink(
                    stmt.value, tainted, taint_path, sanitized_vars,
                    func.name, filepath,
                )
                if flow:
                    flows.append(flow)

            elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                flow = self._check_sink(
                    stmt.value, tainted, taint_path, sanitized_vars,
                    func.name, filepath,
                )
                if flow:
                    flows.append(flow)

        return flows

    def _check_sink(
        self,
        call:           ast.Call,
        tainted:        dict,
        taint_path:     dict,
        sanitized_vars: dict,
        func_name:      str,
        filepath:       str,
    ) -> TaintFlow | None:
        key = _call_key(call)
        if key not in _SINKS:
            return None

        arg_names    = _call_arg_names(call)
        tainted_args = arg_names & tainted.keys()
        if not tainted_args:
            return None

        best = min(tainted_args, key=lambda n: tainted[n][0] or 0)
        src_line, src_desc2 = tainted[best]

        module, name = key
        sink_str = f"{module}.{name}" if module else name

        path = list(taint_path.get(best, []))
        path.append(TaintStep(call.lineno, sink_str, f"reaches sink {sink_str}()"))

        san_args     = tainted_args & sanitized_vars.keys()
        is_sanitized = bool(san_args)
        sanitizer    = sanitized_vars.get(next(iter(san_args))) if san_args else None

        return TaintFlow(
            source_expr=src_desc2,
            sink=sink_str,
            file=filepath,
            source_line=src_line or call.lineno,
            sink_line=call.lineno,
            tainted_vars=sorted(tainted_args),
            function_name=func_name,
            path=path,
            sanitized=is_sanitized,
            sanitizer=sanitizer,
        )


# ── New CFG-based API ─────────────────────────────────────────────────────────
# Imported after the legacy code to avoid circular imports.

from pyhunter.taint.cfg      import build_function_ir   # noqa: E402
from pyhunter.taint.analysis import analyze_function    # noqa: E402
from pyhunter.taint.types    import (                   # noqa: E402
    PathStep, SourceLocation, StepKind, TaintAnalysis, TaintPath,
)


class CFGAnalyzer:
    """High-level facade for the CFG-based taint analysis.

    Mirrors TaintEngine's interface so the Scanner can swap implementations
    without changing call sites.
    """

    def analyze_function(self, func_node, filepath: str, rule_id: str = "") -> List[TaintPath]:
        """Build FunctionIR and run worklist analysis; return List[TaintPath]."""
        func_ir = build_function_ir(func_node, filepath)
        return analyze_function(func_ir, rule_id)

    def find_enclosing_function(self, tree, lineno: int):
        """Return the innermost FunctionDef that contains *lineno*, or None."""
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end   = getattr(node, "end_lineno", start + 1000)
                if start <= lineno <= end:
                    if best is None or node.lineno > best.lineno:
                        best = node
        return best
