"""Strategy-pattern matchers for YAML-defined AST rules.

Design pattern: Strategy
  Each Matcher corresponds to one rule strategy declared in a YAML file.
  The YAML specifies *what* to detect; the matcher implements *how*.

Strategies
──────────
  CallMatcher         call          Bare function call: eval(x), exec(x)
  TaintMatcher        taint         Per-function intra-procedural taint flow
  AssignTrackMatcher  assign_track  Network assignment → deserialiser sink
  DecoratorMatcher    decorator     Dangerous or dynamic decorator expressions
  FileScopeMatcher    file_scope    Patterns restricted to specific filenames
  SaveHeuristicMatcher save_heuristic File upload without validation

The source-vocabulary helpers (_Sources) are self-contained here so that
matchers.py has no upward dependency on pyhunter.rules._sources.
"""
from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pyhunter.models import Finding, Severity


# ── Source vocabulary helpers ─────────────────────────────────────────────────

def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    """Walk a chain of Attribute nodes and return the parts as a tuple.

    ``request.args.get`` → ``("request", "args", "get")``
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _names(node: ast.expr) -> Set[str]:
    """Return every Name id referenced anywhere inside *node*."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _Sources:
    """Resolved taint-source vocabulary loaded from sources.yaml.

    Constructed once per matcher at rule-load time; cheap to query at
    scan time (all checks are set-membership or recursive AST walks).
    """

    def __init__(self, vocab: Dict[str, Any]) -> None:
        self._chains: set[tuple[str, ...]] = {
            tuple(c) for c in vocab.get("chains", [])
        }
        self._methods: set[str]      = set(vocab.get("source_methods", []))
        self._funcs:   set[str]      = set(vocab.get("source_functions", []))
        self._fastapi: set[str]      = set(vocab.get("fastapi_annotations", []))

    # ── Source detection ──────────────────────────────────────────────────────

    def is_source(self, node: ast.expr) -> bool:
        """Return True if *node* directly reads from a user-controlled source."""
        # Attribute chain: request.args, sys.argv, self.request.body, …
        chain = _attr_chain(node)
        if chain and any(chain[: len(s)] == s for s in self._chains):
            return True

        # Subscript on a source: request.args["key"], os.environ["HOME"]
        if isinstance(node, ast.Subscript) and self.is_source(node.value):
            return True

        if isinstance(node, ast.Call):
            func = node.func
            # Standalone source functions: input()
            if isinstance(func, ast.Name) and func.id in self._funcs:
                return True
            # Method calls: request.get("key"), os.environ.get("K")
            if isinstance(func, ast.Attribute) and func.attr in self._methods:
                obj_chain = _attr_chain(func.value)
                if obj_chain and obj_chain[0] in ("request", "self", "os"):
                    return True

        return False

    def is_tainted(self, node: ast.expr, tainted: dict) -> bool:
        return self.is_source(node) or bool(_names(node) & tainted.keys())

    # ── FastAPI parameter detection ───────────────────────────────────────────

    def _is_fastapi_param(self, default: ast.expr) -> bool:
        if not isinstance(default, ast.Call):
            return False
        func = default.func
        if isinstance(func, ast.Name):
            return func.id in self._fastapi
        if isinstance(func, ast.Attribute):
            return func.attr in self._fastapi
        return False

    def _fastapi_tainted_params(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> set[str]:
        tainted: set[str] = set()
        args      = func.args
        n_args    = len(args.args)
        n_defaults = len(args.defaults)
        for i, arg in enumerate(args.args):
            idx = i - (n_args - n_defaults)
            if idx >= 0 and self._is_fastapi_param(args.defaults[idx]):
                tainted.add(arg.arg)
        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
            if default is not None and self._is_fastapi_param(default):
                tainted.add(arg.arg)
        return tainted

    # ── Taint collection ──────────────────────────────────────────────────────

    def collect_taint(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[dict[str, str], set[str]]:
        """Walk *func* and return ``(tainted_vars, fastapi_params)``.

        ``tainted_vars`` maps variable name → source description string.
        Descriptions use the dotted attribute chain when available so that
        rules which expose ``Finding.source`` show meaningful context
        (e.g. ``"request.args.get"`` rather than the generic ``"user input"``).
        """
        fp      = self._fastapi_tainted_params(func)
        tainted: dict[str, str] = {p: "fastapi_param" for p in fp}

        for stmt in ast.walk(func):
            rhs:     ast.expr | None    = None
            targets: list[ast.expr]     = []

            if isinstance(stmt, ast.Assign):
                rhs, targets = stmt.value, stmt.targets
            elif isinstance(stmt, ast.AnnAssign) and stmt.value:
                rhs, targets = stmt.value, [stmt.target]
            elif isinstance(stmt, ast.AugAssign):
                rhs, targets = stmt.value, [stmt.target]

            if rhs is None:
                continue

            # Unwrap `await expr` (Starlette / FastAPI async sources)
            if isinstance(rhs, ast.Await):
                rhs = rhs.value

            rhs_names = _names(rhs)
            if not (self.is_source(rhs) or bool(rhs_names & (tainted.keys() | fp))):
                continue

            # Build a human-readable source description
            if self.is_source(rhs):
                # For Call nodes use the function's attribute chain
                chain_node = rhs.func if isinstance(rhs, ast.Call) else rhs
                chain = _attr_chain(chain_node)
                desc: str = ".".join(chain) if chain else "user input"
            else:
                # Propagate from the best upstream tainted variable
                desc = next(
                    (tainted[n] for n in rhs_names & tainted.keys()),
                    "user input",
                )

            for target in targets:
                for n in ast.walk(target):
                    if isinstance(n, ast.Name):
                        tainted[n.id] = desc

        return tainted, fp


# ── Abstract base ─────────────────────────────────────────────────────────────

class Matcher(ABC):
    """Abstract base for all rule-strategy implementations."""

    @abstractmethod
    def match(
        self,
        tree:         ast.AST,
        source_lines: List[str],
        filepath:     str,
        rule:         Any,     # YAMLRule — avoids circular import
    ) -> List[Finding]: ...

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _snippet(
        self, source_lines: List[str], lineno: int, context: int = 2
    ) -> str:
        start = max(0, lineno - 1 - context)
        end   = min(len(source_lines), lineno + context)
        return "\n".join(source_lines[start:end]).strip()

    def _finding(
        self,
        rule:         Any,
        filepath:     str,
        source_lines: List[str],
        lineno:       int,
        sink:         str,
        source:       Optional[str] = None,
        severity:     Optional[Severity] = None,
    ) -> Finding:
        return Finding(
            id       = f"{rule.rule_id}-{lineno:04d}",
            rule_id  = rule.rule_id,
            severity = severity if severity is not None else rule._severity,
            file     = filepath,
            line     = lineno,
            snippet  = self._snippet(source_lines, lineno),
            sink     = sink,
            source   = source,
        )


# ── CallMatcher ───────────────────────────────────────────────────────────────

class CallMatcher(Matcher):
    """Match bare function calls by name (eval, exec, compile, …).

    Walks the entire AST and flags every ``ast.Call`` whose function is a
    plain Name node matching one of the configured function names.
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._functions: set[str] = set(cfg["functions"])

    def match(self, tree, source_lines, filepath, rule) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in self._functions
            ):
                findings.append(
                    self._finding(rule, filepath, source_lines, node.lineno, node.func.id)
                )
        return findings


# ── TaintMatcher ──────────────────────────────────────────────────────────────

def _has_shell_true(call: ast.Call) -> bool:
    return any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in call.keywords
    )


_SAFE_YAML_LOADERS: frozenset[str] = frozenset(
    {"SafeLoader", "BaseLoader", "CSafeLoader"}
)


def _yaml_load_unsafe(call: ast.Call) -> bool:
    """Return True when ``yaml.load()`` is called without a safe Loader kwarg."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "load"):
        return False
    chain = _attr_chain(func.value)
    if not (chain and chain[-1] == "yaml"):
        return False
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader_name = (
                kw.value.attr if isinstance(kw.value, ast.Attribute)
                else kw.value.id  if isinstance(kw.value, ast.Name)
                else None
            )
            if loader_name in _SAFE_YAML_LOADERS:
                return False
    return True  # no Loader kwarg → uses unsafe default


class TaintMatcher(Matcher):
    """Intra-function taint flow from user-controlled sources to dangerous sinks.

    Covers three distinct patterns unified by configuration:

    CMD-INJECT  — module.function sinks, first-arg check, shell=True variants
    DESER-RCE   — first-arg check + module-level scan + yaml.load safety
    FLOW-WEB    — any-arg check, includes bare function sinks (eval, exec, …)

    Configuration keys
    ──────────────────
    sinks              list of sink defs; each has module?, function,
                       require_shell_true? (bool, default false)
    check_any_arg      flag when any argument is tainted (FLOW-WEB); default
                       false → only the first positional argument is checked
    module_level_check also scan module-scope calls for direct source args
    yaml_unsafe_check  flag yaml.load() without a safe Loader kwarg
    """

    def __init__(self, cfg: Dict[str, Any], sources_vocab: Dict[str, Any]) -> None:
        source_key = cfg.get("sources", "web_inputs")
        self._src           = _Sources(sources_vocab[source_key])
        self._check_any_arg = bool(cfg.get("check_any_arg",      False))
        self._module_level  = bool(cfg.get("module_level_check", False))
        self._yaml_unsafe   = bool(cfg.get("yaml_unsafe_check",  False))

        # Separate always-dangerous sinks from shell=True-only sinks
        self._always: dict[tuple[str | None, str], str] = {}
        self._shell:  dict[tuple[str | None, str], str] = {}

        for s in cfg.get("sinks", []):
            mod   = s.get("module")   # None → bare call
            func  = s["function"]
            label = f"{mod}.{func}" if mod else func
            if s.get("require_shell_true"):
                self._shell[(mod, func)]  = label
            else:
                self._always[(mod, func)] = label

    # ── Sink resolution ───────────────────────────────────────────────────────

    def _sink_label(self, call: ast.Call) -> str | None:
        """Return a sink label if this call is a configured sink, else None."""
        func = call.func
        if isinstance(func, ast.Name):
            return self._always.get((None, func.id))
        if isinstance(func, ast.Attribute):
            chain = _attr_chain(func.value)
            mod   = chain[-1] if chain else ""
            label = self._always.get((mod, func.attr))
            if label:
                return label
            shell_label = self._shell.get((mod, func.attr))
            if shell_label and _has_shell_true(call):
                return f"{shell_label}(shell=True)"
        return None

    # ── Matcher entry point ───────────────────────────────────────────────────

    def match(self, tree, source_lines, filepath, rule) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath, rule))
        if self._module_level:
            findings.extend(self._check_module(tree, source_lines, filepath, rule))
        return findings

    # ── Per-function taint scan ───────────────────────────────────────────────

    def _check_fn(self, func, source_lines, filepath, rule) -> List[Finding]:
        tainted, _ = self._src.collect_taint(func)
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue

            label = self._sink_label(node)
            if label:
                if self._check_any_arg:
                    arg_names = {n for arg in node.args    for n in _names(arg)}
                    arg_names |= {n for kw  in node.keywords for n in _names(kw.value)}
                    hit = arg_names & tainted.keys()
                    if hit:
                        seen.add(node.lineno)
                        source = ", ".join(sorted(tainted[n] for n in hit))
                        findings.append(
                            self._finding(rule, filepath, source_lines, node.lineno, label, source)
                        )
                else:
                    arg = node.args[0] if node.args else None
                    if arg and self._src.is_tainted(arg, tainted):
                        seen.add(node.lineno)
                        findings.append(
                            self._finding(rule, filepath, source_lines, node.lineno, label)
                        )
                continue

            # Special case: yaml.load without a safe Loader
            if self._yaml_unsafe and _yaml_load_unsafe(node):
                arg = node.args[0] if node.args else None
                if arg and self._src.is_tainted(arg, tainted):
                    seen.add(node.lineno)
                    findings.append(
                        self._finding(
                            rule, filepath, source_lines, node.lineno, "yaml.load(unsafe)"
                        )
                    )

        return findings

    # ── Module-level scan (DESER-RCE) ─────────────────────────────────────────

    def _check_module(self, tree, source_lines, filepath, rule) -> List[Finding]:
        """Flag direct source-expression args at module scope (no function context)."""
        findings: List[Finding] = []
        seen: set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            label = self._sink_label(node)
            if label:
                arg = node.args[0] if node.args else None
                if arg and self._src.is_source(arg):
                    seen.add(node.lineno)
                    findings.append(
                        self._finding(rule, filepath, source_lines, node.lineno, label)
                    )
        return findings


# ── AssignTrackMatcher ────────────────────────────────────────────────────────

class AssignTrackMatcher(Matcher):
    """Track raw network bytes flowing into a pickle deserialiser.

    Two-pass approach per scope (module body or function body):
      1. Collect variable names assigned from network-receive expressions.
      2. Flag pickle/dill calls whose first arg is either a direct network
         expression or one of the collected variables.

    Operates at module level *and* inside every function body.
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._recv_methods: set[str] = set(cfg["network_recv_methods"])
        self._http_attrs:   set[str] = set(cfg["http_body_attrs"])
        self._http_methods: set[str] = set(cfg["http_body_methods"])
        self._sink_pairs:   set[tuple[str, str]] = {
            (s["module"], s["function"]) for s in cfg["sink_pairs"]
        }

    def _is_network_expr(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute):
                return expr.func.attr in (self._recv_methods | self._http_methods)
        if isinstance(expr, ast.Attribute):
            return expr.attr in self._http_attrs
        return False

    def _collect_net_vars(self, body: list) -> Set[str]:
        net_vars: Set[str] = set()
        for node in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(node, ast.Assign) and self._is_network_expr(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        net_vars.add(target.id)
        return net_vars

    def _pair(self, func_node: ast.expr) -> tuple[str, str] | None:
        if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            return (func_node.value.id, func_node.attr)
        return None

    def match(self, tree, source_lines, filepath, rule) -> List[Finding]:
        findings: List[Finding] = []
        # Analyse module scope plus each function body as independent scopes
        scopes: list[list] = [tree.body]   # type: ignore[attr-defined]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(node.body)

        for scope in scopes:
            net_vars = self._collect_net_vars(scope)
            for node in ast.walk(ast.Module(body=scope, type_ignores=[])):
                if not isinstance(node, ast.Call):
                    continue
                pair = self._pair(node.func) if isinstance(node.func, ast.Attribute) else None
                if pair not in self._sink_pairs or not node.args:
                    continue
                arg = node.args[0]
                if self._is_network_expr(arg) or (
                    isinstance(arg, ast.Name) and arg.id in net_vars
                ):
                    findings.append(
                        self._finding(
                            rule, filepath, source_lines, node.lineno,
                            f"{pair[0]}.{pair[1]}", "network socket",
                        )
                    )
        return findings


# ── DecoratorMatcher ──────────────────────────────────────────────────────────

class DecoratorMatcher(Matcher):
    """Detect dangerous or dynamic expressions used as function/class decorators.

    Three sub-patterns (each with an independent severity):
      @eval                     bare dangerous name              HIGH
      @eval(non_literal_arg)    dangerous name with dynamic arg  HIGH
      @app.route(non_literal)   web-route with dynamic path      MEDIUM
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._dangerous: set[str] = set(cfg["dangerous_names"])
        self._routes:    set[str] = set(cfg["route_names"])

    def _dec_name(self, dec: ast.expr) -> str | None:
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                return dec.func.id
            if isinstance(dec.func, ast.Attribute):
                return dec.func.attr
        return None

    @staticmethod
    def _is_dynamic(arg: ast.expr) -> bool:
        return not isinstance(arg, (ast.Constant, ast.JoinedStr))

    def match(self, tree, source_lines, filepath, rule) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            for dec in node.decorator_list:
                f = self._check_decorator(dec, source_lines, filepath, rule)
                if f:
                    findings.append(f)
        return findings

    def _check_decorator(
        self, dec: ast.expr, source_lines: List[str], filepath: str, rule: Any
    ) -> Finding | None:
        name = self._dec_name(dec)
        if name is None:
            return None

        # @eval / @exec — bare dangerous name
        if isinstance(dec, ast.Name) and name in self._dangerous:
            return self._finding(
                rule, filepath, source_lines, dec.lineno,
                f"@{name}", severity=Severity.HIGH,
            )

        if isinstance(dec, ast.Call):
            # @eval(dynamic_expr)
            if name in self._dangerous and any(self._is_dynamic(a) for a in dec.args):
                return self._finding(
                    rule, filepath, source_lines, dec.lineno,
                    f"@{name}(dynamic_arg)", severity=Severity.HIGH,
                )
            # @app.route(user_variable)
            if name in self._routes and dec.args and self._is_dynamic(dec.args[0]):
                return self._finding(
                    rule, filepath, source_lines, dec.lineno,
                    f"@{name}(dynamic_route)", severity=Severity.MEDIUM,
                )
        return None


# ── FileScopeMatcher ──────────────────────────────────────────────────────────

class FileScopeMatcher(Matcher):
    """File-restricted pattern matching.

    Only processes files whose base name is in the ``filenames`` list.
    Supports two non-exclusive sub-patterns:

    check_setup_kwargs    flag ``setup(cmdclass=…)`` etc. in setup.py
    danger_call_names     flag import-time calls by name in __init__.py / setup.py
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._filenames:     set[str] = set(cfg["filenames"])
        self._setup_kwargs:  set[str] = set(cfg.get("check_setup_kwargs", []))
        self._danger_calls:  set[str] = set(cfg.get("danger_call_names",  []))

    @staticmethod
    def _is_setup_call(call: ast.Call) -> bool:
        if isinstance(call.func, ast.Name):
            return call.func.id == "setup"
        if isinstance(call.func, ast.Attribute):
            return call.func.attr == "setup"
        return False

    @staticmethod
    def _call_name(call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    def match(self, tree, source_lines, filepath, rule) -> List[Finding]:
        if Path(filepath).name not in self._filenames:
            return []
        findings: List[Finding] = []
        if self._setup_kwargs:
            findings.extend(self._check_setup(tree, source_lines, filepath, rule))
        if self._danger_calls:
            findings.extend(self._check_import_time(tree, source_lines, filepath, rule))
        return findings

    def _check_setup(self, tree, source_lines, filepath, rule) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_setup_call(node):
                for kw in node.keywords:
                    if kw.arg in self._setup_kwargs:
                        findings.append(
                            self._finding(
                                rule, filepath, source_lines, node.lineno,
                                f"setup({kw.arg}=...)",
                            )
                        )
        return findings

    def _check_import_time(self, tree, source_lines, filepath, rule) -> List[Finding]:
        """Scan only module-scope statements (not inside defs or classes)."""
        findings: List[Finding] = []
        for stmt in ast.iter_child_nodes(tree):
            for call in ast.walk(stmt):
                if isinstance(call, ast.Call):
                    name = self._call_name(call)
                    if name in self._danger_calls:
                        findings.append(
                            self._finding(rule, filepath, source_lines, call.lineno, name)
                        )
        return findings


# ── SaveHeuristicMatcher ──────────────────────────────────────────────────────

class SaveHeuristicMatcher(Matcher):
    """File upload saved without extension or type validation.

    Flags two patterns inside every function body:

    1. ``file_obj.save(tainted_path)``  — Flask FileStorage  → CRITICAL
    2. ``open(tainted_path, "w…")``     — Django / FastAPI   → HIGH

    A finding is only emitted when none of the configured ``safe_patterns``
    (e.g. ``splitext``, ``secure_filename``) appear in the surrounding
    ``context_lines`` lines of source code.
    """

    def __init__(self, cfg: Dict[str, Any], sources_vocab: Dict[str, Any]) -> None:
        source_key          = cfg.get("sources", "web_inputs")
        self._src           = _Sources(sources_vocab[source_key])
        self._save_methods  = set(cfg.get("save_methods",   ["save"]))
        self._write_fns     = set(cfg.get("write_functions", ["open"]))
        self._safe_patterns = frozenset(cfg.get("safe_patterns", []))
        self._context_lines = int(cfg.get("context_lines", 15))

    def _lacks_validation(self, lineno: int, source_lines: List[str]) -> bool:
        before = self._context_lines - 5
        start  = max(0, lineno - 1 - before)
        end    = min(len(source_lines), lineno + 5)
        window = "\n".join(source_lines[start:end])
        return not any(p in window for p in self._safe_patterns)

    def match(self, tree, source_lines, filepath, rule) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath, rule))
        return findings

    def _check_fn(self, func, source_lines, filepath, rule) -> List[Finding]:
        tainted, _ = self._src.collect_taint(func)
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue

            # Pattern 1: file_obj.save(tainted_path)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in self._save_methods
            ):
                path = node.args[0] if node.args else None
                if path and self._src.is_tainted(path, tainted):
                    if self._lacks_validation(node.lineno, source_lines):
                        seen.add(node.lineno)
                        findings.append(
                            self._finding(
                                rule, filepath, source_lines, node.lineno,
                                "FileStorage.save(user_controlled_path)",
                                severity=Severity.CRITICAL,
                            )
                        )
                continue

            # Pattern 2: open(tainted_path, "wb")
            method = (
                node.func.id  if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute)
                else None
            )
            if method in self._write_fns and len(node.args) >= 2:
                path      = node.args[0]
                mode_node = node.args[1]
                if (
                    isinstance(mode_node, ast.Constant)
                    and "w" in str(mode_node.value)
                    and self._src.is_tainted(path, tainted)
                    and self._lacks_validation(node.lineno, source_lines)
                ):
                    seen.add(node.lineno)
                    findings.append(
                        self._finding(
                            rule, filepath, source_lines, node.lineno,
                            "open(user_path, 'wb') — unvalidated upload",
                            severity=Severity.HIGH,
                        )
                    )

        return findings
