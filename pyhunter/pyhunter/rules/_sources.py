"""Shared taint-source vocabulary used by every detection rule.

This module is the single source of truth for:
  - Which attribute chains constitute user-controlled input (ALL_CHAINS)
  - Which method names return user-controlled data (SOURCE_METHODS)
  - Which standalone functions return user-controlled data (SOURCE_FUNCS)
  - FastAPI dependency-injection annotations (FASTAPI_USER_ANNOTATIONS)
  - Helper functions for attribute-chain inspection and taint propagation

Rules import from here instead of duplicating framework knowledge.
"""
from __future__ import annotations

import ast
from typing import Set

# ── Per-framework request attribute chains ────────────────────────────────────

_FLASK: set[tuple[str, ...]] = {
    ("request", "args"),    ("request", "form"),    ("request", "json"),
    ("request", "data"),    ("request", "files"),   ("request", "values"),
    ("request", "headers"), ("request", "cookies"),
}

_DJANGO: set[tuple[str, ...]] = {
    ("request", "GET"),     ("request", "POST"),    ("request", "body"),
    ("request", "FILES"),   ("request", "headers"), ("request", "COOKIES"),
    ("request", "META"),
    # Django REST Framework
    ("request", "data"),    ("request", "query_params"),
}

_STARLETTE: set[tuple[str, ...]] = {
    ("request", "query_params"), ("request", "path_params"),
}

# Tornado RequestHandler: self.request.body / .arguments / etc.
_TORNADO: set[tuple[str, ...]] = {
    ("self", "request", "body"),
    ("self", "request", "arguments"),
    ("self", "request", "body_arguments"),
    ("self", "request", "query_arguments"),
    ("self", "request", "files"),
}

# CLI / environment sources
_CLI: set[tuple[str, ...]] = {
    ("sys", "argv"),
    ("os",  "environ"),
}

ALL_CHAINS: set[tuple[str, ...]] = _FLASK | _DJANGO | _STARLETTE | _TORNADO | _CLI

# Methods on request/self that return user-controlled data
SOURCE_METHODS: set[str] = {
    "get", "get_json", "get_data", "getlist", "getfirst",
    # Tornado RequestHandler
    "get_argument", "get_query_argument", "get_body_argument", "get_arguments",
    # Starlette async methods
    "body", "json", "form", "stream",
    # os.environ
    "getenv",
}

SOURCE_FUNCS: set[str] = {"input"}

# FastAPI annotation names that mark a parameter as user-supplied
FASTAPI_USER_ANNOTATIONS: set[str] = {
    "Query", "Path", "Body", "Form", "File", "Header", "Cookie",
}

# FastAPI route-decorator method names
FASTAPI_ROUTE_METHODS: set[str] = {
    "get", "post", "put", "patch", "delete", "head", "options",
    "websocket", "api_route",
}


# ── AST helpers ───────────────────────────────────────────────────────────────

def attr_chain(node: ast.expr) -> tuple[str, ...]:
    """Walk a chain of Attribute accesses and return the parts as a tuple.

    Example: ``request.args.get`` → ``("request", "args", "get")``
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def names(node: ast.expr) -> Set[str]:
    """Return all Name ids referenced anywhere inside *node*."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


# ── Taint source detection ────────────────────────────────────────────────────

def _is_fastapi_user_param(default: ast.expr) -> bool:
    if not isinstance(default, ast.Call):
        return False
    func = default.func
    if isinstance(func, ast.Name):
        return func.id in FASTAPI_USER_ANNOTATIONS
    if isinstance(func, ast.Attribute):
        return func.attr in FASTAPI_USER_ANNOTATIONS
    return False


def fastapi_tainted_params(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Return parameter names annotated with a FastAPI user-input dependency."""
    tainted: set[str] = set()
    args = func.args

    n_args     = len(args.args)
    n_defaults = len(args.defaults)
    for i, arg in enumerate(args.args):
        default_idx = i - (n_args - n_defaults)
        if default_idx >= 0 and _is_fastapi_user_param(args.defaults[default_idx]):
            tainted.add(arg.arg)

    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None and _is_fastapi_user_param(default):
            tainted.add(arg.arg)

    return tainted


def is_source(node: ast.expr) -> bool:
    """Return True if *node* directly reads from a user-controlled source.

    Covers Flask, Django, DRF, FastAPI, Tornado, Starlette, and CLI sources
    (sys.argv, os.environ).
    """
    # Attribute chain: request.args, request.GET, self.request.body, sys.argv …
    chain = attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in ALL_CHAINS):
        return True

    # Subscript on a source: request.args["key"], os.environ["HOME"]
    if isinstance(node, ast.Subscript) and is_source(node.value):
        return True

    if isinstance(node, ast.Call):
        func = node.func

        # Standalone source functions: input()
        if isinstance(func, ast.Name) and func.id in SOURCE_FUNCS:
            return True

        # Method calls: request.get("key"), self.get_argument("q"), os.environ.get("K")
        if isinstance(func, ast.Attribute) and func.attr in SOURCE_METHODS:
            obj_chain = attr_chain(func.value)
            if obj_chain and obj_chain[0] in ("request", "self", "os"):
                return True

    return False


# ── Taint propagation ─────────────────────────────────────────────────────────

def propagate(
    stmt: ast.stmt,
    tainted: dict[str, str],
    seed_names: set[str] | None = None,
) -> None:
    """Examine one statement and extend *tainted* with newly tainted names."""
    seed = seed_names or set()
    rhs: ast.expr | None = None
    targets: list[ast.expr] = []

    if isinstance(stmt, ast.Assign):
        rhs, targets = stmt.value, stmt.targets
    elif isinstance(stmt, ast.AnnAssign) and stmt.value:
        rhs, targets = stmt.value, [stmt.target]
    elif isinstance(stmt, ast.AugAssign):
        rhs, targets = stmt.value, [stmt.target]

    if rhs is None:
        return

    # Unwrap `await expr` — Starlette / FastAPI use `await request.form()`
    if isinstance(rhs, ast.Await):
        rhs = rhs.value

    rhs_names = names(rhs)
    if is_source(rhs) or bool(rhs_names & (tainted.keys() | seed)):
        desc = "user input"
        if is_source(rhs):
            chain = attr_chain(rhs)
            if chain:
                desc = ".".join(chain)
        for target in targets:
            for n in ast.walk(target):
                if isinstance(n, ast.Name):
                    tainted[n.id] = desc


def collect_taint(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[dict[str, str], set[str]]:
    """Walk *func* and return ``(tainted_vars, fastapi_params)``.

    ``tainted_vars`` maps variable name → source description.
    ``fastapi_params`` is the set of FastAPI route parameter names.
    """
    fp      = fastapi_tainted_params(func)
    tainted = {p: "fastapi_param" for p in fp}

    for stmt in ast.walk(func):
        propagate(stmt, tainted, fp)

    return tainted, fp


def is_tainted_expr(node: ast.expr, tainted: dict[str, str]) -> bool:
    """Return True if *node* is a source or references a tainted variable."""
    return is_source(node) or bool(names(node) & tainted.keys())
