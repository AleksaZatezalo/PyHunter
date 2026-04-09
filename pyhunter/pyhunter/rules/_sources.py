"""
Centralised taint-source and taint-tracking helpers for all supported
Python web frameworks: Flask, Django (+DRF), FastAPI, Tornado, Starlette.

Import this module from every rule instead of duplicating the logic.
"""
from __future__ import annotations

import ast
from typing import Set

# ── Per-framework request attribute chains ────────────────────────────────────

_FLASK: set[tuple[str, ...]] = {
    ("request", "args"),   ("request", "form"),    ("request", "json"),
    ("request", "data"),   ("request", "files"),   ("request", "values"),
    ("request", "headers"), ("request", "cookies"),
}

_DJANGO: set[tuple[str, ...]] = {
    ("request", "GET"),    ("request", "POST"),    ("request", "body"),
    ("request", "FILES"),  ("request", "headers"), ("request", "COOKIES"),
    ("request", "META"),
    # Django REST Framework
    ("request", "data"),   ("request", "query_params"),
}

_STARLETTE: set[tuple[str, ...]] = {
    ("request", "query_params"), ("request", "path_params"),
}

ALL_CHAINS: set[tuple[str, ...]] = _FLASK | _DJANGO | _STARLETTE

# Methods on request/self that return user-controlled data
SOURCE_METHODS: set[str] = {
    "get", "get_json", "get_data", "getlist", "getfirst",
    # Tornado RequestHandler
    "get_argument", "get_query_argument", "get_body_argument", "get_arguments",
    # Starlette async methods
    "body", "json", "form", "stream",
}

SOURCE_FUNCS: set[str] = {"input"}

# FastAPI: these annotation names indicate user-supplied parameters
FASTAPI_USER_ANNOTATIONS: set[str] = {
    "Query", "Path", "Body", "Form", "File", "Header", "Cookie",
}

# FastAPI route decorator method names (on app / router / APIRouter objects)
FASTAPI_ROUTE_METHODS: set[str] = {
    "get", "post", "put", "patch", "delete", "head", "options",
    "websocket", "api_route",
}


# ── AST helpers ───────────────────────────────────────────────────────────────

def attr_chain(node: ast.expr) -> tuple[str, ...]:
    """Walk a chain of Attribute accesses and return the parts as a tuple."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def names(node: ast.expr) -> Set[str]:
    """Return the set of all Name ids referenced anywhere inside node."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


# ── Taint source detection ────────────────────────────────────────────────────

def _is_fastapi_user_param(default: ast.expr) -> bool:
    """Return True if a parameter default is a FastAPI user-input annotation."""
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
    """
    Return names of parameters that receive user-controlled input via FastAPI
    annotations (Query/Path/Body/Form/File/Header/Cookie).

    We do NOT require a route decorator — any function whose parameter defaults
    use these annotations is treating those params as user input.
    """

    tainted: set[str] = set()
    args = func.args

    # Positional args with defaults (defaults align to the LAST N args)
    n_args = len(args.args)
    n_defaults = len(args.defaults)
    for i, arg in enumerate(args.args):
        default_idx = i - (n_args - n_defaults)
        if default_idx >= 0 and _is_fastapi_user_param(args.defaults[default_idx]):
            tainted.add(arg.arg)

    # Keyword-only args
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None and _is_fastapi_user_param(default):
            tainted.add(arg.arg)

    return tainted


def is_source(node: ast.expr) -> bool:
    """
    Return True if node directly reads from a user-controlled request source
    across Flask, Django, DRF, Tornado, and Starlette.
    """
    # Attribute chain match: request.args, request.GET, self.request.body, …
    chain = attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in ALL_CHAINS):
        return True

    # Subscript on a source: request.args["key"], request.GET["q"]
    if isinstance(node, ast.Subscript) and is_source(node.value):
        return True

    if isinstance(node, ast.Call):
        func = node.func

        # Standalone source functions: input()
        if isinstance(func, ast.Name) and func.id in SOURCE_FUNCS:
            return True

        # Method calls: request.get("key"), self.get_argument("q"), …
        if isinstance(func, ast.Attribute) and func.attr in SOURCE_METHODS:
            obj_chain = attr_chain(func.value)
            # request.get / request.get_json / etc.
            if obj_chain and obj_chain[0] == "request":
                return True
            # self.get_argument / self.get_query_argument (Tornado)
            if obj_chain and obj_chain[0] == "self":
                return True

    return False


# ── Taint propagation ─────────────────────────────────────────────────────────

def propagate(
    stmt: ast.stmt,
    tainted: dict[str, str],
    seed_names: set[str] | None = None,
) -> None:
    """
    Examine a single statement and add newly tainted variable names to *tainted*.
    *seed_names* are names already known tainted (e.g. FastAPI route params).
    """
    seed = seed_names or set()

    rhs: ast.expr | None = None
    targets: list[ast.expr] = []

    if isinstance(stmt, ast.Assign):
        rhs = stmt.value
        targets = stmt.targets
    elif isinstance(stmt, ast.AnnAssign) and stmt.value:
        rhs = stmt.value
        targets = [stmt.target]
    elif isinstance(stmt, ast.AugAssign):
        rhs = stmt.value
        targets = [stmt.target]

    if rhs is None:
        return

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
    """
    Walk a function's body and return (tainted_dict, fastapi_params).
    tainted_dict maps variable name → source description.
    fastapi_params is the set of FastAPI route parameter names.
    """
    fp = fastapi_tainted_params(func)
    tainted: dict[str, str] = {p: "fastapi_param" for p in fp}

    for stmt in ast.walk(func):
        propagate(stmt, tainted, fp)

    return tainted, fp


def is_tainted_expr(node: ast.expr, tainted: dict[str, str]) -> bool:
    """Return True if node is a source or references a tainted variable."""
    return is_source(node) or bool(names(node) & tainted.keys())
