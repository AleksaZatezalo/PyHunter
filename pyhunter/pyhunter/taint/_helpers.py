"""Shared AST helpers, source/sink/sanitizer tables for the taint package.

Extracted into a separate module so that both taint/__init__.py (TaintEngine)
and taint/cfg.py (CFG builder) can import from here without creating a
circular dependency.
"""
from __future__ import annotations

import ast
from typing import Set


# ── Source / sink / sanitizer tables ─────────────────────────────────────────

_SOURCE_CHAINS: set[tuple[str, ...]] = {
    # Flask
    ("request", "args"),    ("request", "form"),    ("request", "json"),
    ("request", "data"),    ("request", "files"),   ("request", "values"),
    ("request", "headers"), ("request", "cookies"),
    # Django / DRF
    ("request", "GET"),     ("request", "POST"),    ("request", "body"),
    ("request", "FILES"),   ("request", "META"),    ("request", "COOKIES"),
    ("request", "query_params"),
    # Tornado
    ("self", "request", "body"),
    ("self", "request", "arguments"),
    ("self", "request", "body_arguments"),
    ("self", "request", "query_arguments"),
    ("self", "request", "files"),
    # Starlette
    ("request", "query_params"), ("request", "path_params"),
    # CLI / environment
    ("sys", "argv"),
    ("os",  "environ"),
}

_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {
    "get", "get_json", "get_data", "getlist", "getfirst",
    "get_argument", "get_query_argument", "get_body_argument", "get_arguments",
    "body", "json", "form", "stream", "getenv",
}

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

_SANITIZER_KEYS: set[tuple[str | None, str]] = {
    ("html",       "escape"),
    ("shlex",      "quote"),
    ("re",         "escape"),
    ("bleach",     "clean"),
    ("markupsafe", "escape"),
    (None,         "escape"),
    (None,         "quote"),
    (None,         "sanitize"),
    (None,         "clean"),
}


# ── AST helpers ───────────────────────────────────────────────────────────────

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
        if isinstance(func, ast.Attribute) and func.attr in _SOURCE_METHODS:
            obj = _attr_chain(func.value)
            if obj and obj[0] in ("request", "self", "os"):
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


def _call_key(call: ast.Call) -> tuple[str | None, str] | None:
    if isinstance(call.func, ast.Name):
        return (None, call.func.id)
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _unpack_names(target: ast.expr) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def _call_arg_names(call: ast.Call) -> Set[str]:
    names: Set[str] = set()
    for arg in call.args:
        names |= _names(arg)
    for kw in call.keywords:
        names |= _names(kw.value)
    return names
