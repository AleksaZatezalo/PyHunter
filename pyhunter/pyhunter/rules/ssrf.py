"""Rule: Server-Side Request Forgery — user-controlled URL passed to HTTP clients."""
from __future__ import annotations

import ast
from typing import List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_TAINT_SOURCES: set[tuple[str, ...]] = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "values"), ("sys", "argv"),
    ("os", "environ"),
}
_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {"get", "get_json", "get_data"}

# HTTP-client sinks — (module_or_object, method)
_HTTP_SINKS: set[tuple[str | None, str]] = {
    ("requests", "get"),
    ("requests", "post"),
    ("requests", "put"),
    ("requests", "patch"),
    ("requests", "delete"),
    ("requests", "head"),
    ("requests", "options"),
    ("requests", "request"),
    ("urllib", "urlopen"),
    ("urllib2", "urlopen"),
    ("urllib.request", "urlopen"),
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "put"),
    ("httpx", "patch"),
    ("httpx", "delete"),
    ("httpx", "request"),
    ("aiohttp", "get"),
    ("aiohttp", "post"),
    ("aiohttp", "request"),
    (None, "urlopen"),
    (None, "fetch"),
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


def _is_taint_source(node: ast.expr) -> bool:
    chain = _attr_chain(node)
    if chain and any(chain[: len(s)] == s for s in _TAINT_SOURCES):
        return True
    if isinstance(node, ast.Subscript) and _is_taint_source(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _SOURCE_CALLS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in _SOURCE_METHODS and _is_taint_source(func.value):
            return True
    return False


def _names(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _sink_key(call: ast.Call) -> tuple[str | None, str] | None:
    func = call.func
    if isinstance(func, ast.Name):
        return (None, func.id)
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return (func.value.id, func.attr)
        # e.g. urllib.request.urlopen → chain is (urllib, request, urlopen)
        chain = _attr_chain(func.value)
        if chain:
            return (".".join(chain), func.attr)
    return None


class SSRFRule(BaseRule):
    rule_id     = "SSRF"
    description = "User-controlled URL passed to an HTTP client — potential Server-Side Request Forgery"

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
        tainted: dict[str, str] = {}
        findings: List[Finding] = []
        seen: set[int] = set()

        for stmt in ast.walk(func):
            # Taint propagation
            if isinstance(stmt, ast.Assign):
                if _is_taint_source(stmt.value) or bool(_names(stmt.value) & tainted.keys()):
                    for target in stmt.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name):
                                tainted[n.id] = "user input"

            # Sink detection
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                key = _sink_key(node)
                if key is None:
                    continue

                # Normalise the key for matching
                module, method = key
                matched = (module, method) in _HTTP_SINKS or (None, method) in _HTTP_SINKS

                if not matched:
                    continue
                if node.lineno in seen:
                    continue

                # Check first positional arg (URL) or 'url' kwarg
                url_arg = node.args[0] if node.args else None
                for kw in node.keywords:
                    if kw.arg == "url":
                        url_arg = kw.value

                if url_arg is None:
                    continue

                if _is_taint_source(url_arg) or bool(_names(url_arg) & tainted.keys()):
                    seen.add(node.lineno)
                    sink_label = f"{module}.{method}" if module else method
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="user input",
                        sink=sink_label,
                    ))

        return findings
