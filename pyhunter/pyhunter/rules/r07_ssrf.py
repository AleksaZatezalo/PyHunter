"""Rule 07 — SSRF: Server-Side Request Forgery.

User-controlled URL passed to an HTTP client.
Flags cloud metadata endpoints (AWS/GCP/Azure IMDSv1) and Docker socket
usage as CRITICAL; other SSRF as HIGH.

Covers: requests, httpx, aiohttp, urllib, urllib2, urllib3, httplib2
across all framework request sources.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, names, is_tainted_expr, collect_taint,
)

_HTTP_METHODS = {
    "get", "post", "put", "patch", "delete", "head",
    "options", "request", "send", "urlopen", "fetch",
    "open",  # urllib.request.urlopen alias
}

# Cloud metadata and internal-only endpoints that make SSRF critical
_HIGH_VALUE_TARGETS = {
    "169.254.169.254",   # AWS / GCP / Azure IMDS
    "metadata.google",
    "metadata.internal",
    "169.254.170.2",     # ECS credentials
    "fd00:ec2::254",     # IPv6 IMDS
    "docker.sock",
    "/var/run/docker.sock",
}


def _sink_label(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr in _HTTP_METHODS:
            chain = attr_chain(func.value)
            mod = chain[-1] if chain else "?"
            return f"{mod}.{func.attr}"
    if isinstance(func, ast.Name) and func.id in _HTTP_METHODS:
        return func.id
    return None


def _url_arg(call: ast.Call) -> ast.expr | None:
    """Return the URL argument (first positional or 'url' keyword)."""
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    return None


def _is_critical_target(url_node: ast.expr) -> bool:
    """Check if a literal URL string targets a high-value SSRF endpoint."""
    if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
        return any(t in url_node.value for t in _HIGH_VALUE_TARGETS)
    if isinstance(url_node, ast.JoinedStr):
        # Check string parts of an f-string
        for part in ast.walk(url_node):
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if any(t in part.value for t in _HIGH_VALUE_TARGETS):
                    return True
    return False


class SSRFRule(BaseRule):
    rule_id     = "SSRF"
    description = (
        "User-controlled URL passed to an HTTP client — "
        "can reach cloud metadata (169.254.169.254), internal services, "
        "or the Docker socket to escalate from web process to cloud/host"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    def _check_fn(self, func, source_lines, filepath):
        tainted, _ = collect_taint(func)
        findings = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            label = _sink_label(node)
            if label is None:
                continue
            url = _url_arg(node)
            if url is None:
                continue

            if is_tainted_expr(url, tainted):
                seen.add(node.lineno)
                severity = Severity.CRITICAL if _is_critical_target(url) else Severity.HIGH
                findings.append(Finding(
                    id=f"{self.rule_id}-{node.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=severity,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    source="user input",
                    sink=label,
                ))

        return findings
