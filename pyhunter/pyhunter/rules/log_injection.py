"""Rule: log injection and sensitive data exposure via logging calls."""
from __future__ import annotations

import ast
from typing import List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}

_TAINT_SOURCES: set[tuple[str, ...]] = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "values"), ("sys", "argv"),
    ("os", "environ"),
}
_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {"get", "get_json", "get_data"}

_SENSITIVE_KEYWORDS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "credential", "credentials",
    "auth_token", "ssn", "credit_card", "cvv", "pin", "private",
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


def _is_log_call(node: ast.Call) -> bool:
    func = node.func
    return isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS


def _sensitive_name_hit(names: Set[str]) -> str | None:
    for name in names:
        lower = name.lower()
        for kw in _SENSITIVE_KEYWORDS:
            if kw in lower:
                return name
    return None


class LogInjectionRule(BaseRule):
    rule_id     = "LOG-INJECT"
    description = "User input or sensitive data (passwords, tokens) flowing into logging calls"

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
        tainted: set[str] = set()
        findings: List[Finding] = []
        seen: set[int] = set()

        for stmt in ast.walk(func):
            # Track taint assignments
            if isinstance(stmt, ast.Assign) and _is_taint_source(stmt.value):
                for target in stmt.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            tainted.add(n.id)

            # Check logging calls
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call) or not _is_log_call(node):
                    continue
                if node.lineno in seen:
                    continue

                arg_names = {n for arg in node.args for n in _names(arg)}
                arg_names |= {n for kw in node.keywords for n in _names(kw.value)}

                if any(_is_taint_source(arg) for arg in node.args) or (arg_names & tainted):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="user input",
                        sink="logging",
                    ))
                elif hit := _sensitive_name_hit(arg_names):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source=hit,
                        sink="logging",
                    ))

        return findings
