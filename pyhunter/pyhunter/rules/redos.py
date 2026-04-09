"""Rule: ReDoS — user-controlled regex pattern or catastrophic backtracking."""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_RE_FUNCS = {"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"}

_TAINT_SOURCES: set[tuple[str, ...]] = {
    ("request", "args"), ("request", "form"), ("request", "json"),
    ("request", "data"), ("request", "values"), ("sys", "argv"),
}
_SOURCE_CALLS   = {"input"}
_SOURCE_METHODS = {"get", "get_json", "get_data"}

# Patterns indicative of catastrophic backtracking (e.g. (a+)+ or (.*)*  or nested quantifiers)
_CATASTROPHIC = re.compile(
    r"(\([^)]*[+*][^)]*\)[+*]"      # (a+)+ / (a*)* style
    r"|(\([^)]*\)\?){3,}"            # (a?)? repeated ≥ 3 times
    r"|\(\?:.*[+*].*\)[+*]"         # (?:...+)+ style
    r"|\.[\*\+]\{[^}]*\}"            # .* followed by complex quantifier
    r"|\[.*\]\+\*)"                  # [x]+*
    , re.VERBOSE,
)


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


def _names(node: ast.expr) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_re_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _RE_FUNCS:
        chain = _attr_chain(func.value)
        return bool(chain) and chain[-1] == "re"
    return False


class ReDoSRule(BaseRule):
    rule_id     = "REDOS"
    description = (
        "User-controlled regex pattern or catastrophic backtracking pattern detected — "
        "potential Regular Expression Denial of Service"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function(node, source_lines, filepath))
        # Also catch module-level catastrophic patterns
        findings.extend(self._check_static_patterns(tree, source_lines, filepath))
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
            if isinstance(stmt, ast.Assign) and _is_taint_source(stmt.value):
                for target in stmt.targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            tainted.add(n.id)

            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call) or not _is_re_call(node):
                    continue
                if node.lineno in seen or not node.args:
                    continue
                pattern_arg = node.args[0]
                if _is_taint_source(pattern_arg) or bool(_names(pattern_arg) & tainted):
                    seen.add(node.lineno)
                    func_node = node.func
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="user input",
                        sink=f"re.{func_node.attr}" if isinstance(func_node, ast.Attribute) else "re",
                    ))

        return findings

    def _check_static_patterns(
        self,
        tree: ast.AST,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        """Flag literal regex strings with catastrophic backtracking patterns."""
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_re_call(node):
                continue
            if not node.args or node.lineno in seen:
                continue
            pattern_arg = node.args[0]
            if isinstance(pattern_arg, ast.Constant) and isinstance(pattern_arg.value, str):
                if _CATASTROPHIC.search(pattern_arg.value):
                    seen.add(node.lineno)
                    func_node = node.func
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source="static pattern",
                        sink=f"re.{func_node.attr}" if isinstance(func_node, ast.Attribute) else "re",
                    ))

        return findings
