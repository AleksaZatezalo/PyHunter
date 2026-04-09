"""Rule: NoSQL / LDAP / XPath injection."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_MONGO_METHODS  = {
    "find", "find_one", "find_one_and_update", "find_one_and_delete",
    "find_one_and_replace", "count", "count_documents",
    "delete_one", "delete_many", "update_one", "update_many",
    "replace_one", "aggregate",
}
_XPATH_METHODS  = {"xpath", "XPath"}
_LDAP_METHODS   = {"search", "search_s", "search_st", "search_ext", "search_ext_s"}
_LDAP_KWARG_NAMES = {"filterstr", "search_filter", "filter"}


def _contains_name(node: ast.expr) -> bool:
    return any(isinstance(n, ast.Name) for n in ast.walk(node))


def _is_dynamic_str(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _contains_name(node)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    if isinstance(node, ast.Name):
        return True
    return False


def _dict_has_where(node: ast.expr) -> bool:
    """Return True if a dict literal contains a ``$where`` key."""
    if not isinstance(node, ast.Dict):
        return False
    return any(
        isinstance(k, ast.Constant) and k.value == "$where"
        for k in node.keys
    )


class NoSQLInjectionRule(BaseRule):
    rule_id     = "INJ-NOSQL"
    description = "NoSQL / LDAP / XPath injection via unsanitised dynamic query"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue

            lineno = node.lineno

            # MongoDB $where injection
            if func.attr in _MONGO_METHODS:
                for arg in node.args:
                    if _dict_has_where(arg) and lineno not in seen:
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink="mongodb.$where",
                        ))

            # XPath injection
            elif func.attr in _XPATH_METHODS:
                if node.args and _is_dynamic_str(node.args[0]) and lineno not in seen:
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"xpath.{func.attr}",
                    ))

            # LDAP filter injection
            elif func.attr in _LDAP_METHODS:
                filter_arg = node.args[2] if len(node.args) >= 3 else None
                for kw in node.keywords:
                    if kw.arg in _LDAP_KWARG_NAMES:
                        filter_arg = kw.value
                if filter_arg is not None and _is_dynamic_str(filter_arg) and lineno not in seen:
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"ldap.{func.attr}",
                    ))

        return findings
