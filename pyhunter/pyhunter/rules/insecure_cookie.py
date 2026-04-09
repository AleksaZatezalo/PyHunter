"""Rule: insecure cookie flags (missing httponly, secure, or samesite)."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Methods that set cookies
_SET_COOKIE_METHODS = {"set_cookie", "set_signed_cookie"}

# Django settings assignments that weaken cookie security
_DJANGO_INSECURE_SETTINGS = {
    "SESSION_COOKIE_SECURE":   False,
    "SESSION_COOKIE_HTTPONLY": False,
    "CSRF_COOKIE_SECURE":      False,
    "CSRF_COOKIE_HTTPONLY":    False,
}


def _kw_bool(keywords: list[ast.keyword], name: str) -> bool | None:
    """Return the boolean value of a keyword argument, or None if not present."""
    for kw in keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, bool):
                return kw.value.value
    return None


class InsecureCookieRule(BaseRule):
    rule_id     = "INSECURE-COOKIE"
    description = (
        "Cookie set without httponly=True, secure=True, or samesite — "
        "exposes session to XSS or network interception"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # Flask / Django response.set_cookie(...)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in _SET_COOKIE_METHODS:
                    issues = []
                    if _kw_bool(node.keywords, "httponly") is False:
                        issues.append("httponly=False")
                    elif _kw_bool(node.keywords, "httponly") is None:
                        issues.append("missing httponly")
                    if _kw_bool(node.keywords, "secure") is False:
                        issues.append("secure=False")
                    elif _kw_bool(node.keywords, "secure") is None:
                        issues.append("missing secure")
                    if issues:
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink=f"{func.attr}({', '.join(issues)})",
                        ))

            # Django settings: SESSION_COOKIE_SECURE = False
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in _DJANGO_INSECURE_SETTINGS:
                        expected_insecure = _DJANGO_INSECURE_SETTINGS[target.id]
                        if (
                            isinstance(node.value, ast.Constant)
                            and node.value.value == expected_insecure
                        ):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.MEDIUM,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=target.id,
                            ))

        return findings
