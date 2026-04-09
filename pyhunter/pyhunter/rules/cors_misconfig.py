"""Rule: CORS misconfiguration — wildcard origin with credentialed requests."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_WILDCARD = "*"

# Flask-CORS init call: CORS(app, ...) / cross_origin(...)
_CORS_FUNCS = {"CORS", "cross_origin"}

# Django CORS header library setting names
_DJANGO_CORS_SETTINGS = {
    "CORS_ALLOW_ALL_ORIGINS",        # True = wildcard
    "CORS_ORIGIN_ALLOW_ALL",         # True = wildcard (older django-cors-headers)
}


def _is_wildcard(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value == _WILDCARD


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _origins_is_wildcard(node: ast.expr) -> bool:
    """Return True if the origins/resources argument contains a wildcard."""
    if _is_wildcard(node):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_is_wildcard(elt) for elt in node.elts)
    # Dict like {r"/*": {"origins": "*"}}
    if isinstance(node, ast.Dict):
        for val in node.values:
            if isinstance(val, ast.Dict):
                for k, v in zip(val.keys, val.values):
                    if isinstance(k, ast.Constant) and k.value == "origins" and _is_wildcard(v):
                        return True
    return False


class CORSMisconfigRule(BaseRule):
    rule_id     = "CORS-MISCONFIG"
    description = (
        "CORS configured with wildcard origin ('*') — "
        "allows any website to make credentialed cross-origin requests"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # Pattern 1: CORS(app, origins="*") / cross_origin(origins="*")
            if isinstance(node, ast.Call):
                func = node.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr

                if func_name in _CORS_FUNCS:
                    for kw in node.keywords:
                        if kw.arg in ("origins", "resources") and _origins_is_wildcard(kw.value):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.MEDIUM,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=f"{func_name}(origins='*')",
                            ))
                            break

            # Pattern 2: response.headers["Access-Control-Allow-Origin"] = "*"
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "Access-Control-Allow-Origin"
                        and _is_wildcard(node.value)
                    ):
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink="Access-Control-Allow-Origin: *",
                        ))

            # Pattern 3: Django settings CORS_ALLOW_ALL_ORIGINS = True
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in _DJANGO_CORS_SETTINGS:
                        if _is_true(node.value):
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
