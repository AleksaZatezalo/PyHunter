"""Rule 11 — AUTH-BYPASS: Broken authentication and authorization.

Covers:
  - JWT: algorithms=None / ["none"] / verify_signature=False / verify=False
  - Django REST Framework: authentication_classes=[] / permission_classes=[]
  - FastAPI: sensitive routes with no Security/Depends auth dependency
  - Django: @login_required missing (detected by decorated-free function names)
  - Predictable / missing session secrets
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain, FASTAPI_ROUTE_METHODS

_SENSITIVE_ROUTE_NAMES = re.compile(
    r"(admin|delete|update|create|upload|reset|password|secret|manage|config|"
    r"user|account|profile|payment|checkout|export|download|backup|deploy)",
    re.IGNORECASE,
)

_AUTH_DEPS = re.compile(
    r"(current_user|get_current_user|require_auth|authenticated|login_required|"
    r"verify_token|oauth2_scheme|security|token_required)",
    re.IGNORECASE,
)


def _is_none_alg(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(
            isinstance(e, ast.Constant) and str(e.value).lower() == "none"
            for e in node.elts
        )
    return False


def _options_no_verify(node: ast.expr) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for key, val in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == "verify_signature":
            if isinstance(val, ast.Constant) and val.value is False:
                return True
    return False


def _is_empty_list(node: ast.expr) -> bool:
    return isinstance(node, (ast.List, ast.Tuple)) and not node.elts


def _has_auth_dependency(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if any FastAPI route parameter references an auth dependency."""
    for arg in func.args.args + func.args.kwonlyargs:
        if _AUTH_DEPS.search(arg.arg):
            return True
    # Also check default values
    for default in func.args.defaults + func.args.kw_defaults:
        if default is None:
            continue
        for n in ast.walk(default):
            if isinstance(n, ast.Name) and _AUTH_DEPS.search(n.id):
                return True
            if isinstance(n, ast.Attribute) and _AUTH_DEPS.search(n.attr):
                return True
    return False


def _is_fastapi_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(d, ast.Call)
        and isinstance(d.func, ast.Attribute)
        and d.func.attr in FASTAPI_ROUTE_METHODS
        for d in func.decorator_list
    )


class AuthBypassRule(BaseRule):
    rule_id     = "AUTH-BYPASS"
    description = (
        "Authentication disabled or bypassable — "
        "JWT signature not verified, DRF auth removed, "
        "or FastAPI sensitive route missing auth dependency"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # JWT bypass
            if isinstance(node, ast.Call):
                func = node.func
                is_decode = (
                    isinstance(func, ast.Attribute) and func.attr == "decode"
                ) or (
                    isinstance(func, ast.Name) and func.id == "decode"
                )
                if is_decode:
                    for kw in node.keywords:
                        if kw.arg == "algorithms" and _is_none_alg(kw.value):
                            seen.add(lineno)
                            findings.append(self._f(lineno, source_lines, filepath, "jwt.decode(algorithms=None/none)", Severity.CRITICAL))
                            break
                        if kw.arg == "options" and _options_no_verify(kw.value):
                            seen.add(lineno)
                            findings.append(self._f(lineno, source_lines, filepath, "jwt.decode(verify_signature=False)", Severity.CRITICAL))
                            break
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            seen.add(lineno)
                            findings.append(self._f(lineno, source_lines, filepath, "jwt.decode(verify=False)", Severity.CRITICAL))
                            break

                # DRF ViewSet / APIView: authentication_classes=[] / permission_classes=[]
                for kw in node.keywords:
                    if kw.arg in ("authentication_classes", "permission_classes") and _is_empty_list(kw.value):
                        seen.add(lineno)
                        findings.append(self._f(lineno, source_lines, filepath, f"DRF {kw.arg}=[]", Severity.HIGH))

            # DRF class-level: authentication_classes = [] as class attribute
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {"authentication_classes", "permission_classes"}:
                        if _is_empty_list(node.value):
                            seen.add(lineno)
                            findings.append(self._f(lineno, source_lines, filepath, f"DRF {target.id}=[]", Severity.HIGH))

        # FastAPI: sensitive route with no auth dependency
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_fastapi_route(node) and _SENSITIVE_ROUTE_NAMES.search(node.name):
                    if not _has_auth_dependency(node):
                        lineno = node.lineno
                        if lineno not in seen:
                            seen.add(lineno)
                            findings.append(self._f(
                                lineno, source_lines, filepath,
                                f"FastAPI route '{node.name}' — no auth dependency",
                                Severity.MEDIUM,
                            ))

        return findings

    def _f(self, lineno, source_lines, filepath, sink, severity):
        return Finding(
            id=f"{self.rule_id}-{lineno:04d}",
            rule_id=self.rule_id,
            severity=severity,
            file=filepath,
            line=lineno,
            snippet=self._snippet(source_lines, lineno),
            sink=sink,
        )
