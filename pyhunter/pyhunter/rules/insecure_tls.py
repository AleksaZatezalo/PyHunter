"""Rule: insecure TLS configuration (disabled verification, weak protocols)."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# requests / httpx / aiohttp — verify=False keyword argument
_HTTP_CLIENT_METHODS = {
    "get", "post", "put", "patch", "delete", "head",
    "options", "request", "send",
}

# Weak ssl module constants
_WEAK_SSL_PROTOCOLS = {
    "PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
    "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
}

# ssl attribute assignments that weaken security
_INSECURE_SSL_ATTRS = {"check_hostname", "verify_mode"}


def _is_false(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


class InsecureTLSRule(BaseRule):
    rule_id     = "INSECURE-TLS"
    description = (
        "TLS verification disabled or weak SSL protocol selected — "
        "connection vulnerable to MITM attacks"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # Pattern 1: requests.get(url, verify=False)
            if isinstance(node, ast.Call):
                func = node.func
                method_name = None
                if isinstance(func, ast.Attribute):
                    method_name = func.attr
                elif isinstance(func, ast.Name):
                    method_name = func.id

                if method_name in _HTTP_CLIENT_METHODS:
                    for kw in node.keywords:
                        if kw.arg == "verify" and _is_false(kw.value):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=f"{method_name}(verify=False)",
                            ))
                            break

                # ssl._create_unverified_context()
                if isinstance(func, ast.Attribute) and func.attr == "_create_unverified_context":
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink="ssl._create_unverified_context",
                    ))

                # ssl.create_default_context() / SSLContext with weak protocol
                if isinstance(func, ast.Attribute) and func.attr in {"SSLContext", "wrap_socket"}:
                    for kw in node.keywords:
                        if kw.arg == "ssl_version" and isinstance(kw.value, ast.Attribute):
                            if kw.value.attr in _WEAK_SSL_PROTOCOLS:
                                seen.add(lineno)
                                findings.append(Finding(
                                    id=f"{self.rule_id}-{lineno:04d}",
                                    rule_id=self.rule_id,
                                    severity=Severity.HIGH,
                                    file=filepath,
                                    line=lineno,
                                    snippet=self._snippet(source_lines, lineno),
                                    sink=f"ssl.{kw.value.attr}",
                                ))

            # Pattern 2: ctx.check_hostname = False  /  ctx.verify_mode = CERT_NONE
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "check_hostname":
                        if _is_false(node.value):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink="ssl.check_hostname=False",
                            ))
                    if isinstance(target, ast.Attribute) and target.attr == "verify_mode":
                        chain = _attr_chain(node.value)
                        if "CERT_NONE" in chain:
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink="ssl.verify_mode=CERT_NONE",
                            ))

            # Pattern 3: reference to weak SSL protocol constants
            elif isinstance(node, ast.Attribute) and node.attr in _WEAK_SSL_PROTOCOLS:
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink=f"ssl.{node.attr}",
                ))

        return findings
