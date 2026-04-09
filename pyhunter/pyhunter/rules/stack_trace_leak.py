"""Rule: stack trace or raw exception message exposed to HTTP clients."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# traceback functions that produce exploit-useful output
_TRACEBACK_SINKS = {"format_exc", "format_exception", "print_exc", "print_exception", "format_tb"}

# Response / return functions that surface data to the client
_RESPONSE_FUNCS = {"jsonify", "make_response", "render_template_string", "HttpResponse", "JsonResponse"}


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _is_traceback_call(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _TRACEBACK_SINKS:
        chain = _attr_chain(func.value)
        return bool(chain) and chain[-1] == "traceback"
    return False


def _is_str_of_exception(node: ast.expr) -> bool:
    """Detect str(e) or repr(e) where e is an exception variable."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in {"str", "repr"}:
            return True  # conservative: any str(x) in except block
    return False


class StackTraceLeakRule(BaseRule):
    rule_id     = "STACK-TRACE-LEAK"
    description = (
        "Stack trace or raw exception message returned to HTTP client — "
        "leaks internal paths, library versions, and logic to attackers"
    )

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
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.ExceptHandler):
                continue

            # Walk statements inside the except block
            for stmt in ast.walk(node):
                lineno = getattr(stmt, "lineno", None)
                if lineno is None or lineno in seen:
                    continue

                # traceback.format_exc() / traceback.print_exc() inside except handler
                if isinstance(stmt, ast.Expr) and _is_traceback_call(stmt.value):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink="traceback",
                    ))

                # return traceback.format_exc() / return str(e)
                if isinstance(stmt, ast.Return) and stmt.value is not None:
                    val = stmt.value
                    if _is_traceback_call(val) or _is_str_of_exception(val):
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink="return exception to client",
                        ))

                # jsonify(error=str(e)) / make_response(traceback...) etc.
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call = stmt.value
                    func_name = None
                    if isinstance(call.func, ast.Name):
                        func_name = call.func.id
                    elif isinstance(call.func, ast.Attribute):
                        func_name = call.func.attr
                    if func_name in _RESPONSE_FUNCS:
                        for arg in call.args:
                            if _is_traceback_call(arg) or _is_str_of_exception(arg):
                                seen.add(lineno)
                                findings.append(Finding(
                                    id=f"{self.rule_id}-{lineno:04d}",
                                    rule_id=self.rule_id,
                                    severity=Severity.MEDIUM,
                                    file=filepath,
                                    line=lineno,
                                    snippet=self._snippet(source_lines, lineno),
                                    sink=func_name,
                                ))
                                break

        return findings
