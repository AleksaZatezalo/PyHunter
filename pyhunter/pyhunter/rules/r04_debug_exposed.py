"""Rule 04 — DEBUG-EXPOSED: Debug mode or interactive console exposed.

Covers Flask, Django, FastAPI (/docs unauthenticated), Tornado, Werkzeug.
An exposed debug console gives attackers a Python REPL in the browser → RCE.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class DebugExposedRule(BaseRule):
    rule_id     = "DEBUG-EXPOSED"
    description = (
        "Debug mode enabled or interactive console exposed — "
        "gives attackers a live Python REPL and detailed stack traces"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # ── Assignments ──────────────────────────────────────────────────
            if isinstance(node, ast.Assign):
                for target in node.targets:

                    # Django / Flask: DEBUG = True
                    if isinstance(target, ast.Name) and target.id in {"DEBUG", "FLASK_DEBUG", "APP_DEBUG"}:
                        if _is_true(node.value):
                            seen.add(lineno)
                            findings.append(self._finding(lineno, source_lines, filepath, target.id))

                    # Flask: app.debug = True
                    if isinstance(target, ast.Attribute) and target.attr == "debug":
                        if _is_true(node.value):
                            seen.add(lineno)
                            findings.append(self._finding(lineno, source_lines, filepath, "app.debug=True"))

                    # Django: ALLOWED_HOSTS = []  (empty list = debug-style permissive)
                    if isinstance(target, ast.Name) and target.id == "ALLOWED_HOSTS":
                        if isinstance(node.value, (ast.List, ast.Tuple)) and not node.value.elts:
                            seen.add(lineno)
                            findings.append(self._finding(lineno, source_lines, filepath, "ALLOWED_HOSTS=[]"))

            # ── Function calls ───────────────────────────────────────────────
            elif isinstance(node, ast.Call):
                func = node.func
                method = None
                if isinstance(func, ast.Attribute):
                    method = func.attr
                elif isinstance(func, ast.Name):
                    method = func.id

                # Flask / Tornado: app.run(debug=True)
                if method == "run":
                    for kw in node.keywords:
                        if kw.arg == "debug" and _is_true(kw.value):
                            seen.add(lineno)
                            findings.append(self._finding(lineno, source_lines, filepath, "app.run(debug=True)"))

                # Werkzeug: run_simple(..., use_debugger=True)
                if method == "run_simple":
                    for kw in node.keywords:
                        if kw.arg == "use_debugger" and _is_true(kw.value):
                            seen.add(lineno)
                            findings.append(self._finding(lineno, source_lines, filepath, "run_simple(use_debugger=True)"))

                # Tornado: Application(..., debug=True)
                if method == "Application":
                    for kw in node.keywords:
                        if kw.arg == "debug" and _is_true(kw.value):
                            seen.add(lineno)
                            findings.append(self._finding(lineno, source_lines, filepath, "tornado.Application(debug=True)"))

                # FastAPI: FastAPI(docs_url="/docs") with no auth — flag if docs_url not None and no dependencies
                if method == "FastAPI":
                    docs_disabled = any(
                        kw.arg == "docs_url" and isinstance(kw.value, ast.Constant) and kw.value.value is None
                        for kw in node.keywords
                    )
                    if not docs_disabled and lineno not in seen:
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink="FastAPI(docs unauthenticated)",
                        ))

        return findings

    def _finding(self, lineno, source_lines, filepath, sink):
        return Finding(
            id=f"{self.rule_id}-{lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=filepath,
            line=lineno,
            snippet=self._snippet(source_lines, lineno),
            sink=sink,
        )
