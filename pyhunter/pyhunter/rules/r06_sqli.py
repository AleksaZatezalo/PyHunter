"""Rule 06 — SQL-INJECT: SQL injection across raw SQL, SQLAlchemy, Django ORM.

Covers:
  - Raw cursor.execute() / executemany() with dynamic strings
  - SQLAlchemy: db.execute(text(f"...")), engine.execute(f"...")
  - Django ORM: .raw(f"..."), .extra(where=[f"..."]), .extra(select={...})
  - psycopg2 / pymysql / sqlite3 cursors
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, names, is_tainted_expr, collect_taint,
)

_EXECUTE_METHODS = {"execute", "executemany", "executescript"}
_ORM_RAW_METHODS = {"raw", "extra"}


def _contains_name(node: ast.expr) -> bool:
    return any(isinstance(n, ast.Name) for n in ast.walk(node))


def _is_dynamic_str(node: ast.expr) -> bool:
    """Return True if the node is a dynamically constructed string."""
    if isinstance(node, ast.JoinedStr):                          # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _contains_name(node)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False


def _is_text_wrapped(node: ast.expr) -> bool:
    """Return True if node is SQLAlchemy text(f"...") with dynamic content."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
    if name != "text":
        return False
    return node.args and _is_dynamic_str(node.args[0])


class SQLInjectRule(BaseRule):
    rule_id     = "SQL-INJECT"
    description = (
        "SQL query constructed with dynamic string content — "
        "allows data exfiltration, authentication bypass, and "
        "file read/write depending on DB privileges"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            lineno = node.lineno
            if lineno in seen:
                continue
            if not isinstance(func, ast.Attribute):
                continue

            # cursor.execute / executemany / executescript
            if func.attr in _EXECUTE_METHODS and node.args:
                query = node.args[0]
                if _is_dynamic_str(query) or _is_text_wrapped(query):
                    seen.add(lineno)
                    findings.append(self._f(lineno, source_lines, filepath, func.attr))

            # SQLAlchemy: db.execute(text(f"...")) or db.execute(f"...")
            elif func.attr == "execute" and node.args:
                query = node.args[0]
                if _is_dynamic_str(query) or _is_text_wrapped(query):
                    seen.add(lineno)
                    findings.append(self._f(lineno, source_lines, filepath, "db.execute"))

            # Django ORM: Model.objects.raw(f"...") / .extra(where=[f"..."])
            elif func.attr in _ORM_RAW_METHODS:
                if func.attr == "raw" and node.args:
                    if _is_dynamic_str(node.args[0]):
                        seen.add(lineno)
                        findings.append(self._f(lineno, source_lines, filepath, "queryset.raw"))

                elif func.attr == "extra":
                    for kw in node.keywords:
                        if kw.arg in ("where", "select", "tables", "order_by"):
                            if isinstance(kw.value, (ast.List, ast.Tuple)):
                                for elt in kw.value.elts:
                                    if _is_dynamic_str(elt):
                                        seen.add(lineno)
                                        findings.append(self._f(lineno, source_lines, filepath, f"queryset.extra({kw.arg}=...)"))
                                        break
                            elif _is_dynamic_str(kw.value):
                                seen.add(lineno)
                                findings.append(self._f(lineno, source_lines, filepath, f"queryset.extra({kw.arg}=...)"))

        return findings

    def _f(self, lineno, source_lines, filepath, sink):
        return Finding(
            id=f"{self.rule_id}-{lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=filepath,
            line=lineno,
            snippet=self._snippet(source_lines, lineno),
            sink=sink,
        )
