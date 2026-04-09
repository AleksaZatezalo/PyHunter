"""Rule 09 — PATH-TRAVERSAL: Path traversal and Zip Slip.

Covers: open(), os.path.join without normalization,
Flask send_file/send_from_directory, FastAPI FileResponse,
Django StreamingHttpResponse(open(...)), ZipFile.extract/extractall.

Path traversal chains into: read /etc/passwd, .env, SSH keys →
credential theft → lateral movement.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, names, is_tainted_expr, collect_taint,
)

_FILE_SERVE_FUNCS = {"send_file", "send_from_directory", "FileResponse", "StaticFiles"}


def _is_dynamic(node: ast.expr) -> bool:
    return not isinstance(node, ast.Constant)


class PathTraversalRule(BaseRule):
    rule_id     = "PATH-TRAVERSAL"
    description = (
        "User-controlled path used in file operation — "
        "allows reading /etc/passwd, SSH keys, .env files, "
        "and source code via directory traversal"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    def _check_fn(self, func, source_lines, filepath):
        tainted, _ = collect_taint(func)
        findings = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            fn = node.func
            method = (
                fn.id if isinstance(fn, ast.Name)
                else fn.attr if isinstance(fn, ast.Attribute)
                else None
            )
            if method is None:
                continue

            # open(user_path, ...)
            if method == "open" and node.args:
                path = node.args[0]
                if _is_dynamic(path) and is_tainted_expr(path, tainted):
                    seen.add(node.lineno)
                    findings.append(self._f(node.lineno, source_lines, filepath, "open"))

            # Flask: send_file(user_path), send_from_directory(dir, user_name)
            elif method in {"send_file", "FileResponse"}:
                path = node.args[0] if node.args else None
                if path and is_tainted_expr(path, tainted):
                    seen.add(node.lineno)
                    findings.append(self._f(node.lineno, source_lines, filepath, method))

            elif method == "send_from_directory" and len(node.args) >= 2:
                path = node.args[1]
                if is_tainted_expr(path, tainted):
                    seen.add(node.lineno)
                    findings.append(self._f(node.lineno, source_lines, filepath, "send_from_directory"))

            # os.path.join without subsequent normalization check
            elif method == "join":
                chain = attr_chain(fn.value) if isinstance(fn, ast.Attribute) else ()
                if "path" in chain:
                    for arg in node.args[1:]:   # all parts after the base
                        if is_tainted_expr(arg, tainted):
                            seen.add(node.lineno)
                            findings.append(self._f(node.lineno, source_lines, filepath, "os.path.join (no normalization)"))
                            break

            # Zip Slip: ZipFile.extract / extractall
            elif method in {"extract", "extractall"}:
                # Flag: destination path is user-controlled or archive is user-supplied
                path = node.args[0] if node.args else None
                dest = node.args[1] if len(node.args) >= 2 else None
                if (path and is_tainted_expr(path, tainted)) or (dest and is_tainted_expr(dest, tainted)):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=f"ZipFile.{method} (Zip Slip)",
                    ))

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
