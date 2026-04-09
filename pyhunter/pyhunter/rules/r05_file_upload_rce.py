"""Rule 05 — FILE-UPLOAD-RCE: Unsafe file upload enabling webshell/RCE.

Detects file uploads saved without extension validation or to a
web-accessible/executable path, across Flask, Django, and FastAPI.
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain, names, collect_taint, is_tainted_expr

# Extensions that can execute server-side code
_DANGEROUS_EXTENSIONS = re.compile(
    r"\.(py|sh|bash|php|cgi|pl|rb|jsp|jspx|asp|aspx|exe|elf|so|dylib)$",
    re.IGNORECASE,
)

# Paths that are web-accessible or commonly served as static/uploaded content
_WEB_PATHS = re.compile(
    r"(static|media|upload|uploads|public|www|wwwroot|assets|files)",
    re.IGNORECASE,
)

# Flask: request.files["x"].save(path)
# Django: request.FILES["x"]  →  open(path, "wb").write(f.read())
# FastAPI: UploadFile  →  open(path, "wb").write(await f.read())


def _is_file_save_call(node: ast.Call) -> bool:
    """Return True if this is a .save() call (Flask FileStorage.save)."""
    func = node.func
    return isinstance(func, ast.Attribute) and func.attr == "save"


def _path_arg(node: ast.Call) -> ast.expr | None:
    return node.args[0] if node.args else None


def _path_has_no_extension_check(func_node, source_lines) -> bool:
    """Heuristic: if there's no reference to 'splitext', 'suffix', or extension
    filtering near the save call, flag it."""
    # We check the surrounding snippet for common safeguards
    lineno = getattr(func_node, "lineno", 1)
    start = max(0, lineno - 10)
    end = min(len(source_lines), lineno + 5)
    surrounding = "\n".join(source_lines[start:end])
    safe_patterns = {"splitext", ".suffix", "allowed_file", "secure_filename", "extension", "mimetype"}
    return not any(p in surrounding for p in safe_patterns)


class FileUploadRCERule(BaseRule):
    rule_id     = "FILE-UPLOAD"
    description = (
        "File upload saved without extension/type validation — "
        "allows webshell upload leading to remote code execution"
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

            # Pattern 1: file_obj.save(path)  — Flask FileStorage
            if _is_file_save_call(node):
                path = _path_arg(node)
                if path is not None and is_tainted_expr(path, tainted):
                    if _path_has_no_extension_check(node, source_lines):
                        seen.add(node.lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{node.lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            file=filepath,
                            line=node.lineno,
                            snippet=self._snippet(source_lines, node.lineno),
                            sink="FileStorage.save(user_controlled_path)",
                        ))

            # Pattern 2: open(path, "wb") where path is tainted and lacks validation
            func_node = node.func
            method = (
                func_node.id if isinstance(func_node, ast.Name)
                else func_node.attr if isinstance(func_node, ast.Attribute)
                else None
            )
            if method == "open" and len(node.args) >= 1:
                path = node.args[0]
                # Check that file is opened in write mode
                write_mode = len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and "w" in str(node.args[1].value)
                if write_mode and is_tainted_expr(path, tainted):
                    if _path_has_no_extension_check(node, source_lines):
                        seen.add(node.lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{node.lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=node.lineno,
                            snippet=self._snippet(source_lines, node.lineno),
                            sink="open(user_path, 'wb') — unvalidated upload",
                        ))

        return findings
