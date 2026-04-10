"""Rule: FILE-UPLOAD — unsafe file upload enabling webshell / RCE.

Detects file uploads saved without extension validation or to a
web-accessible path, across Flask, Django, and FastAPI.
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain, names, collect_taint, is_tainted_expr

# Server-side-executable extensions
_DANGEROUS_EXTENSIONS = re.compile(
    r"\.(py|sh|bash|php|cgi|pl|rb|jsp|jspx|asp|aspx|exe|elf|so|dylib)$",
    re.IGNORECASE,
)

# Common safeguards — if any appear near the upload, skip the finding
_SAFE_PATTERNS = frozenset({"splitext", ".suffix", "allowed_file", "secure_filename",
                             "extension", "mimetype"})


def _is_save_call(node: ast.Call) -> bool:
    """Flask FileStorage.save(path)."""
    return isinstance(node.func, ast.Attribute) and node.func.attr == "save"


def _lacks_validation(node: ast.AST, source_lines: List[str]) -> bool:
    """Heuristic: no extension/mime check visible in the surrounding 15 lines."""
    lineno = getattr(node, "lineno", 1)
    start  = max(0, lineno - 10)
    end    = min(len(source_lines), lineno + 5)
    surrounding = "\n".join(source_lines[start:end])
    return not any(p in surrounding for p in _SAFE_PATTERNS)


class FileUploadRCERule(BaseRule):
    """Template Method: implements BaseRule.check() for file-upload sinks."""

    rule_id     = "FILE-UPLOAD"
    description = (
        "File upload saved without extension/type validation — "
        "allows webshell upload leading to remote code execution"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        return findings

    def _check_fn(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        tainted, _ = collect_taint(func)
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue

            # Pattern 1: file_obj.save(tainted_path) — Flask FileStorage
            if _is_save_call(node):
                path = node.args[0] if node.args else None
                if path is not None and is_tainted_expr(path, tainted):
                    if _lacks_validation(node, source_lines):
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
                continue

            # Pattern 2: open(tainted_path, "wb") — Django / FastAPI write
            func_node = node.func
            method = (
                func_node.id  if isinstance(func_node, ast.Name)
                else func_node.attr if isinstance(func_node, ast.Attribute)
                else None
            )
            if method == "open" and len(node.args) >= 2:
                path       = node.args[0]
                mode_node  = node.args[1]
                write_mode = (
                    isinstance(mode_node, ast.Constant)
                    and "w" in str(mode_node.value)
                )
                if write_mode and is_tainted_expr(path, tainted):
                    if _lacks_validation(node, source_lines):
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
