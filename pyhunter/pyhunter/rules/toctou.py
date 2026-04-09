"""Rule: TOCTOU (Time-of-Check Time-of-Use) race condition on file operations."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Check functions that test file existence/accessibility
_CHECK_FUNCS: set[tuple[str, str]] = {
    ("os.path", "exists"),
    ("os.path", "isfile"),
    ("os.path", "isdir"),
    ("os.path", "islink"),
    ("os",      "access"),
    ("pathlib", "exists"),   # Path.exists()
    ("pathlib", "is_file"),
    ("pathlib", "is_dir"),
}

# Use functions that act on a path
_USE_FUNCS: set[str] = {"open", "remove", "unlink", "rename", "mkdir", "makedirs", "rmdir"}
_USE_METHODS: set[str] = {"open", "unlink", "rename", "mkdir", "rmdir", "write_text", "read_text"}


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _call_path_arg(node: ast.Call) -> str | None:
    """Return the first string-literal or variable-name path argument, or None."""
    if not node.args:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        return arg.id
    return None


def _is_check_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        chain = _attr_chain(func.value)
        prefix = ".".join(chain)
        return (prefix, func.attr) in _CHECK_FUNCS or func.attr in {a for _, a in _CHECK_FUNCS}
    return False


def _is_use_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in _USE_FUNCS:
        return True
    if isinstance(func, ast.Attribute) and func.attr in _USE_METHODS:
        return True
    return False


class TOCTOURule(BaseRule):
    rule_id     = "TOCTOU"
    description = (
        "File existence checked then used separately (check-then-use race condition); "
        "use atomic operations or exception handling instead"
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
        # Collect all check calls with their path arg and lineno
        checks: list[tuple[str, int]] = []

        for node in ast.walk(func):
            if isinstance(node, ast.Call) and _is_check_call(node):
                path = _call_path_arg(node)
                if path:
                    checks.append((path, node.lineno))

        if not checks:
            return findings

        # Now look for use calls with the same path arg
        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or not _is_use_call(node):
                continue
            use_path = _call_path_arg(node)
            if use_path is None:
                continue
            for check_path, check_line in checks:
                if check_path == use_path and node.lineno > check_line:
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        source=f"check at line {check_line}",
                        sink=f"use of '{use_path}'",
                    ))
                    break

        return findings
