"""Rule 01 — SSTI: Server-Side Template Injection.

Covers: Jinja2, Mako, Django templates, Tornado templates across
Flask, Django, FastAPI, Tornado, and Starlette.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, is_source, is_tainted_expr, collect_taint,
)

# (module_alias, method_or_class) pairs — first arg is the template string
_SINKS: set[tuple[str, str]] = {
    # Jinja2
    ("jinja2",     "Template"),
    ("jinja2",     "from_string"),
    ("Environment", "from_string"),
    # Flask shorthand
    (None,         "render_template_string"),
    # Mako
    ("mako",       "Template"),
    ("Template",   "render"),           # generic
    # Django
    ("template",   "Template"),
    ("Engine",     "from_string"),
    # Tornado
    ("template",   "Template"),
}

# Methods dangerous enough to flag regardless of the module alias used
_ALIAS_SAFE_METHODS = {"Template", "from_string", "render_template_string"}


def _is_ssti_sink(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return any(func.id == s for _, s in _SINKS)
    if isinstance(func, ast.Attribute):
        chain = attr_chain(func.value)
        obj = chain[-1] if chain else ""
        # Exact match
        if (obj, func.attr) in _SINKS or (None, func.attr) in _SINKS:
            return True
        # Alias fallback: `from django import template as tmpl` → tmpl.Template(...)
        # Only for high-signal method names; exclude .render() which is too generic
        if func.attr in _ALIAS_SAFE_METHODS:
            return True
    return False

def _first_arg_dynamic(call: ast.Call, tainted: dict[str, str]) -> bool:
    if not call.args:
        return False
    arg = call.args[0]
    if isinstance(arg, ast.Constant):
        return False
    return is_tainted_expr(arg, tainted) or not isinstance(arg, ast.Constant)


class SSTIRule(BaseRule):
    rule_id     = "SSTI"
    description = (
        "User input rendered as a server-side template — "
        "leads to full RCE via template sandbox escape"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        # Module-level template construction
        findings.extend(self._check_module(tree, source_lines, filepath))
        return findings

    def _check_fn(self, func, source_lines, filepath):
        tainted, _ = collect_taint(func)
        findings = []
        seen: set[int] = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and _is_ssti_sink(node):
                if node.lineno not in seen and _first_arg_dynamic(node, tainted):
                    seen.add(node.lineno)
                    sink = (
                        node.func.attr if isinstance(node.func, ast.Attribute)
                        else node.func.id
                    )
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=sink,
                    ))
        return findings

    def _check_module(self, tree, source_lines, filepath):
        findings = []
        seen: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_ssti_sink(node):
                if node.lineno not in seen and _first_arg_dynamic(node, {}):
                    seen.add(node.lineno)
                    sink = (
                        node.func.attr if isinstance(node.func, ast.Attribute)
                        else node.func.id
                    )
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=sink,
                    ))
        return findings
