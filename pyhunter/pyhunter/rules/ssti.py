"""Rule: Server-Side Template Injection (SSTI) via dynamic template rendering."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Direct template construction with non-literal strings
_TEMPLATE_CTORS = {
    ("jinja2",     "Template"),
    ("jinja2",     "from_string"),
    ("mako",       "Template"),
    ("mako.template", "Template"),
    ("django.template", "Template"),
}

# render_template_string(user_input) — first arg is the template itself
_RENDER_STRING_CALLS = {
    ("flask",         "render_template_string"),
    ("flask_mako",    "render_template"),
}


def _attr_pair(call: ast.Call) -> tuple[str, str] | None:
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return (call.func.value.id, call.func.attr)
    return None


def _name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    return None


def _first_arg_dynamic(call: ast.Call) -> bool:
    """Return True if the first positional argument is not a string literal."""
    if not call.args:
        return False
    return not isinstance(call.args[0], ast.Constant)


class SSTIRule(BaseRule):
    rule_id     = "SSTI"
    description = "Server-Side Template Injection via dynamic template rendering"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sink = self._match(node)
            if sink and _first_arg_dynamic(node):
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

    def _match(self, call: ast.Call) -> str | None:
        pair = _attr_pair(call)
        if pair in _TEMPLATE_CTORS or pair in _RENDER_STRING_CALLS:
            return f"{pair[0]}.{pair[1]}"
        # jinja2.Environment().from_string(...)  or  env.from_string(...)
        if isinstance(call.func, ast.Attribute) and call.func.attr == "from_string":
            return "env.from_string"
        # render_template_string as a bare import
        if isinstance(call.func, ast.Name) and call.func.id == "render_template_string":
            return "render_template_string"
        return None
