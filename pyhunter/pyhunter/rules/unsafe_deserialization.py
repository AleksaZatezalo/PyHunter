"""Rule: unsafe deserialization via pickle / yaml.load / jsonpickle."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_SINKS = {
    ("pickle",     "load"),
    ("pickle",     "loads"),
    ("dill",       "load"),
    ("dill",       "loads"),
    ("jsonpickle", "decode"),
}

_YAML_SAFE_LOADERS = {"SafeLoader", "BaseLoader"}


def _yaml_is_safe(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg != "Loader":
            continue
        name = (kw.value.attr if isinstance(kw.value, ast.Attribute) else
                kw.value.id   if isinstance(kw.value, ast.Name) else None)
        if name in _YAML_SAFE_LOADERS:
            return True
    return False


class UnsafeDeserializationRule(BaseRule):
    rule_id     = "DESER-UNSAFE"
    description = "Unsafe deserialization of untrusted data"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sink = self._match(node)
            if sink is None:
                continue
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
        if not isinstance(call.func, ast.Attribute):
            return None
        if not isinstance(call.func.value, ast.Name):
            return None
        module, method = call.func.value.id, call.func.attr
        if (module, method) in _SINKS:
            return f"{module}.{method}"
        if module == "yaml" and method == "load" and not _yaml_is_safe(call):
            return "yaml.load"
        return None
