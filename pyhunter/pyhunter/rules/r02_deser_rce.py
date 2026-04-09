"""Rule 02 — DESER-RCE: Unsafe Deserialization leading to Remote Code Execution.

Covers: pickle, PyYAML, jsonpickle, marshal, dill, shelve
across all framework request sources.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import (
    attr_chain, is_source, is_tainted_expr, collect_taint,
)

# (module, function) — any of these with tainted input → RCE
_SINKS: set[tuple[str, str]] = {
    ("pickle",      "loads"),
    ("pickle",      "load"),
    ("_pickle",     "loads"),
    ("cPickle",     "loads"),
    ("dill",        "loads"),
    ("dill",        "load"),
    ("jsonpickle",  "decode"),
    ("marshal",     "loads"),
    ("marshal",     "load"),
    ("shelve",      "open"),       # key controlled by user → RCE via stored pickle
}

# yaml.load is unsafe only with certain Loaders (not SafeLoader/BaseLoader)
_SAFE_YAML_LOADERS = {"SafeLoader", "BaseLoader", "CSafeLoader"}


def _is_deser_sink(call: ast.Call) -> tuple[bool, str]:
    """Return (is_sink, sink_label)."""
    func = call.func
    if isinstance(func, ast.Attribute):
        chain = attr_chain(func.value)
        mod = chain[-1] if chain else ""
        key = (mod, func.attr)
        if key in _SINKS:
            return True, f"{mod}.{func.attr}"
    return False, ""


def _yaml_load_is_unsafe(call: ast.Call) -> bool:
    """Return True if yaml.load() is called with an unsafe Loader."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "load"):
        return False
    chain = attr_chain(func.value)
    if not (chain and chain[-1] == "yaml"):
        return False
    # Safe if Loader= is explicitly one of the safe loaders
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader_name = None
            if isinstance(kw.value, ast.Attribute):
                loader_name = kw.value.attr
            elif isinstance(kw.value, ast.Name):
                loader_name = kw.value.id
            if loader_name in _SAFE_YAML_LOADERS:
                return False
    return True   # no Loader kwarg = uses unsafe default


class DeserRCERule(BaseRule):
    rule_id     = "DESER-RCE"
    description = (
        "Untrusted data passed to a deserialiser — "
        "pickle/YAML/jsonpickle/marshal/dill can execute arbitrary code on load"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        findings.extend(self._check_module(tree, source_lines, filepath))
        return findings

    def _check_fn(self, func, source_lines, filepath):
        tainted, _ = collect_taint(func)
        findings = []
        seen: set[int] = set()

        for node in ast.walk(func):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue

            # Standard deser sinks
            flagged, label = _is_deser_sink(node)
            if flagged:
                arg = node.args[0] if node.args else None
                if arg and is_tainted_expr(arg, tainted):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=label,
                    ))
                continue

            # yaml.load with unsafe loader + tainted data
            if _yaml_load_is_unsafe(node):
                arg = node.args[0] if node.args else None
                if arg and is_tainted_expr(arg, tainted):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink="yaml.load(unsafe)",
                    ))

        return findings

    def _check_module(self, tree, source_lines, filepath):
        """Flag any deserialisation of network/request data at module level."""
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            flagged, label = _is_deser_sink(node)
            if flagged:
                arg = node.args[0] if node.args else None
                if arg and is_source(arg):
                    seen.add(node.lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=label,
                    ))
        return findings
