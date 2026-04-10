"""Rule: DESER-RCE — unsafe deserialization leading to remote code execution.

Covers pickle, PyYAML, jsonpickle, marshal, dill, shelve across all supported
web frameworks. Flags calls only when the first argument is tainted with
user-controlled data from a request source.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain, is_source, is_tainted_expr, collect_taint

# (module, function) pairs whose return value executes arbitrary code on load
_SINKS: set[tuple[str, str]] = {
    ("pickle",     "loads"),
    ("pickle",     "load"),
    ("_pickle",    "loads"),
    ("cPickle",    "loads"),
    ("dill",       "loads"),
    ("dill",       "load"),
    ("jsonpickle", "decode"),
    ("marshal",    "loads"),
    ("marshal",    "load"),
    ("shelve",     "open"),   # key controlled by user → RCE via stored pickle
}

# yaml.load is only safe with these explicit Loaders
_SAFE_YAML_LOADERS = {"SafeLoader", "BaseLoader", "CSafeLoader"}


def _is_deser_sink(call: ast.Call) -> tuple[bool, str]:
    """Return (is_sink, sink_label) for standard deserialisation calls."""
    func = call.func
    if isinstance(func, ast.Attribute):
        chain = attr_chain(func.value)
        mod   = chain[-1] if chain else ""
        if (mod, func.attr) in _SINKS:
            return True, f"{mod}.{func.attr}"
    return False, ""


def _yaml_load_is_unsafe(call: ast.Call) -> bool:
    """Return True when yaml.load() is called without a safe Loader."""
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "load"):
        return False
    chain = attr_chain(func.value)
    if not (chain and chain[-1] == "yaml"):
        return False
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader_name = (
                kw.value.attr if isinstance(kw.value, ast.Attribute)
                else kw.value.id  if isinstance(kw.value, ast.Name)
                else None
            )
            if loader_name in _SAFE_YAML_LOADERS:
                return False
    return True  # no Loader kwarg → uses unsafe default


class DeserRCERule(BaseRule):
    """Template Method: implements BaseRule.check() for deserialization sinks."""

    rule_id     = "DESER-RCE"
    description = (
        "Untrusted data passed to a deserialiser — "
        "pickle/YAML/jsonpickle/marshal/dill can execute arbitrary code on load"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_fn(node, source_lines, filepath))
        findings.extend(self._check_module(tree, source_lines, filepath))
        return findings

    # ── per-function scan (taint-tracked) ────────────────────────────────────

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

            flagged, label = _is_deser_sink(node)
            if flagged:
                arg = node.args[0] if node.args else None
                if arg and is_tainted_expr(arg, tainted):
                    seen.add(node.lineno)
                    findings.append(self._finding(filepath, source_lines, node, label))
                continue

            if _yaml_load_is_unsafe(node):
                arg = node.args[0] if node.args else None
                if arg and is_tainted_expr(arg, tainted):
                    seen.add(node.lineno)
                    findings.append(
                        self._finding(filepath, source_lines, node, "yaml.load(unsafe)")
                    )

        return findings

    # ── module-level scan (no taint context, flag direct source args) ─────────

    def _check_module(
        self,
        tree: ast.AST,
        source_lines: List[str],
        filepath: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno in seen:
                continue
            flagged, label = _is_deser_sink(node)
            if flagged:
                arg = node.args[0] if node.args else None
                if arg and is_source(arg):
                    seen.add(node.lineno)
                    findings.append(self._finding(filepath, source_lines, node, label))

        return findings

    def _finding(
        self,
        filepath: str,
        source_lines: List[str],
        node: ast.Call,
        label: str,
    ) -> Finding:
        return Finding(
            id=f"{self.rule_id}-{node.lineno:04d}",
            rule_id=self.rule_id,
            severity=Severity.CRITICAL,
            file=filepath,
            line=node.lineno,
            snippet=self._snippet(source_lines, node.lineno),
            sink=label,
        )
