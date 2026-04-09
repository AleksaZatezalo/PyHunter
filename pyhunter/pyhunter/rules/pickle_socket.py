"""Rule: pickle deserialization of data received over a network socket."""
from __future__ import annotations

import ast
from typing import List, Set

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Methods that receive raw bytes from the network
_NET_RECV_METHODS = {"recv", "recvfrom", "recvfrom_into", "recv_into", "read", "readline", "makefile"}

# HTTP / requests library response accessors that expose raw bytes
_HTTP_BODY_ATTRS = {"content", "raw", "data"}
_HTTP_BODY_METHODS = {"read", "iter_content", "iter_lines"}

_PICKLE_LOADS = {("pickle", "loads"), ("pickle", "load"), ("dill", "loads"), ("dill", "load")}


def _attr_pair(node: ast.expr) -> tuple[str, str] | None:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return (node.value.id, node.attr)
    return None


def _is_network_expr(expr: ast.expr) -> bool:
    """Return True if this expression looks like it reads bytes from the network."""
    # socket_obj.recv(...)
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Attribute) and expr.func.attr in _NET_RECV_METHODS:
            return True
        # response.read() / response.iter_content()
        if isinstance(expr.func, ast.Attribute) and expr.func.attr in _HTTP_BODY_METHODS:
            return True
    # response.content / response.data / response.raw
    if isinstance(expr, ast.Attribute) and expr.attr in _HTTP_BODY_ATTRS:
        return True
    return False


def _collect_net_vars(func_body: list) -> Set[str]:
    """Collect variable names that are assigned network-received data."""
    net_vars: Set[str] = set()
    for node in ast.walk(ast.Module(body=func_body, type_ignores=[])):
        if not isinstance(node, ast.Assign):
            continue
        if _is_network_expr(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    net_vars.add(target.id)
    return net_vars


def _arg_is_network(arg: ast.expr, net_vars: Set[str]) -> bool:
    if _is_network_expr(arg):
        return True
    if isinstance(arg, ast.Name) and arg.id in net_vars:
        return True
    return False


class PickleOverSocketRule(BaseRule):
    rule_id     = "PICKLE-NET"
    description = "Pickle deserialization of network-received data"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        # Check at module level and inside each function/method
        scopes: list[list] = [tree.body]  # type: ignore[attr-defined]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(node.body)

        for scope in scopes:
            net_vars = _collect_net_vars(scope)
            for node in ast.walk(ast.Module(body=scope, type_ignores=[])):
                if not isinstance(node, ast.Call):
                    continue
                pair = _attr_pair(node.func) if isinstance(node.func, ast.Attribute) else None
                if pair not in _PICKLE_LOADS:
                    continue
                if not node.args:
                    continue
                if _arg_is_network(node.args[0], net_vars):
                    findings.append(Finding(
                        id=f"{self.rule_id}-{node.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        sink=f"{pair[0]}.{pair[1]}",
                        source="network socket",
                    ))
        return findings
