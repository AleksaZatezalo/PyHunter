"""Rule: insecure JWT verification (missing or disabled signature checks)."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Acceptable: jwt.decode(token, key, algorithms=["HS256"])
# Flagged:
#   jwt.decode(token, options={"verify_signature": False})
#   jwt.decode(token, algorithms=["none"])
#   jwt.decode(token, algorithms=None)
#   jwt.decode(token, verify=False)           # PyJWT <2
#   jose.jwt.decode(token, key, options={"verify_at_hash": False, ...})


def _is_none_or_none_alg(node: ast.expr) -> bool:
    """Return True if node is None literal or a list containing 'none'/'None'."""
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                return True
    return False


def _options_disable_verify(node: ast.expr) -> bool:
    """Return True if an options dict disables signature verification."""
    if not isinstance(node, ast.Dict):
        return False
    for key, val in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant):
            continue
        if key.value == "verify_signature" and isinstance(val, ast.Constant) and val.value is False:
            return True
    return False


class WeakJWTRule(BaseRule):
    rule_id     = "WEAK-JWT"
    description = "JWT decoded without signature verification (algorithm=none, verify_signature=False)"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            # Match: jwt.decode(...) / jose.jwt.decode(...)
            is_decode = (
                (isinstance(func, ast.Attribute) and func.attr == "decode")
                or (isinstance(func, ast.Name) and func.id == "decode")
            )
            if not is_decode:
                continue

            flagged = False

            for kw in node.keywords:
                if kw.arg == "algorithms" and _is_none_or_none_alg(kw.value):
                    flagged = True
                    break
                if kw.arg == "options" and _options_disable_verify(kw.value):
                    flagged = True
                    break
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    flagged = True
                    break

            if flagged:
                findings.append(Finding(
                    id=f"{self.rule_id}-{node.lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    sink="jwt.decode",
                ))

        return findings
