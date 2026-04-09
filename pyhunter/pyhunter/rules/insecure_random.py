"""Rule: use of the non-cryptographic random module for security-sensitive values."""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Functions from the random module that are not cryptographically secure
_RANDOM_FUNCS = {
    "random", "randint", "randrange", "choice", "choices",
    "shuffle", "sample", "uniform", "getrandbits",
}

# Variable / context names that suggest security-sensitive use
_SECURITY_CONTEXT = re.compile(
    r"(token|secret|password|passwd|pwd|nonce|salt|otp|pin|key|"
    r"session|csrf|captcha|uuid|auth|verification|reset|challenge)",
    re.IGNORECASE,
)


def _looks_security_sensitive(name: str) -> bool:
    return bool(_SECURITY_CONTEXT.search(name))


class InsecureRandomRule(BaseRule):
    rule_id     = "INSECURE-RANDOM"
    description = (
        "Non-cryptographic random module used in a security-sensitive context; "
        "use secrets or os.urandom instead"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            lineno = node.lineno

            # random.choice(...) / random.randint(...) etc.
            if not (
                isinstance(func, ast.Attribute)
                and func.attr in _RANDOM_FUNCS
                and isinstance(func.value, ast.Name)
                and func.value.id == "random"
            ):
                continue

            if lineno in seen:
                continue

            # Determine security-sensitivity from assignment target name
            parent_assign = self._enclosing_assign_name(tree, node)
            if parent_assign and _looks_security_sensitive(parent_assign):
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink=f"random.{func.attr}",
                    source=parent_assign,
                ))
            # Also flag random usage in functions whose name suggests security
            else:
                fn = self._enclosing_function_name(tree, node)
                if fn and _looks_security_sensitive(fn):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"random.{func.attr}",
                        source=fn,
                    ))

        return findings

    def _enclosing_assign_name(self, tree: ast.AST, target_call: ast.Call) -> str | None:
        """Return the variable name that this call is being assigned to, if any."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and node.value is target_call:
                for t in node.targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            return n.id
            if isinstance(node, ast.AnnAssign) and node.value is target_call:
                if isinstance(node.target, ast.Name):
                    return node.target.id
        return None

    def _enclosing_function_name(self, tree: ast.AST, target_call: ast.Call) -> str | None:
        """Return the name of the innermost function containing the call."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(n is target_call for n in ast.walk(node)):
                    return node.name
        return None
