"""Rule: hardcoded secrets, credentials, and API keys in source code."""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# Variable / keyword-argument names that suggest a secret value
_SECRET_VAR_PATTERNS = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|"
    r"db[_-]?pass|database[_-]?password|jwt[_-]?secret|encryption[_-]?key|"
    r"signing[_-]?key|hmac[_-]?key|bearer|credentials?|django[_-]?secret)",
    re.IGNORECASE,
)

# Exclude obvious non-secret placeholder strings
_PLACEHOLDER = re.compile(
    r"^(<[^>]+>|\$\{[^}]+\}|%\([^)]+\)s|\{\{[^}]+\}\}|your[_-]?.*|"
    r"changeme|replace[_-]?me|placeholder|example|test|demo|dummy|xxx+|"
    r"secret[_-]?key[_-]?here|enter[_-]?.*)$",
    re.IGNORECASE,
)

# Minimum length to avoid flagging empty strings and tiny values
_MIN_SECRET_LEN = 6


def _looks_like_secret_value(val: str) -> bool:
    if len(val) < _MIN_SECRET_LEN:
        return False
    if _PLACEHOLDER.match(val.strip()):
        return False
    return True


def _var_is_secret(name: str) -> bool:
    return bool(_SECRET_VAR_PATTERNS.search(name))


class HardcodedSecretsRule(BaseRule):
    rule_id     = "HARDCODED-SECRET"
    description = "Secret, password, or API key assigned as a string literal in source code"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # Pattern 1: name = "literal"  /  name: str = "literal"
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if isinstance(node, ast.Assign):
                    targets = node.targets
                    value = node.value
                else:
                    targets = [node.target] if node.target else []
                    value = node.value

                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    continue
                if not _looks_like_secret_value(value.value):
                    continue

                for target in targets:
                    for name_node in ast.walk(target):
                        if isinstance(name_node, ast.Name) and _var_is_secret(name_node.id):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=name_node.id,
                            ))
                            break

            # Pattern 2: keyword argument  e.g. connect(password="secret123")
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg and _var_is_secret(kw.arg):
                        if (
                            isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)
                            and _looks_like_secret_value(kw.value.value)
                            and lineno not in seen
                        ):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=kw.arg,
                            ))
                            break

        return findings
