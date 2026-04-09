"""Rule 10 — HARDCODED-SECRET: Credentials and keys embedded in source.

Covers: API keys, passwords, Django SECRET_KEY, AWS/GCP credentials,
database connection strings with embedded passwords, JWT signing keys,
private key PEM blocks.

Hardcoded secrets chain into: direct DB/cloud access, JWT forgery,
SSH access → immediate privilege escalation without exploiting any vuln.
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_SECRET_VAR = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|"
    r"db[_-]?pass(?:word)?|database[_-]?pass(?:word)?|jwt[_-]?secret|"
    r"signing[_-]?key|hmac[_-]?key|bearer|credential|django[_-]?secret|"
    r"secret[_-]?key|aws[_-]?secret|encryption[_-]?key|"
    r"GITHUB[_-]?TOKEN|SLACK[_-]?TOKEN|SENDGRID[_-]?API)",
    re.IGNORECASE,
)

_PLACEHOLDER = re.compile(
    r"^(<[^>]+>|\$\{[^}]+\}|%\([^)]+\)s|\{\{[^}]+\}\}|"
    r"your[_-]?.{0,30}|changeme|replace[_-]?me|placeholder|"
    r"example|test|demo|dummy|xxx+|insert[_-]?.{0,30}|"
    r"secret[_-]?key[_-]?here|enter[_-]?.{0,30})$",
    re.IGNORECASE,
)

# Regex patterns that look like real secrets (AWS keys, GitHub tokens, etc.)
_SECRET_PATTERN = re.compile(
    r"("
    r"AKIA[0-9A-Z]{16}"                   # AWS access key
    r"|[a-zA-Z0-9+/]{40}"                 # generic 40-char base64
    r"|ghp_[a-zA-Z0-9]{36}"               # GitHub personal access token
    r"|sk-[a-zA-Z0-9]{32,}"               # OpenAI / Stripe secret key
    r"|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"   # PEM private key
    r"|eyJ[a-zA-Z0-9_-]{10,}"             # JWT-like token
    r")"
)

_MIN_LEN = 8


def _is_real_secret(val: str) -> bool:
    if len(val) < _MIN_LEN:
        return False
    if _PLACEHOLDER.match(val.strip()):
        return False
    return True


def _is_high_entropy(val: str) -> bool:
    """True if string looks like a real secret (pattern match or raw entropy)."""
    if _SECRET_PATTERN.search(val):
        return True
    # Simple heuristic: if alphanumeric + symbols and len ≥ 16 with no spaces
    if len(val) >= 16 and " " not in val and re.search(r"[0-9]", val) and re.search(r"[a-zA-Z]", val):
        return True
    return False


def _var_matches(name: str) -> bool:
    return bool(_SECRET_VAR.search(name))


class HardcodedSecretsRule(BaseRule):
    rule_id     = "HARDCODED-SECRET"
    description = (
        "Secret, password, or API key embedded as a string literal — "
        "immediate credential theft leading to DB, cloud, or SSH access"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # name = "literal"
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value if isinstance(node, ast.Assign) else node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                    continue
                if not _is_real_secret(value.value):
                    continue
                for target in targets:
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name) and _var_matches(n.id):
                            seen.add(lineno)
                            findings.append(Finding(
                                id=f"{self.rule_id}-{lineno:04d}",
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file=filepath,
                                line=lineno,
                                snippet=self._snippet(source_lines, lineno),
                                sink=n.id,
                            ))
                            break

            # function(password="literal", api_key="literal")
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg and _var_matches(kw.arg):
                        if (
                            isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)
                            and _is_real_secret(kw.value.value)
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
