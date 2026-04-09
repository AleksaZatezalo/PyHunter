"""Rule: use of weak or broken cryptographic algorithms."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# hashlib weak algorithms
_WEAK_HASH_FUNCS = {"md5", "sha1"}

# Weak cipher / mode attribute names
_WEAK_CIPHER_ATTRS = {
    "DES", "DES3", "TripleDES", "ARC2", "ARC4", "RC4", "Blowfish",
    "MODE_ECB",                        # ECB mode (all cipher libs)
    "ECB",
}

# cryptography hazmat weak algorithms (as ast.Name / ast.Attribute)
_WEAK_HAZMAT_NAMES = {
    "TripleDES", "Blowfish", "ARC4", "ARC2", "CAST5",
}

# Weak TLS/SSL constants (also covered by insecure_tls, but flag here too)
_WEAK_PROTOCOL_ATTRS = {"PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"}


class WeakCryptoRule(BaseRule):
    rule_id     = "WEAK-CRYPTO"
    description = "Use of a weak or broken cryptographic algorithm (MD5, SHA-1, DES, RC4, ECB mode)"

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            if lineno is None or lineno in seen:
                continue

            # hashlib.md5() / hashlib.sha1() / md5() / sha1()
            if isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr

                if name in _WEAK_HASH_FUNCS:
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=name,
                    ))

                # Crypto.Cipher.DES.new() / Cryptodome / cryptography hazmat
                elif isinstance(func, ast.Attribute) and func.attr == "new":
                    obj = func.value
                    obj_name = None
                    if isinstance(obj, ast.Attribute):
                        obj_name = obj.attr
                    elif isinstance(obj, ast.Name):
                        obj_name = obj.id
                    if obj_name in _WEAK_CIPHER_ATTRS or obj_name in _WEAK_HAZMAT_NAMES:
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink=obj_name,
                        ))

            # Attribute access of weak constants: AES.MODE_ECB, algorithms.TripleDES(...)
            elif isinstance(node, ast.Attribute) and node.attr in _WEAK_CIPHER_ATTRS:
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink=node.attr,
                ))

        return findings
