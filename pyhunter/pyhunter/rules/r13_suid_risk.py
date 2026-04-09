"""Rule 13 — SUID-RISK: Code that enables or relies on SUID / privilege escalation.

Detects:
  - os.setuid(0) / os.seteuid(0) — web process explicitly elevating to root
  - os.chmod with SUID/SGID bits (0o4000, 0o2000, 0o6000)
  - subprocess / os.system calls that reference SUID-abuse binaries
  - Code that explicitly checks it is running as root and continues
  - ctypes calling setuid (common privesc PoC pattern)

In a root chain: once RCE is achieved as www-data, these code patterns
or their presence on the filesystem are the final hop to root.
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain

# SUID-abusable binaries that appear in GTFObins / common privesc paths
_SUID_BINS = re.compile(
    r"\b(python3?|perl|ruby|node|vim|vi|nano|less|more|find|awk|nmap|"
    r"bash|sh|dash|zsh|env|tar|zip|unzip|cp|mv|install|tee|dd|"
    r"openssl|curl|wget|git|gcc|make|php|lua|ftp|socat|netcat|nc)\b",
    re.IGNORECASE,
)

# SUID / SGID bitmasks
_SUID_BITS = {0o4000, 0o2000, 0o6000, 0o4755, 0o6755}


def _is_zero(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value == 0


def _bitmask_has_suid(node: ast.expr) -> bool:
    """Return True if an integer literal has SUID/SGID bits set."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return bool(node.value & 0o6000)
    return False


def _str_contains_suid_bin(node: ast.expr) -> bool:
    """Return True if a string constant references a SUID-abusable binary."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(_SUID_BINS.search(node.value))
    if isinstance(node, ast.JoinedStr):
        for part in ast.walk(node):
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if _SUID_BINS.search(part.value):
                    return True
    return False


class SUIDRiskRule(BaseRule):
    rule_id     = "SUID-RISK"
    description = (
        "Code sets UID to root, applies SUID bits, or invokes SUID-abusable binaries — "
        "final hop in a privilege escalation chain after achieving initial RCE"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            lineno = node.lineno
            if lineno in seen:
                continue
            func = node.func
            chain = attr_chain(func.value) if isinstance(func, ast.Attribute) else ()
            method = (
                func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute)
                else None
            )
            if method is None:
                continue

            # os.setuid(0) / os.seteuid(0) — explicit privilege escalation
            if method in {"setuid", "seteuid", "setreuid", "setresuid"} and "os" in chain:
                if node.args and _is_zero(node.args[0]):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"os.{method}(0)",
                    ))

            # os.chmod(..., 0o4755) — setting SUID bit on a file
            elif method == "chmod" and "os" in chain:
                if len(node.args) >= 2 and _bitmask_has_suid(node.args[1]):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink="os.chmod(SUID/SGID bit)",
                    ))

            # ctypes.CDLL(None).setuid(0) — C-level privilege escalation
            elif method == "setuid" and node.args and _is_zero(node.args[0]):
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink="ctypes.setuid(0)",
                ))

            # subprocess/os.system calling SUID-abusable binary
            elif method in {"system", "popen"} and "os" in chain:
                if node.args and _str_contains_suid_bin(node.args[0]):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"os.{method}(suid_bin)",
                    ))

        return findings
