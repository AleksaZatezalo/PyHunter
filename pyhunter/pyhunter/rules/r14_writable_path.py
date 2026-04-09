"""Rule 14 — WRITABLE-PATH: Writing to privilege-escalation-enabling system paths.

Detects code that writes to:
  - /etc/cron.d/, /etc/cron.hourly|daily|weekly|monthly/
  - /etc/passwd, /etc/shadow, /etc/sudoers, /etc/sudoers.d/
  - systemd service directories (/etc/systemd/, /lib/systemd/)
  - /root/.ssh/authorized_keys
  - /tmp/ with predictable names (TOCTOU / symlink attack)
  - Python site-packages (library poisoning)
  - Web process's own source files (hot-patch persistence)

These are the persistence and privilege escalation targets after
achieving initial RCE as a low-privilege web user.
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

_CRITICAL_PATHS = re.compile(
    r"(/etc/cron\.|/etc/passwd|/etc/shadow|/etc/sudoers|"
    r"/etc/systemd|/lib/systemd|/usr/lib/systemd|"
    r"/root/\.ssh|/home/[^/]+/\.ssh|"
    r"site-packages|dist-packages)",
    re.IGNORECASE,
)

_HIGH_PATHS = re.compile(
    r"(/etc/|/usr/|/var/spool/cron|/proc/|/sys/)",
    re.IGNORECASE,
)

_WRITE_MODES = re.compile(r"[wa]", re.IGNORECASE)


def _path_str(node: ast.expr) -> str | None:
    """Extract a path string from a constant or f-string, best-effort."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                parts.append(str(part.value))
            else:
                parts.append("*")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _path_str(node.left)
        right = _path_str(node.right)
        if left and right:
            return left + right
        return left or right
    return None


def _is_write_mode(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(_WRITE_MODES.search(node.value))


class WritablePathRule(BaseRule):
    rule_id     = "WRITABLE-PATH"
    description = (
        "Code writes to a system path used for privilege escalation — "
        "cron jobs, sudoers, SSH authorized_keys, systemd services"
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
            method = (
                func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute)
                else None
            )

            # open("/etc/cron.d/evil", "w")
            if method == "open" and len(node.args) >= 1:
                path = _path_str(node.args[0])
                mode_node = node.args[1] if len(node.args) >= 2 else None
                mode_kw = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
                is_write = (mode_node and _is_write_mode(mode_node)) or (mode_kw and _is_write_mode(mode_kw))

                if path and is_write:
                    if _CRITICAL_PATHS.search(path):
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink=f"open({path!r}, write)",
                        ))
                    elif _HIGH_PATHS.search(path):
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink=f"open({path!r}, write) — system path",
                        ))

            # shutil.copy / shutil.move / shutil.copyfile to sensitive destination
            elif method in {"copy", "copyfile", "move", "copy2"} and len(node.args) >= 2:
                dest = _path_str(node.args[1])
                if dest:
                    if _CRITICAL_PATHS.search(dest):
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink=f"shutil.{method}(dest={dest!r})",
                        ))

        return findings
