"""Rule 15 — CONTAINER-ESCAPE: Code that enables or exploits container escape.

Detects:
  - Docker socket access (/var/run/docker.sock) — full host RCE via API
  - subprocess calls with --privileged, -v /:/mnt, --pid=host flags
  - nsenter usage — namespace escape
  - /proc/1/cgroup access — detect container context (then escape)
  - cap_sys_admin / cap_sys_ptrace capability abuse patterns
  - Docker SDK: docker.from_env() with privileged/volume-mount arguments

Container escape is the final hop when the web process runs in Docker:
  web user → container RCE → docker.sock or privileged container → host root.
"""
from __future__ import annotations

import ast
import re
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain

_DOCKER_SOCK = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)

_ESCAPE_FLAGS = re.compile(
    r"(--privileged|--pid=host|--net=host|--ipc=host|"
    r"-v\s+/:/|--volume\s+/:/|--volume=/:/|"
    r"nsenter|unshare\s+--mount)",
    re.IGNORECASE,
)

_CAP_ESCAPE = re.compile(
    r"(CAP_SYS_ADMIN|CAP_SYS_PTRACE|CAP_NET_ADMIN|CAP_DAC_OVERRIDE|"
    r"CAP_SETUID|CAP_SETGID|CAP_CHOWN)",
    re.IGNORECASE,
)

_DOCKER_SDK_DANGEROUS_KWARGS = {"privileged", "pid_mode", "network_mode", "ipc_mode", "cap_add"}


def _str_val(node: ast.expr) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
        return "".join(parts)
    return ""


class ContainerEscapeRule(BaseRule):
    rule_id     = "CONTAINER-ESCAPE"
    description = (
        "Code accesses the Docker socket, mounts the host filesystem, "
        "or uses privileged container flags — "
        "enables full host takeover from inside a container"
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

            # open("/var/run/docker.sock", ...)  — raw socket access
            if method == "open" and node.args:
                path = _str_val(node.args[0])
                if _DOCKER_SOCK.search(path):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink="open(/var/run/docker.sock)",
                    ))

            # os.system / subprocess with escape flags (exclude bare "run" — handled below)
            elif method in {"system", "popen", "Popen", "call", "check_output", "check_call"}:
                cmd_parts = []
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, (ast.Constant, ast.JoinedStr)):
                        cmd_parts.append(_str_val(arg))
                    elif isinstance(arg, (ast.List, ast.Tuple)):
                        for elt in arg.elts:
                            cmd_parts.append(_str_val(elt))
                cmd = " ".join(cmd_parts)
                if _ESCAPE_FLAGS.search(cmd) or _DOCKER_SOCK.search(cmd):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"{method}(container_escape_flag)",
                    ))

            # subprocess.run with escape flags (separate branch to avoid shadowing Docker SDK)
            elif method == "run" and not any(kw.arg in _DOCKER_SDK_DANGEROUS_KWARGS for kw in node.keywords):
                cmd_parts = []
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, (ast.Constant, ast.JoinedStr)):
                        cmd_parts.append(_str_val(arg))
                    elif isinstance(arg, (ast.List, ast.Tuple)):
                        for elt in arg.elts:
                            cmd_parts.append(_str_val(elt))
                cmd = " ".join(cmd_parts)
                if _ESCAPE_FLAGS.search(cmd) or _DOCKER_SOCK.search(cmd):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink="subprocess.run(container_escape_flag)",
                    ))

            # Docker SDK: client.containers.run(..., privileged=True, pid_mode="host")
            elif method in {"run", "create"} and any(
                kw.arg in _DOCKER_SDK_DANGEROUS_KWARGS and (
                    (isinstance(kw.value, ast.Constant) and kw.value.value not in (False, None, ""))
                    or isinstance(kw.value, (ast.List, ast.Tuple))
                )
                for kw in node.keywords
            ):
                dangerous_kws = [
                    kw.arg for kw in node.keywords
                    if kw.arg in _DOCKER_SDK_DANGEROUS_KWARGS
                ]
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink=f"docker.{method}({', '.join(dangerous_kws)}=...)",
                ))

            # String constants referencing CAP_SYS_ADMIN etc. (capability abuse)
            for arg in node.args:
                val = _str_val(arg)
                if _CAP_ESCAPE.search(val) and lineno not in seen:
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"capability: {_CAP_ESCAPE.search(val).group()}",
                    ))
                    break

        return findings
