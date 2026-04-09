"""Rule 08 — XXE: XML External Entity Injection.

Covers lxml (unsafe by default), xml.sax, xml.dom.minidom, and
xml.etree.ElementTree (flagged for completeness on pre-3.8 compatibility).
XXE chains into: local file read (/etc/passwd, SSH keys) → SSRF → RCE.
"""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import attr_chain


def _uses_lxml(node: ast.Call) -> bool:
    chain = attr_chain(node.func.value if isinstance(node.func, ast.Attribute) else ast.Name())
    return any(p in ("etree", "lxml") for p in chain)


def _resolve_entities_disabled(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "resolve_entities" and isinstance(kw.value, ast.Constant):
            return kw.value.value is False
    return False


def _has_safe_parser_kwarg(node: ast.Call) -> bool:
    return any(kw.arg == "parser" for kw in node.keywords)


class XXERule(BaseRule):
    rule_id     = "XXE"
    description = (
        "XML parsed without disabling external entity resolution — "
        "allows reading local files (/etc/passwd, SSH keys) and "
        "pivoting to internal services via SSRF"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            lineno = node.lineno
            if lineno in seen:
                continue

            method = func.attr
            chain = attr_chain(func.value)
            obj = chain[-1] if chain else ""

            # lxml.etree.XMLParser() without resolve_entities=False
            if method == "XMLParser" and any(p in chain for p in ("etree", "lxml")):
                if not _resolve_entities_disabled(node):
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink="lxml.XMLParser(resolve_entities=True[default])",
                    ))

            # lxml.etree.parse / fromstring / XML / HTML without safe parser kwarg
            elif method in {"parse", "fromstring", "XML", "HTML", "iterparse"}:
                if any(p in chain for p in ("etree", "lxml")):
                    if not _has_safe_parser_kwarg(node):
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink=f"lxml.{method}(no safe parser)",
                        ))

            # xml.sax.parseString / parse
            elif method in {"parseString", "parse"} and "sax" in chain:
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink=f"xml.sax.{method}",
                ))

            # xml.dom.minidom.parseString / parse
            elif method in {"parseString", "parse"} and "minidom" in chain:
                seen.add(lineno)
                findings.append(Finding(
                    id=f"{self.rule_id}-{lineno:04d}",
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    file=filepath,
                    line=lineno,
                    snippet=self._snippet(source_lines, lineno),
                    sink=f"xml.dom.minidom.{method}",
                ))

        return findings
