"""Rule: XML External Entity (XXE) injection via unsafe XML parsers."""
from __future__ import annotations

import ast
from typing import List

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule

# lxml functions that parse XML and are unsafe by default
_LXML_PARSE_FUNCS = {"parse", "fromstring", "XML", "HTML", "iterparse"}

# Standard library etree is safe for XXE, but flag explicit unsafe usage
# lxml XMLParser with resolve_entities left as default (True)


def _attr_chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _kw_is_true(keywords: list[ast.keyword], name: str) -> bool:
    for kw in keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _kw_is_false(keywords: list[ast.keyword], name: str) -> bool:
    for kw in keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _uses_lxml(node: ast.Call) -> bool:
    chain = _attr_chain(node.func)
    return any(part in ("etree", "lxml") for part in chain)


class XXERule(BaseRule):
    rule_id     = "XXE"
    description = (
        "XML parsed with lxml without disabling external entity resolution — "
        "potential XXE injection"
    )

    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        seen: set[int] = set()

        # Track XMLParser() calls that enable resolve_entities
        unsafe_parsers: set[str] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            lineno = node.lineno
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue

            # lxml.etree.XMLParser(resolve_entities=True) — explicitly unsafe
            if func.attr == "XMLParser" and _uses_lxml(node):
                if not _kw_is_false(node.keywords, "resolve_entities"):
                    # Default is True, so no kwarg or True = unsafe
                    # Track the assigned variable name
                    if lineno not in seen:
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink="lxml.XMLParser(resolve_entities=True)",
                        ))

            # lxml.etree.parse / fromstring / XML etc. without a safe parser argument
            elif func.attr in _LXML_PARSE_FUNCS and _uses_lxml(node):
                # Flag if no 'parser' kwarg is provided (defaults to unsafe)
                has_safe_parser = any(kw.arg == "parser" for kw in node.keywords)
                if not has_safe_parser and lineno not in seen:
                    seen.add(lineno)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        file=filepath,
                        line=lineno,
                        snippet=self._snippet(source_lines, lineno),
                        sink=f"lxml.{func.attr}",
                    ))

            # xml.sax.make_parser / parseString without feature_external_ges disabled
            elif func.attr in {"parseString", "parse"} and not _uses_lxml(node):
                chain = _attr_chain(func.value)
                if "sax" in chain:
                    if lineno not in seen:
                        seen.add(lineno)
                        findings.append(Finding(
                            id=f"{self.rule_id}-{lineno:04d}",
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file=filepath,
                            line=lineno,
                            snippet=self._snippet(source_lines, lineno),
                            sink="xml.sax.parse",
                        ))

        return findings
