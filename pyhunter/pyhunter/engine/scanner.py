"""
PyHunter scanning engine.

Pipeline per file:
  1. AST rules   → raw Finding list (pattern matches)
  2. Taint engine → TaintFlow list (source→sink confirmation)
  3. Merge        → annotate findings with confirmed source info
  4. LLM skills  → analyze, explain, poc, demo (if use_llm=True)
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from pyhunter.models import Finding
from pyhunter.rules.registry import all_rules
from pyhunter.taint import TaintEngine, TaintFlow
from pyhunter.skills import analyze as _analyze_mod
from pyhunter.skills import explain as _explain_mod
from pyhunter.skills import poc as _poc_mod
from pyhunter.skills import demo as _demo_mod


class Scanner:
    """
    Orchestrates the full scan pipeline.

    Usage:
        scanner = Scanner(use_llm=True)
        findings = scanner.scan("/path/to/project")
    """

    def __init__(self, use_llm: bool = True, skip_false_positives: bool = True):
        self.rules = all_rules()
        self.taint = TaintEngine()
        self.use_llm = use_llm
        self.skip_false_positives = skip_false_positives

    # ── public ────────────────────────────────────────────────────────────────

    def scan(self, target: str) -> List[Finding]:
        """Scan a file or directory tree. Returns enriched findings."""
        target_path = Path(target)
        python_files = self._collect_files(target_path)

        raw_findings: List[Finding] = []
        for filepath in python_files:
            raw_findings.extend(self._scan_file(filepath))

        if not self.use_llm:
            return raw_findings

        return self._enrich(raw_findings)

    # ── file-level analysis ───────────────────────────────────────────────────

    def _collect_files(self, path: Path) -> List[Path]:
        if path.is_file() and path.suffix == ".py":
            return [path]
        return list(path.rglob("*.py"))

    def _scan_file(self, filepath: Path) -> List[Finding]:
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(filepath))
            source_lines = source.splitlines()
        except SyntaxError:
            return []

        # AST rules → raw findings
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(tree, source_lines, str(filepath)))

        # Taint engine → confirmed flows
        flows = self.taint.analyze(tree, source_lines, str(filepath))

        # Merge: annotate findings with taint source where confirmed
        self._merge_taint(findings, flows)

        return findings

    def _merge_taint(self, findings: List[Finding], flows: List[TaintFlow]) -> None:
        """
        For each finding whose sink matches a confirmed taint flow at the same
        line, annotate finding.source with the taint origin.
        """
        # Index flows by (sink, sink_line)
        flow_index: dict[tuple[str, int], TaintFlow] = {}
        for flow in flows:
            # Normalise sink name to match Finding.sink format
            key = (flow.sink, flow.sink_line)
            flow_index[key] = flow

        for finding in findings:
            if finding.sink is None or finding.source is not None:
                continue
            # Try exact match first
            flow = flow_index.get((finding.sink, finding.line))
            if flow:
                finding.source = flow.source_expr
                finding.extra["taint_vars"] = flow.tainted_vars
                finding.extra["taint_source_line"] = flow.source_line
                continue

            # Fuzzy: same file + sink name anywhere nearby (±5 lines)
            for (sink, line), flow in flow_index.items():
                if sink == finding.sink and abs(line - finding.line) <= 5:
                    finding.source = flow.source_expr
                    finding.extra["taint_vars"] = flow.tainted_vars
                    break

    # ── LLM enrichment ────────────────────────────────────────────────────────

    def _enrich(self, findings: List[Finding]) -> List[Finding]:
        """Run each finding through the four-stage Claude skill pipeline."""
        enriched: List[Finding] = []
        for finding in findings:
            finding = _analyze_mod.analyze(finding)

            if self.skip_false_positives and finding.exploitable is False:
                continue

            finding = _explain_mod.explain(finding)
            finding = _poc_mod.poc(finding)
            finding = _demo_mod.demo(finding)

            enriched.append(finding)

        return enriched
