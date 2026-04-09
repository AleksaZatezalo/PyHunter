"""Scan pipeline: collect files → parse → rules + taint → async LLM enrichment."""
from __future__ import annotations

import ast
import asyncio
import sys
from pathlib import Path
from typing import Callable, List, Optional

from pyhunter.models import Finding
from pyhunter.rules.registry import all_rules
from pyhunter.taint import TaintEngine, TaintFlow
from pyhunter.skills.enrich import enrich

# Max concurrent Claude API requests — stays well under rate limits
_CONCURRENCY = 5


class Scanner:
    """
    Orchestrates the full scan pipeline.

    scan(target) → List[Finding]
        1. Collect .py files under target
        2. Parse each file: run rules + taint engine
        3. Merge taint flows into findings
        4. Enrich each finding via Claude (async, rate-limited)

    Callbacks:
        raw_findings_callback(findings)          — called after AST parse, before enrichment
        progress_callback(completed, total, f)   — called after each enrichment completes;
                                                   f is the enriched Finding or None if filtered
    """

    def __init__(
        self,
        use_llm:               bool                                          = True,
        skip_false_positives:  bool                                          = True,
        progress_callback:     Optional[Callable[[int, int, Optional[Finding]], None]] = None,
        raw_findings_callback: Optional[Callable[[List[Finding]], None]]     = None,
    ):
        self.rules                 = all_rules()
        self.taint                 = TaintEngine()
        self.use_llm               = use_llm
        self.skip_false_positives  = skip_false_positives
        self.progress_callback     = progress_callback
        self.raw_findings_callback = raw_findings_callback

    def scan(self, target: str) -> List[Finding]:
        files        = self._collect(Path(target))
        raw_findings = [f for path in files for f in self._parse(path)]
        if self.raw_findings_callback:
            self.raw_findings_callback(raw_findings)
        if not self.use_llm:
            return raw_findings
        return asyncio.run(self._enrich_all(raw_findings))

    # ── File collection ───────────────────────────────────────────────────────

    def _collect(self, path: Path) -> List[Path]:
        if path.is_file() and path.suffix == ".py":
            return [path]
        return list(path.rglob("*.py"))

    # ── Per-file parsing ──────────────────────────────────────────────────────

    def _parse(self, filepath: Path) -> List[Finding]:
        try:
            source       = filepath.read_text(encoding="utf-8", errors="replace")
            tree         = ast.parse(source, filename=str(filepath))
            source_lines = source.splitlines()
        except SyntaxError:
            return []

        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(tree, source_lines, str(filepath)))

        flows = self.taint.analyze(tree, source_lines, str(filepath))
        self._merge_taint(findings, flows)
        return findings

    # ── Taint merge ───────────────────────────────────────────────────────────

    def _merge_taint(self, findings: List[Finding], flows: List[TaintFlow]) -> None:
        index = {(f.sink, f.sink_line): f for f in flows}
        for finding in findings:
            if finding.sink is None or finding.source is not None:
                continue
            flow = index.get((finding.sink, finding.line))
            if flow is None:
                flow = next(
                    (f for (s, l), f in index.items()
                     if s == finding.sink and abs(l - finding.line) <= 5),
                    None,
                )
            if flow:
                finding.source = flow.source_expr

    # ── Async LLM enrichment ──────────────────────────────────────────────────

    async def _enrich_all(self, findings: List[Finding]) -> List[Finding]:
        total     = len(findings)
        completed = 0
        sem       = asyncio.Semaphore(_CONCURRENCY)

        async def enrich_and_track(f: Finding) -> Optional[Finding]:
            nonlocal completed
            async with sem:
                try:
                    result = await enrich(f, skip_false_positives=self.skip_false_positives)
                except Exception as exc:
                    print(f"\n  [!] Enrichment error ({f.id}): {exc}", file=sys.stderr)
                    result = f  # keep raw finding on API failure
            completed += 1
            if self.progress_callback:
                self.progress_callback(completed, total, result)
            return result

        results = await asyncio.gather(*[enrich_and_track(f) for f in findings])
        return [r for r in results if r is not None]
