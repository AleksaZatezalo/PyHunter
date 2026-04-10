"""Scan pipeline: collect files → parse → rules + taint → async LLM enrichment → chain.

Design pattern: Pipeline (behavioural)
  Each stage of Scanner.scan() transforms its input into the input for the next:

    _collect()          Path          → List[Path]       (file discovery)
    _parse()            Path          → List[Finding]    (AST rules + taint)
    _merge_taint()      findings      → findings         (annotate source fields)
    _enrich_all()       findings      → findings         (Claude exploitability)
    Chainer.build()     findings      → ExploitChains    (multi-phase chain analysis)

  Each stage is a private method with a single responsibility. The public
  scan() method is the only entry point.
"""
from __future__ import annotations

import ast
import asyncio
import sys
from pathlib import Path
from typing import Callable, List, Optional

from pyhunter.config import load_config
from pyhunter.engine.chainer import Chainer
from pyhunter.models import ExploitChain, Finding
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
        3. Merge taint flows into findings (populates Finding.source)
        4. Enrich each finding via Claude (async, rate-limited)
        5. Build exploit chains from confirmed findings (async, Claude-narrated)

    After scan() returns, ``scanner.chains`` holds any ExploitChain objects.

    Callbacks (set before calling scan):
        raw_findings_callback(findings)          — after AST parse, before enrichment
        progress_callback(completed, total, f)   — after each enrichment completes;
                                                   f is the enriched Finding or None
                                                   if filtered as a false positive
    """

    def __init__(
        self,
        use_llm:               bool                                          = True,
        skip_false_positives:  bool                                          = True,
        progress_callback:     Optional[Callable[[int, int, Optional[Finding]], None]] = None,
        raw_findings_callback: Optional[Callable[[List[Finding]], None]]     = None,
    ):
        cfg              = load_config()
        disabled         = set(cfg.get("disabled_rules", []))
        self.rules       = [r for r in all_rules() if r.rule_id not in disabled]
        self.taint       = TaintEngine()
        self.use_llm               = use_llm
        self.skip_false_positives  = skip_false_positives
        self.progress_callback     = progress_callback
        self.raw_findings_callback = raw_findings_callback
        self.chains: List[ExploitChain] = []

    def scan(self, target: str) -> List[Finding]:
        files        = self._collect(Path(target))
        raw_findings = [f for path in files for f in self._parse(path)]
        if self.raw_findings_callback:
            self.raw_findings_callback(raw_findings)
        if not self.use_llm:
            return raw_findings
        return asyncio.run(self._enrich_and_chain(raw_findings))

    # ── Stage 1: file collection ──────────────────────────────────────────────

    def _collect(self, path: Path) -> List[Path]:
        if path.is_file() and path.suffix == ".py":
            return [path]
        return list(path.rglob("*.py"))

    # ── Stage 2: per-file parsing ─────────────────────────────────────────────

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

    # ── Stage 3: taint merge ──────────────────────────────────────────────────

    def _merge_taint(self, findings: List[Finding], flows: List[TaintFlow]) -> None:
        """Annotate Finding.source using standalone taint-engine flows."""
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

    # ── Stages 4 + 5: async enrichment and chain analysis ────────────────────

    async def _enrich_and_chain(self, findings: List[Finding]) -> List[Finding]:
        enriched    = await self._enrich_all(findings)
        self.chains = await Chainer().build(enriched)
        return enriched

    async def _enrich_all(self, findings: List[Finding]) -> List[Finding]:
        total     = len(findings)
        completed = 0
        sem       = asyncio.Semaphore(_CONCURRENCY)

        async def _enrich_one(f: Finding) -> Optional[Finding]:
            nonlocal completed
            async with sem:
                try:
                    result = await enrich(f, skip_false_positives=self.skip_false_positives)
                except Exception as exc:
                    print(f"\n  [!] Enrichment error ({f.id}): {exc}", file=sys.stderr)
                    result = f
            completed += 1
            if self.progress_callback:
                self.progress_callback(completed, total, result)
            return result

        results = await asyncio.gather(*[_enrich_one(f) for f in findings])
        return [r for r in results if r is not None]
