"""LLM enrichment pipeline: analyze → taint → explain → poc → demo → context."""
from __future__ import annotations

from typing import Optional

from pyhunter.models import Finding
from pyhunter.skills.analyze     import analyze
from pyhunter.skills.taint_skill import analyze_taint_path
from pyhunter.skills.explain     import explain
from pyhunter.skills.poc         import poc
from pyhunter.skills.demo        import demo
from pyhunter.skills.context     import context


async def enrich(finding: Finding, skip_false_positives: bool = True) -> Optional[Finding]:
    """Run the full 6-stage LLM pipeline on one finding.

    Pipeline stages:
      1. analyze      — exploitability verdict + confidence
      2. taint        — taint path assessment + sanitizer bypass + chain potential
      3. explain      — developer-friendly description
      4. poc          — minimal safe payload
      5. demo         — runnable exploit script
      6. context      — standalone vs chained exploitation context

    Returns None if the finding is a false positive and skip_false_positives is True.
    """
    await analyze(finding)
    if skip_false_positives and finding.exploitable is False:
        return None
    # Stage 2: taint skill — only when a typed TaintPath was recorded.
    if finding.taint_path is not None:
        finding.taint_analysis = await analyze_taint_path(finding.taint_path)
    await explain(finding)
    await poc(finding)
    await demo(finding)
    await context(finding)
    return finding
