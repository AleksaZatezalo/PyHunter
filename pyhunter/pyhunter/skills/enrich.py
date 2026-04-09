"""LLM enrichment pipeline: analyze → explain → poc → demo → context."""
from __future__ import annotations

from typing import Optional

from pyhunter.models import Finding
from pyhunter.skills.analyze  import analyze
from pyhunter.skills.explain  import explain
from pyhunter.skills.poc      import poc
from pyhunter.skills.demo     import demo
from pyhunter.skills.context  import context


async def enrich(finding: Finding, skip_false_positives: bool = True) -> Optional[Finding]:
    """Run the full 5-stage LLM pipeline on one finding.

    Returns None if the finding is a false positive and skip_false_positives is True.
    """
    await analyze(finding)
    if skip_false_positives and finding.exploitable is False:
        return None
    await explain(finding)
    await poc(finding)
    await demo(finding)
    await context(finding)
    return finding
