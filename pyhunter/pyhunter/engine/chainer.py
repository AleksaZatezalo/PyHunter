"""Exploit chain engine — groups confirmed findings into multi-step attack paths.

Design pattern: Chain of Responsibility (structural)
  Each confirmed finding is assigned to an attack phase. When findings span
  two or more phases the Chainer treats them as a chain: each phase "enables"
  the next, and Claude narrates the end-to-end attack story.

Attack phases for the current rule set
───────────────────────────────────────
  1  Initial Access    — attacker-controlled input reaches vulnerable code
                         FLOW-WEB, CMD-INJECT, DESER-RCE, FILE-UPLOAD, PICKLE-NET

  2  Code Execution    — the actual RCE mechanism triggered by that input
                         RCE-EVAL, EXEC-DECORATOR

  3  Supply Chain      — persistence: code runs at build/install/import time
                         RCE-BUILD, RCE-IMPORT

Example chains
  Phase 1 + 2 : FLOW-WEB → RCE-EVAL  (web input reaches eval())
  Phase 1 + 3 : FILE-UPLOAD → RCE-IMPORT  (uploaded file executed at import)
  All phases  : CMD-INJECT → RCE-EVAL → RCE-BUILD
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from pyhunter.models import ExploitChain, Finding
from pyhunter.skills.chain import chain_skill

# ── Phase mapping ─────────────────────────────────────────────────────────────

PHASE_MAP: Dict[str, int] = {
    # Phase 1 — Initial Access
    "FLOW-WEB":       1,
    "CMD-INJECT":     1,
    "DESER-RCE":      1,
    "FILE-UPLOAD":    1,
    "PICKLE-NET":     1,
    # Phase 2 — Code Execution
    "RCE-EVAL":       2,
    "EXEC-DECORATOR": 2,
    # Phase 3 — Supply Chain
    "RCE-BUILD":      3,
    "RCE-IMPORT":     3,
}

PHASE_NAMES: Dict[int, str] = {
    1: "Initial Access",
    2: "Code Execution",
    3: "Supply Chain",
}

# Attack timeline order: access → execution → persistence
_PHASE_ORDER = [1, 2, 3]

_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _sev(f: Finding) -> int:
    return _SEV_RANK.get(f.severity.value, 0)


# ── Chainer ───────────────────────────────────────────────────────────────────

class Chainer:
    """Identifies and narrates exploit chains from a list of confirmed findings."""

    async def build(self, findings: List[Finding]) -> List[ExploitChain]:
        """Return exploit chains (empty list if no multi-phase findings exist)."""
        exploitable = [f for f in findings if f.exploitable is True]
        if len(exploitable) < 2:
            return []

        by_phase: Dict[int, List[Finding]] = defaultdict(list)
        for f in exploitable:
            phase = PHASE_MAP.get(f.rule_id)
            if phase is not None:
                by_phase[phase].append(f)

        if len(by_phase) < 2:
            return []

        candidates = self._build_candidates(by_phase)
        chains: List[ExploitChain] = []
        for i, steps in enumerate(candidates, 1):
            c = await chain_skill(steps, chain_id=f"CHAIN-{i:03d}")
            if c:
                chains.append(c)
        return chains

    # ── Candidate construction ────────────────────────────────────────────────

    def _build_candidates(
        self,
        by_phase: Dict[int, List[Finding]],
    ) -> List[List[Finding]]:
        """
        Return up to 3 candidate chains in priority order (duplicates suppressed).

          1. Full chain — best-severity finding per phase, in attack-timeline order.
          2. Access → Execution  (phases 1 + 2) — web input reaching RCE.
          3. Access → Supply Chain  (phases 1 + 3) — uploaded/injected persistence.
        """
        def best(phase: int) -> Finding:
            return max(by_phase[phase], key=_sev)

        present = set(by_phase.keys())
        seen: set[frozenset[int]] = set()
        candidates: List[List[Finding]] = []

        def add(phases: List[int]) -> None:
            covered = [p for p in phases if p in present]
            if len(covered) < 2:
                return
            key = frozenset(covered)
            if key in seen:
                return
            seen.add(key)
            candidates.append([best(p) for p in covered])

        # 1. Full chain across all represented phases
        add([p for p in _PHASE_ORDER if p in present])

        # 2. Initial Access → Code Execution
        add([1, 2])

        # 3. Initial Access → Supply Chain
        add([1, 3])

        return candidates[:3]
