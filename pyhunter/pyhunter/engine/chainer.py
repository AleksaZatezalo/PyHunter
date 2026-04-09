"""Chain engine: groups verified findings into multi-step exploit chains.

Each of the 15 rules belongs to an attack phase that maps to a stage in the
web-app-to-root kill chain.  When confirmed findings span two or more phases,
the Chainer identifies them as a chainable sequence and asks Claude to write
the end-to-end attack narrative.

Attack phases
─────────────
  1  Initial Access / RCE   — SSTI, DESER-RCE, CMD-INJECT, DEBUG-EXPOSED, FILE-UPLOAD-RCE
  2  Data Exfiltration       — SQL-INJECT, SSRF, XXE, PATH-TRAVERSAL
  3  Credential Theft        — HARDCODED-SECRET
  4  Auth / Privilege Bypass — AUTH-BYPASS, MASS-ASSIGN
  5  Host Privilege Escalation — SUID-RISK, WRITABLE-PATH, CONTAINER-ESCAPE
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from pyhunter.models import ExploitChain, Finding
from pyhunter.skills.chain import chain_skill

# ── Phase mapping ─────────────────────────────────────────────────────────────

PHASE_MAP: Dict[str, int] = {
    # Phase 1 — Initial Access / RCE
    "SSTI":             1,
    "DESER-RCE":        1,
    "CMD-INJECT":       1,
    "DEBUG-EXPOSED":    1,
    "FILE-UPLOAD-RCE":  1,
    # Phase 2 — Data Exfiltration / Lateral Movement
    "SQL-INJECT":       2,
    "SSRF":             2,
    "XXE":              2,
    "PATH-TRAVERSAL":   2,
    # Phase 3 — Credential Theft
    "HARDCODED-SECRET": 3,
    # Phase 4 — Auth / Privilege Bypass within the application
    "AUTH-BYPASS":      4,
    "MASS-ASSIGN":      4,
    # Phase 5 — Host-level Privilege Escalation
    "SUID-RISK":        5,
    "WRITABLE-PATH":    5,
    "CONTAINER-ESCAPE": 5,
}

PHASE_NAMES: Dict[int, str] = {
    1: "Initial Access / RCE",
    2: "Data Exfiltration",
    3: "Credential Theft",
    4: "Auth / Privilege Bypass",
    5: "Host Privilege Escalation",
}

# Natural "feeds-into" relationships between phases.
# The list order controls the attack timeline presented in chains.
_PHASE_ORDER = [4, 3, 2, 1, 5]   # auth-bypass → cred-theft → exfil → RCE → privesc

_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _sev(f: Finding) -> int:
    return _SEV_RANK.get(f.severity.value, 0)


# ── Chainer ───────────────────────────────────────────────────────────────────

class Chainer:
    """Identifies and narrates exploit chains from a list of confirmed findings."""

    async def build(self, findings: List[Finding]) -> List[ExploitChain]:
        """Return a list of ExploitChain objects (may be empty)."""
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

    # ── Candidate building ────────────────────────────────────────────────────

    def _build_candidates(
        self,
        by_phase: Dict[int, List[Finding]],
    ) -> List[List[Finding]]:
        """
        Build candidate chains.  Returns a list of finding-sequences for Claude
        to narrate.

        Candidates (in priority order, duplicates suppressed):
          1. Full chain — one best-severity finding per phase, ordered by attack
             timeline (_PHASE_ORDER).
          2. RCE → Host Privesc  (phases 1 + 5) — the canonical Docker escape.
          3. Auth Bypass → Data Exfil  (phases 4 + 2) — unauthenticated dump.
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
        full_order = [p for p in _PHASE_ORDER if p in present]
        add(full_order)

        # 2. RCE → Container / Host Privesc
        add([1, 5])

        # 3. Auth bypass → data exfiltration
        add([4, 2])

        return candidates[:3]
