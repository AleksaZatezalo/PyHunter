"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    """One vulnerability finding produced by the scan pipeline."""

    # Identity
    id:       str
    rule_id:  str
    severity: Severity

    # Location
    file:    str
    line:    int
    snippet: str

    # Taint info (populated by engine)
    sink:   Optional[str] = None
    source: Optional[str] = None

    # LLM enrichment (populated by skills)
    exploitable:           Optional[bool]  = None
    confidence:            Optional[float] = None  # exploitability confidence [0.0–1.0]
    false_positive_reason: Optional[str]   = None
    analysis:              Optional[str]   = None  # exploitability rationale
    explanation:           Optional[str]  = None  # developer-friendly description
    poc:                   Optional[str]  = None  # minimal payload
    demo:                  Optional[str]  = None  # runnable exploit script
    context:               Optional[str]  = None  # standalone vs chained analysis

    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:

        return {
            "id":                    self.id,
            "rule_id":               self.rule_id,
            "severity":              self.severity.value,
            "file":                  self.file,
            "line":                  self.line,
            "snippet":               self.snippet,
            "sink":                  self.sink,
            "source":                self.source,
            "exploitable":           self.exploitable,
            "confidence":            self.confidence,
            "false_positive_reason": self.false_positive_reason,
            "analysis":              self.analysis,
            "explanation":           self.explanation,
            "poc":                   self.poc,
            "demo":                  self.demo,
            "context":               self.context,
        }

    def to_markdown(self) -> str:
        verdict = (
            "Exploitable"    if self.exploitable is True  else
            "False Positive" if self.exploitable is False else
            "Unknown"
        )
        lines = [
            f"# {self.id} — {self.rule_id}",
            "",
            f"| Field    | Value |",
            f"|----------|-------|",
            f"| Severity | **{self.severity.value}** |",
            f"| File     | `{self.file}` |",
            f"| Line     | {self.line} |",
            f"| Sink     | `{self.sink or '—'}` |",
            f"| Source   | `{self.source or '—'}` |",
            "",
            "**Snippet**",
            "",
            "```python",
            self.snippet or "",
            "```",
            "",
            "---",
            "",
            "## Analysis",
            "",
            f"**Verdict**: {verdict}",
        ]

        if self.false_positive_reason:
            lines += ["", f"**Reason**: {self.false_positive_reason}"]
        if self.analysis:
            lines += ["", self.analysis]

        lines += ["", "---", "", "## Explanation", ""]
        lines.append(self.explanation or "_Not available._")

        lines += ["", "---", "", "## Proof of Concept", ""]
        if self.poc:
            lines += ["```", self.poc, "```"]
        else:
            lines.append("_No safe PoC available._")

        lines += ["", "---", "", "## Demo", ""]
        if self.demo:
            lines += ["```python", self.demo, "```"]
        else:
            lines.append("_No demo available._")

        lines += ["", "---", "", "## Exploitation Context", ""]
        lines.append(self.context or "_Not available._")
        lines.append("")

        return "\n".join(lines)


_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


@dataclass
class ExploitChain:
    """A sequence of verified findings chained into a complete end-to-end attack path."""

    id:             str             # "CHAIN-001", "CHAIN-002", …
    title:          str             # "AUTH-BYPASS + SSTI → CONTAINER-ESCAPE"
    severity:       Severity        # maximum severity across all steps
    steps:          List[Finding]   # ordered findings in the attack sequence
    narrative:      str             # Claude-generated step-by-step attack story
    prerequisites:  str             # what the attacker needs to start
    impact:         str             # final attacker capability

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "title":         self.title,
            "severity":      self.severity.value,
            "steps":         [s.id for s in self.steps],
            "narrative":     self.narrative,
            "prerequisites": self.prerequisites,
            "impact":        self.impact,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# {self.id} — {self.title}",
            "",
            f"**Severity:** {self.severity.value}  |  **Steps:** {len(self.steps)}",
            "",
            "## Attack Steps",
            "",
        ]
        for i, step in enumerate(self.steps, 1):
            lines.append(
                f"{i}. **{step.rule_id}** — "
                f"`{step.file}:{step.line}` — "
                f"`{step.sink or '?'}`"
            )
        lines += [
            "",
            "## Attack Narrative",
            "",
            self.narrative,
            "",
            "## Prerequisites",
            "",
            self.prerequisites,
            "",
            "## Impact",
            "",
            self.impact,
            "",
        ]
        return "\n".join(lines)
