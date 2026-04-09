"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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
