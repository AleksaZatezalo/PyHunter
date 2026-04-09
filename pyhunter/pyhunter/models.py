"""Shared data models for PyHunter findings."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single vulnerability finding produced by the scanner pipeline."""

    id: str                          # e.g. PY-RCE-001
    rule_id: str                     # internal rule identifier
    severity: Severity
    file: str
    line: int
    snippet: str                     # raw source code at the match site

    # Populated by Claude skills
    source: Optional[str] = None     # taint source (e.g. "request.args")
    sink: Optional[str] = None       # dangerous sink (e.g. "eval")
    explanation: Optional[str] = None
    poc: Optional[str] = None        # minimal exploit payload
    demo: Optional[str] = None       # runnable demo script
    exploitable: Optional[bool] = None
    false_positive_reason: Optional[str] = None

    # Raw metadata for debugging
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "source": self.source,
            "sink": self.sink,
            "explanation": self.explanation,
            "poc": self.poc,
            "demo": self.demo,
            "exploitable": self.exploitable,
            "false_positive_reason": self.false_positive_reason,
        }
