"""Typed boundary contracts for the four-layer taint analysis pipeline.

Layer boundaries
----------------
  Layer 1  (Program Representation)  → Layer 2 (Taint Propagation):   FunctionIR  (ir.py)
  Layer 2  (Taint Propagation)        → Layer 3 (LLM Reasoning):       TaintPath   (this module)
  Layer 3  (LLM Reasoning)            → Layer 4 (Output):              TaintAnalysis (this module)

No layer passes raw AST nodes or untyped dicts across its boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


@dataclass(frozen=True)
class SourceLocation:
    """File + line — the atomic unit of position in all layer contracts."""

    file: str
    line: int


class StepKind(str, Enum):
    """Semantic classification of a taint propagation step."""

    SOURCE       = "source"
    PROPAGATION  = "propagation"
    SANITIZATION = "sanitization"
    SINK         = "sink"


@dataclass(frozen=True)
class PathStep:
    """One hop in a typed taint propagation path.

    frozen=True makes each step immutable so that path lists can be safely
    copied during building without aliasing bugs.
    """

    location:    SourceLocation
    variable:    str
    kind:        StepKind
    description: str
    sanitizer:   Optional[str] = None


@dataclass
class TaintPath:
    """A complete, typed source-to-sink taint path.

    This is the Layer 2 → Layer 3 contract: the CFG-based analysis emits
    TaintPath objects; the LLM skill consumes them without needing AST nodes
    or raw dict lists.
    """

    id:            str
    rule_id:       str
    source_label:  str          # e.g. "request.args.get"
    sink_label:    str          # e.g. "os.system"
    function_name: str
    filepath:      str
    steps:         List[PathStep]
    sanitized:     bool
    sanitizer:     Optional[str]
    finding_line:  int

    # ── Accessors ──────────────────────────────────────────────────────────────

    def source_line(self) -> Optional[int]:
        for step in self.steps:
            if step.kind == StepKind.SOURCE:
                return step.location.line
        return None

    def sink_step(self) -> Optional[PathStep]:
        for step in reversed(self.steps):
            if step.kind == StepKind.SINK:
                return step
        return None

    # ── Serialisation — backward-compatible step format ───────────────────────

    def to_step_dicts(self) -> List[dict]:
        """Return steps in the legacy [{line, variable, description}, …] format.

        Used by Finding.to_dict() so JSON consumers see no breaking change.
        """
        return [
            {
                "line":        s.location.line,
                "variable":    s.variable,
                "description": s.description,
            }
            for s in self.steps
        ]

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "rule_id":       self.rule_id,
            "source_label":  self.source_label,
            "sink_label":    self.sink_label,
            "function_name": self.function_name,
            "filepath":      self.filepath,
            "steps":         self.to_step_dicts(),
            "sanitized":     self.sanitized,
            "sanitizer":     self.sanitizer,
            "finding_line":  self.finding_line,
        }


@dataclass
class TaintAnalysis:
    """Typed result of the LLM taint-path skill — the Layer 3 → Layer 4 contract.

    Unlike the old ``taint_assessment: str``, this struct carries parsed sections
    so downstream consumers can act on specific parts without string parsing.
    """

    path_id:               str
    sanitizer_bypass_risk: Optional[str]   # None when no sanitizer in path
    chain_potential:       str
    assessment:            str             # full Claude response text
