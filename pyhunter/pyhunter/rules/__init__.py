"""Base class for all AST-based detection rules."""

from __future__ import annotations
import ast
from abc import ABC, abstractmethod
from typing import List

from pyhunter.models import Finding


class BaseRule(ABC):
    """
    All rules follow the same contract:
      - receive an AST + source lines
      - return zero or more raw (pre-LLM) Finding objects

    The engine runs rules independently and merges results.
    """

    #: Human-readable rule ID, e.g. "RCE-EVAL"
    rule_id: str = ""

    #: One-line description shown in verbose output
    description: str = ""

    @abstractmethod
    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        """Run the rule against a parsed AST. Return raw findings."""
        ...

    # ------------------------------------------------------------------ helpers

    def _snippet(self, source_lines: List[str], lineno: int, context: int = 0) -> str:
        """Return the source line (1-indexed) with optional surrounding context."""
        start = max(0, lineno - 1 - context)
        end = min(len(source_lines), lineno + context)
        return "\n".join(source_lines[start:end]).strip()
