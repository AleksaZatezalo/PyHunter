"""Base class for all AST detection rules."""
from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import List

from pyhunter.models import Finding


class BaseRule(ABC):
    rule_id:     str = ""
    description: str = ""

    @abstractmethod
    def check(self, tree: ast.AST, source_lines: List[str], filepath: str) -> List[Finding]:
        """Run the rule against a parsed AST. Return raw findings."""
        ...

    def _snippet(self, source_lines: List[str], lineno: int, context: int = 2) -> str:
        start = max(0, lineno - 1 - context)
        end   = min(len(source_lines), lineno + context)
        return "\n".join(source_lines[start:end]).strip()
