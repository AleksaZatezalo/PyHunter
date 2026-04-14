"""IR node types for the CFG-based taint analysis (Layer 1 internals).

AST nodes are lowered to these typed IR instructions before CFG construction so
that the dataflow analysis layer (analysis.py) never touches raw ast nodes.

These types are Layer 1 internal — they are NOT the layer boundary contract.
The Layer 1 → Layer 2 contract is FunctionIR (a graph of BasicBlocks of IRStmts).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Union


# ── Statement IR ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IRAssign:
    """target = <expr involving source_vars>.

    is_source=True  → the RHS is a recognised taint source (request.*, input(), …)
    source_vars     → variable names read from the RHS, used for propagation
    source_desc     → human-readable source label, empty string when not a source
    """

    lineno:      int
    target:      str
    source_vars: FrozenSet[str]
    is_source:   bool
    source_desc: str


@dataclass(frozen=True)
class IRSanitize:
    """target = sanitizer_fn(source_vars).

    Taint flows through sanitized variables but is flagged so the LLM skill can
    assess bypass risk.
    """

    lineno:      int
    target:      str
    source_vars: FrozenSet[str]
    sanitizer:   str   # "shlex.quote", "html.escape", …


@dataclass(frozen=True)
class IRCall:
    """A call site — may be a sink, a helper, or a harmless function."""

    lineno:     int
    module:     Optional[str]   # None for bare names (eval, exec, open)
    name:       str
    arg_vars:   FrozenSet[str]  # variable names passed as arguments
    is_sink:    bool
    shell_true: bool            # subprocess.* called with shell=True


IRStmt = Union[IRAssign, IRSanitize, IRCall]


# ── CFG structure ─────────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    """A maximal straight-line sequence of IR statements with no internal branches."""

    id:           int
    stmts:        List[IRStmt] = field(default_factory=list)
    successors:   List[int]    = field(default_factory=list)
    predecessors: List[int]    = field(default_factory=list)


@dataclass
class FunctionIR:
    """Complete CFG for one function — the Layer 1 → Layer 2 contract.

    The CFG builder (cfg.py) produces a FunctionIR and the dataflow analysis
    (analysis.py) consumes it, so neither layer needs the other's internals.
    """

    name:     str
    filepath: str
    entry:    int                        # entry block ID
    blocks:   Dict[int, BasicBlock] = field(default_factory=dict)
