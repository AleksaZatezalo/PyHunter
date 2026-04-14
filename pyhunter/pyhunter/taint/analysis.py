"""Worklist-based intra-procedural may-taint dataflow analysis (Layer 2).

Input:   FunctionIR (from cfg.py)
Output:  List[TaintPath] (typed Layer 2 → Layer 3 contract)

Algorithm
---------
May-taint is a forward, union-at-joins (over-approximating) analysis.

  Initialise taint_out[b] = {} for all blocks.
  Worklist ← all blocks (ensures every block is visited at least once).
  While worklist non-empty:
    block ← dequeue
    taint_in  ← join(taint_out[pred] for pred in block.predecessors)
    (new_state, block_paths) ← transfer_with_steps(block, taint_in, filepath)
    if new_state != taint_out[block]:
      taint_out[block] ← new_state
      worklist ← worklist ∪ successors(block)

Path collection is integrated into the transfer function (not a separate phase)
so that step lists are built from up-to-date predecessor states.  A seen_sinks
set ensures each (function, sink_label, lineno) is emitted at most once.

Since may-taint only adds (never removes) tainted variables, the state lattice
grows monotonically and the algorithm always terminates.
"""
from __future__ import annotations

import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from pyhunter.taint.ir import (
    BasicBlock, FunctionIR,
    IRAssign, IRCall, IRSanitize,
)
from pyhunter.taint.types import (
    PathStep, SourceLocation, StepKind, TaintPath,
)


# ── Per-variable taint state ──────────────────────────────────────────────────

@dataclass
class _TaintInfo:
    """Tracks how a variable became tainted, including its full step history."""

    source_desc: str
    source_line: int
    steps:       List[PathStep] = field(default_factory=list)
    sanitized:   bool           = False
    sanitizer:   Optional[str]  = None

    def copy(self) -> "_TaintInfo":
        return _TaintInfo(
            source_desc=self.source_desc,
            source_line=self.source_line,
            steps=list(self.steps),
            sanitized=self.sanitized,
            sanitizer=self.sanitizer,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _TaintInfo):
            return NotImplemented
        return (
            self.source_desc == other.source_desc
            and self.source_line == other.source_line
            and self.sanitized == other.sanitized
            and self.sanitizer == other.sanitizer
            # Intentionally ignore steps for convergence comparison — steps
            # are path metadata, not lattice elements.  Two states are equal
            # for convergence purposes when the same variables are tainted with
            # the same source / sanitizer metadata.
        )

    def __hash__(self) -> int:
        return hash((self.source_desc, self.source_line, self.sanitized, self.sanitizer))


_TaintState = Dict[str, _TaintInfo]   # variable name → info


# ── Join ──────────────────────────────────────────────────────────────────────

def _join(states: list[_TaintState]) -> _TaintState:
    """Union-at-joins: a variable is tainted if tainted on *any* predecessor."""
    result: _TaintState = {}
    for state in states:
        for var, info in state.items():
            if var not in result:
                result[var] = info.copy()
            # May-taint: keep the first path recorded (deterministic ordering).
    return result


def _pick_best(candidates: Set[str], state: _TaintState) -> str:
    """Return the candidate whose taint originates on the earliest source line."""
    return min(candidates, key=lambda n: state[n].source_line)


# ── Transfer function with step building ─────────────────────────────────────

def _transfer(
    block:    BasicBlock,
    taint_in: _TaintState,
    filepath: str,
) -> _TaintState:
    """Apply the block's IR statements to taint_in; return updated taint state.

    Step lists are built here so that the converged taint_out values carry
    complete path metadata for the path-collection pass.
    """
    state = {k: v.copy() for k, v in taint_in.items()}

    for stmt in block.stmts:

        if isinstance(stmt, IRAssign):
            if stmt.is_source:
                step = PathStep(
                    location    = SourceLocation(filepath, stmt.lineno),
                    variable    = stmt.target,
                    kind        = StepKind.SOURCE,
                    description = f"assigned from {stmt.source_desc}",
                )
                state[stmt.target] = _TaintInfo(
                    source_desc = stmt.source_desc,
                    source_line = stmt.lineno,
                    steps       = [step],
                )
            else:
                tainted_srcs = stmt.source_vars & state.keys()
                if tainted_srcs:
                    best = _pick_best(tainted_srcs, state)
                    prev = state[best]
                    step = PathStep(
                        location    = SourceLocation(filepath, stmt.lineno),
                        variable    = stmt.target,
                        kind        = StepKind.PROPAGATION,
                        description = f"propagated to `{stmt.target}`",
                    )
                    state[stmt.target] = _TaintInfo(
                        source_desc = prev.source_desc,
                        source_line = prev.source_line,
                        steps       = prev.steps + [step],
                        sanitized   = prev.sanitized,
                        sanitizer   = prev.sanitizer,
                    )

        elif isinstance(stmt, IRSanitize):
            tainted_srcs = stmt.source_vars & state.keys()
            if tainted_srcs:
                best = _pick_best(tainted_srcs, state)
                prev = state[best]
                step = PathStep(
                    location    = SourceLocation(filepath, stmt.lineno),
                    variable    = stmt.target,
                    kind        = StepKind.SANITIZATION,
                    description = f"sanitized by {stmt.sanitizer}() → `{stmt.target}`",
                    sanitizer   = stmt.sanitizer,
                )
                state[stmt.target] = _TaintInfo(
                    source_desc = prev.source_desc,
                    source_line = prev.source_line,
                    steps       = prev.steps + [step],
                    sanitized   = True,
                    sanitizer   = stmt.sanitizer,
                )

        # IRCall sinks do not introduce new tainted variables.

    return state


# ── Main worklist algorithm ───────────────────────────────────────────────────

def analyze_function(func_ir: FunctionIR, rule_id: str = "") -> List[TaintPath]:
    """Run worklist may-taint analysis on one function.

    Returns one TaintPath per unique (function, sink, line) combination where
    attacker-controlled data reaches a dangerous sink.

    The worklist is seeded with ALL blocks (not just the entry) so that every
    block is visited at least once, even when upstream blocks produce no taint.
    This is required for correct analysis of if-branches where taint is
    introduced inside the branch and flows to a post-branch sink.
    """
    taint_out: Dict[int, _TaintState] = {bid: {} for bid in func_ir.blocks}
    paths:     List[TaintPath]        = []
    seen:      Set[Tuple[str, str, int]] = set()  # (func_name, sink_label, lineno)

    # Seed with all blocks so every block is visited at least once.
    worklist: deque[int] = deque(func_ir.blocks.keys())

    while worklist:
        block_id = worklist.popleft()
        block    = func_ir.blocks[block_id]

        taint_in      = _join([taint_out[p] for p in block.predecessors])
        new_taint_out = _transfer(block, taint_in, func_ir.filepath)

        # Collect sink findings from this block using the fresh state.
        # We reconstitute intra-block taint progression for accurate step lists.
        intra = {k: v.copy() for k, v in taint_in.items()}
        for stmt in block.stmts:
            if isinstance(stmt, IRAssign):
                if stmt.is_source:
                    step = PathStep(
                        location    = SourceLocation(func_ir.filepath, stmt.lineno),
                        variable    = stmt.target,
                        kind        = StepKind.SOURCE,
                        description = f"assigned from {stmt.source_desc}",
                    )
                    intra[stmt.target] = _TaintInfo(
                        source_desc=stmt.source_desc,
                        source_line=stmt.lineno,
                        steps=[step],
                    )
                else:
                    tainted_srcs = stmt.source_vars & intra.keys()
                    if tainted_srcs:
                        best = _pick_best(tainted_srcs, intra)
                        prev = intra[best]
                        step = PathStep(
                            location    = SourceLocation(func_ir.filepath, stmt.lineno),
                            variable    = stmt.target,
                            kind        = StepKind.PROPAGATION,
                            description = f"propagated to `{stmt.target}`",
                        )
                        intra[stmt.target] = _TaintInfo(
                            source_desc=prev.source_desc,
                            source_line=prev.source_line,
                            steps=prev.steps + [step],
                            sanitized=prev.sanitized,
                            sanitizer=prev.sanitizer,
                        )

            elif isinstance(stmt, IRSanitize):
                tainted_srcs = stmt.source_vars & intra.keys()
                if tainted_srcs:
                    best = _pick_best(tainted_srcs, intra)
                    prev = intra[best]
                    step = PathStep(
                        location    = SourceLocation(func_ir.filepath, stmt.lineno),
                        variable    = stmt.target,
                        kind        = StepKind.SANITIZATION,
                        description = f"sanitized by {stmt.sanitizer}() → `{stmt.target}`",
                        sanitizer   = stmt.sanitizer,
                    )
                    intra[stmt.target] = _TaintInfo(
                        source_desc=prev.source_desc,
                        source_line=prev.source_line,
                        steps=prev.steps + [step],
                        sanitized=True,
                        sanitizer=stmt.sanitizer,
                    )

            elif isinstance(stmt, IRCall) and stmt.is_sink:
                tainted_args = stmt.arg_vars & intra.keys()
                if tainted_args:
                    sink_label = (
                        f"{stmt.module}.{stmt.name}" if stmt.module else stmt.name
                    )
                    dedup_key = (func_ir.name, sink_label, stmt.lineno)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        best = _pick_best(tainted_args, intra)
                        prev = intra[best]
                        sink_step = PathStep(
                            location    = SourceLocation(func_ir.filepath, stmt.lineno),
                            variable    = sink_label,
                            kind        = StepKind.SINK,
                            description = f"reaches sink {sink_label}()",
                        )
                        paths.append(TaintPath(
                            id            = uuid.uuid4().hex[:8],
                            rule_id       = rule_id,
                            source_label  = prev.source_desc,
                            sink_label    = sink_label,
                            function_name = func_ir.name,
                            filepath      = func_ir.filepath,
                            steps         = prev.steps + [sink_step],
                            sanitized     = prev.sanitized,
                            sanitizer     = prev.sanitizer,
                            finding_line  = stmt.lineno,
                        ))

        # Check for convergence — update and propagate only if taint state grew.
        if new_taint_out != taint_out[block_id]:
            taint_out[block_id] = new_taint_out
            for succ_id in block.successors:
                worklist.append(succ_id)

    return paths
