"""Tests for the CFG builder (Layer 1): AST function node → FunctionIR.

Checks:
  - Linear functions produce a single block with correct IR instructions
  - if/else creates a then-block, an else-block, and a merge-block
  - Loops create a header, body, and after-block with a back-edge
  - try/except connects try-body and all handlers to a join block
  - Sanitizer calls are lowered to IRSanitize, not IRAssign
  - Sinks appear as IRCall with is_sink=True
  - Source assignments are marked is_source=True with a non-empty source_desc
"""
from __future__ import annotations

import ast

import pytest

from pyhunter.taint.cfg import build_function_ir
from pyhunter.taint.ir  import (
    BasicBlock, FunctionIR,
    IRAssign, IRCall, IRSanitize,
)


def _build(src: str) -> FunctionIR:
    tree = ast.parse(src)
    func = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    return build_function_ir(func, "test.py")


def _all_stmts(ir: FunctionIR):
    """Flatten all IR statements across all blocks."""
    return [stmt for b in ir.blocks.values() for stmt in b.stmts]


# ── Block structure ───────────────────────────────────────────────────────────

class TestBlockStructure:
    def test_linear_function_has_entry_block(self):
        ir = _build("def f():\n    x = 1\n")
        assert ir.entry in ir.blocks

    def test_if_else_creates_at_least_three_blocks(self):
        src = """\
def f(cond):
    if cond:
        x = 1
    else:
        x = 2
    return x
"""
        ir = _build(src)
        # entry → then, else, merge + virtual exit = ≥4 blocks
        assert len(ir.blocks) >= 3

    def test_if_no_else_still_creates_merge(self):
        src = """\
def f(cond):
    x = 0
    if cond:
        x = 1
    return x
"""
        ir = _build(src)
        assert len(ir.blocks) >= 2

    def test_loop_creates_back_edge(self):
        src = """\
def f(items):
    for item in items:
        pass
"""
        ir = _build(src)
        # At least one block must have a predecessor that appears later in the
        # block-id sequence (= back-edge from loop body to header).
        has_back_edge = any(
            any(p > bid for p in block.predecessors)
            for bid, block in ir.blocks.items()
        )
        assert has_back_edge, "expected a back-edge for the loop"

    def test_try_except_connects_handler_to_join(self):
        src = """\
def f(x):
    try:
        y = x
    except ValueError:
        y = 0
    return y
"""
        ir = _build(src)
        # There must be a block with two or more predecessors (the join).
        join_candidates = [b for b in ir.blocks.values() if len(b.predecessors) >= 2]
        assert join_candidates, "expected a join block after try/except"

    def test_predecessor_successor_symmetry(self):
        """Every edge a→b must be reflected as b having a as predecessor."""
        src = """\
def f(cond, x):
    if cond:
        y = x
    else:
        y = 0
    return y
"""
        ir = _build(src)
        for bid, block in ir.blocks.items():
            for succ_id in block.successors:
                assert bid in ir.blocks[succ_id].predecessors, (
                    f"block {bid} → {succ_id} but {succ_id}.predecessors={ir.blocks[succ_id].predecessors}"
                )


# ── IR instruction lowering ───────────────────────────────────────────────────

class TestIRLowering:
    def test_source_assignment_marked_is_source(self):
        src = """\
from flask import request
def f():
    x = request.args.get("cmd")
"""
        ir = _build(src)
        assigns = [s for s in _all_stmts(ir) if isinstance(s, IRAssign)]
        source_assigns = [a for a in assigns if a.is_source]
        assert source_assigns, "expected at least one IRAssign with is_source=True"
        assert any("request" in a.source_desc for a in source_assigns)

    def test_clean_assignment_not_source(self):
        src = """\
def f():
    x = 42
"""
        ir = _build(src)
        assigns = [s for s in _all_stmts(ir) if isinstance(s, IRAssign)]
        assert all(not a.is_source for a in assigns)

    def test_sanitizer_call_lowered_to_ir_sanitize(self):
        src = """\
import shlex
def f(raw):
    safe = shlex.quote(raw)
"""
        ir = _build(src)
        sani = [s for s in _all_stmts(ir) if isinstance(s, IRSanitize)]
        assert sani, "expected an IRSanitize for shlex.quote"
        assert sani[0].sanitizer == "shlex.quote"
        assert "raw" in sani[0].source_vars

    def test_sink_call_lowered_to_ir_call_is_sink(self):
        src = """\
import os
def f(cmd):
    os.system(cmd)
"""
        ir = _build(src)
        calls = [s for s in _all_stmts(ir) if isinstance(s, IRCall)]
        sinks = [c for c in calls if c.is_sink]
        assert sinks, "expected an IRCall with is_sink=True for os.system"
        assert sinks[0].name == "system"
        assert sinks[0].module == "os"

    def test_plain_call_is_not_sink(self):
        src = """\
def f(x):
    print(x)
"""
        ir = _build(src)
        calls = [s for s in _all_stmts(ir) if isinstance(s, IRCall)]
        assert all(not c.is_sink for c in calls)

    def test_subprocess_shell_true_detected(self):
        src = """\
import subprocess
def f(cmd):
    subprocess.run(cmd, shell=True)
"""
        ir = _build(src)
        subprocess_calls = [
            s for s in _all_stmts(ir)
            if isinstance(s, IRCall) and s.name == "run"
        ]
        assert subprocess_calls
        assert subprocess_calls[0].shell_true is True

    def test_eval_sink_in_return(self):
        src = """\
def f(x):
    return eval(x)
"""
        ir = _build(src)
        calls = [s for s in _all_stmts(ir) if isinstance(s, IRCall) and s.is_sink]
        assert any(c.name == "eval" for c in calls)

    def test_arg_vars_captured_for_sink(self):
        src = """\
import os
def f(cmd):
    os.system(cmd)
"""
        ir = _build(src)
        calls = [s for s in _all_stmts(ir) if isinstance(s, IRCall) and s.is_sink]
        assert calls
        assert "cmd" in calls[0].arg_vars

    def test_aug_assign_includes_self_in_source_vars(self):
        src = """\
def f(request):
    cmd = "echo "
    cmd += request.args.get("x")
"""
        ir = _build(src)
        assigns = [s for s in _all_stmts(ir) if isinstance(s, IRAssign) and s.target == "cmd"]
        # The second assign (aug) must have "cmd" in source_vars
        aug_assigns = [a for a in assigns if "cmd" in a.source_vars]
        assert aug_assigns, "aug-assign must include old 'cmd' in source_vars"


# ── Async functions ───────────────────────────────────────────────────────────

class TestAsyncFunctions:
    def test_async_function_builds_ir(self):
        src = """\
async def handler(request):
    cmd = request.args.get("cmd")
    import os
    os.system(cmd)
"""
        ir = _build(src)
        assert ir.name == "handler"
        calls = [s for s in _all_stmts(ir) if isinstance(s, IRCall) and s.is_sink]
        assert calls

    def test_async_function_entry_block_exists(self):
        src = """\
async def f():
    pass
"""
        ir = _build(src)
        assert ir.entry in ir.blocks
