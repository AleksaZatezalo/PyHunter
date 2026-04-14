"""CFG builder: AST function node → FunctionIR (Layer 1).

Design
------
Lowers Python AST statements to typed IR instructions and connects them into
a Control-Flow Graph of BasicBlocks.

Supported constructs
--------------------
- Linear statements: Assign, AnnAssign, AugAssign, Expr(Call), Return
- Branches:         if / elif / else  (creates then-block, else-block, merge-block)
- Loops:            for / while       (header → body → header back-edge, header → exit)
- Exception:        try / except      (try-body → join; each handler → join)
- Context mgr:      with / async with (flattened — body treated as linear)
- Nested defs:      skipped (intra-procedural only)

Entry point: ``build_function_ir(func_node, filepath) -> FunctionIR``
"""
from __future__ import annotations

import ast
from typing import List, Optional, Tuple

from pyhunter.taint.ir import (
    BasicBlock, FunctionIR,
    IRAssign, IRCall, IRSanitize, IRStmt,
)
# Import from _helpers.py (not taint/__init__.py) to avoid circular imports.
from pyhunter.taint._helpers import (
    _SANITIZER_KEYS, _SINKS,
    _attr_chain, _call_arg_names, _call_key, _is_source, _names, _unpack_names,
)


# ── AST helpers ───────────────────────────────────────────────────────────────

def _get_source_desc(expr: ast.expr) -> str:
    """Human-readable label for a recognised taint source expression."""
    chain = _attr_chain(expr)
    if chain:
        return ".".join(chain)
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Attribute):
            chain = _attr_chain(func.value)
            prefix = ".".join(chain) if chain else ""
            return f"{prefix}.{func.attr}".lstrip(".")
        if isinstance(func, ast.Name):
            return func.id
    return "user input"


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if (
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
        ):
            return True
    return False


# ── IR lowering ───────────────────────────────────────────────────────────────

def _lower_assign(stmt: ast.Assign) -> Optional[IRAssign | IRSanitize]:
    """Lower an ``ast.Assign`` to an IR instruction.

    Sanitizer calls (``x = shlex.quote(y)``) are lowered to ``IRSanitize``;
    everything else becomes ``IRAssign``.

    Only the *first* target is kept (tuple unpacking is approximated as a
    single assignment — sufficient for the taint analysis use case).
    """
    if isinstance(stmt.value, ast.Call):
        key = _call_key(stmt.value)
        if key in _SANITIZER_KEYS:
            arg_vars = frozenset(_call_arg_names(stmt.value))
            san = f"{key[0]}.{key[1]}" if key[0] else key[1]
            for target in stmt.targets:
                for name in _unpack_names(target):
                    return IRSanitize(
                        lineno=stmt.lineno,
                        target=name,
                        source_vars=arg_vars,
                        sanitizer=san,
                    )

    is_src = _is_source(stmt.value)
    src_vars = frozenset() if is_src else frozenset(_names(stmt.value))
    src_desc = _get_source_desc(stmt.value) if is_src else ""

    for target in stmt.targets:
        for name in _unpack_names(target):
            return IRAssign(
                lineno=stmt.lineno,
                target=name,
                source_vars=src_vars,
                is_source=is_src,
                source_desc=src_desc,
            )
    return None


def _lower_call(call: ast.Call, lineno: int) -> Optional[IRCall]:
    """Lower a call node to IRCall, or return None for unrecognised call shapes."""
    key = _call_key(call)
    if key is None:
        return None
    return IRCall(
        lineno=lineno,
        module=key[0],
        name=key[1],
        arg_vars=frozenset(_call_arg_names(call)),
        is_sink=key in _SINKS,
        shell_true=_has_shell_true(call),
    )


def _lower_for_iter(stmt: ast.For) -> Optional[IRAssign]:
    """Model ``for target in iter:`` as ``target = iter`` for taint propagation."""
    targets = _unpack_names(stmt.target)
    if not targets:
        return None
    is_src = _is_source(stmt.iter)
    src_vars = frozenset() if is_src else frozenset(_names(stmt.iter))
    return IRAssign(
        lineno=stmt.lineno,
        target=targets[0],
        source_vars=src_vars,
        is_source=is_src,
        source_desc=_get_source_desc(stmt.iter) if is_src else "",
    )


# ── CFG builder ───────────────────────────────────────────────────────────────

class _CFGBuilder:
    """Stateful builder that walks one function and produces a FunctionIR."""

    def __init__(self, filepath: str) -> None:
        self._filepath = filepath
        self._blocks: dict[int, BasicBlock] = {}
        self._next_id = 0

    # ── Block management ─────────────────────────────────────────────────────

    def _new_block(self) -> BasicBlock:
        b = BasicBlock(id=self._next_id)
        self._blocks[self._next_id] = b
        self._next_id += 1
        return b

    def _connect(self, pred: BasicBlock, succ: BasicBlock) -> None:
        if succ.id not in pred.successors:
            pred.successors.append(succ.id)
        if pred.id not in succ.predecessors:
            succ.predecessors.append(pred.id)

    # ── Statement processing ─────────────────────────────────────────────────

    def _build_body(
        self,
        stmts: list[ast.stmt],
        current: BasicBlock,
        exit_b: BasicBlock,
    ) -> BasicBlock:
        """Process a list of statements, return the last active block."""
        for stmt in stmts:
            result = self._build_one(stmt, current, exit_b)
            if result is not None:
                current = result
        return current

    def _build_one(
        self,
        stmt: ast.stmt,
        current: BasicBlock,
        exit_b: BasicBlock,
    ) -> Optional[BasicBlock]:
        """Lower one AST statement into IR, possibly creating successor blocks."""

        # ── Simple statements ─────────────────────────────────────────────────
        if isinstance(stmt, ast.Assign):
            ir = _lower_assign(stmt)
            if ir:
                current.stmts.append(ir)
            # The RHS call might also be a sink (e.g. ``x = eval(y)``).
            if isinstance(stmt.value, ast.Call):
                ir2 = _lower_call(stmt.value, stmt.lineno)
                if ir2 and ir2.is_sink:
                    current.stmts.append(ir2)
            return current

        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            # Lower as a regular assignment with a single target.
            is_src = _is_source(stmt.value)
            src_vars = frozenset() if is_src else frozenset(_names(stmt.value))
            for name in _unpack_names(stmt.target):
                current.stmts.append(IRAssign(
                    lineno=stmt.lineno,
                    target=name,
                    source_vars=src_vars,
                    is_source=is_src,
                    source_desc=_get_source_desc(stmt.value) if is_src else "",
                ))
            return current

        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            # ``x += y`` — model as ``x = old_x ∪ y``
            rhs_vars = frozenset(_names(stmt.value))
            is_src = _is_source(stmt.value)
            current.stmts.append(IRAssign(
                lineno=stmt.lineno,
                target=stmt.target.id,
                source_vars=rhs_vars | {stmt.target.id},
                is_source=is_src,
                source_desc=_get_source_desc(stmt.value) if is_src else "",
            ))
            return current

        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            ir = _lower_call(stmt.value, stmt.lineno)
            if ir:
                current.stmts.append(ir)
            return current

        if isinstance(stmt, ast.Return) and stmt.value is not None:
            if isinstance(stmt.value, ast.Call):
                ir = _lower_call(stmt.value, stmt.lineno)
                if ir:
                    current.stmts.append(ir)
            return current

        # ── Compound statements ───────────────────────────────────────────────
        if isinstance(stmt, ast.If):
            return self._build_if(stmt, current, exit_b)

        if isinstance(stmt, (ast.For, ast.While)):
            return self._build_loop(stmt, current, exit_b)

        if isinstance(stmt, ast.Try):
            return self._build_try(stmt, current, exit_b)

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            # Flatten context manager body.
            for item in stmt.items:
                if item.optional_vars is not None:
                    for name in _unpack_names(item.optional_vars):
                        # Approximate: treat context var as clean.
                        current.stmts.append(IRAssign(
                            lineno=stmt.lineno,
                            target=name,
                            source_vars=frozenset(),
                            is_source=False,
                            source_desc="",
                        ))
            return self._build_body(stmt.body, current, exit_b)

        # Nested function/class defs, imports, etc. — skip (intra-procedural).
        return current

    # ── Compound statement builders ───────────────────────────────────────────

    def _build_if(
        self,
        stmt: ast.If,
        current: BasicBlock,
        exit_b: BasicBlock,
    ) -> BasicBlock:
        merge_b = self._new_block()

        then_b = self._new_block()
        self._connect(current, then_b)
        then_exit = self._build_body(stmt.body, then_b, exit_b)
        self._connect(then_exit, merge_b)

        if stmt.orelse:
            else_b = self._new_block()
            self._connect(current, else_b)
            else_exit = self._build_body(stmt.orelse, else_b, exit_b)
            self._connect(else_exit, merge_b)
        else:
            # No else branch: current flows directly to merge.
            self._connect(current, merge_b)

        return merge_b

    def _build_loop(
        self,
        stmt: ast.For | ast.While,
        current: BasicBlock,
        exit_b: BasicBlock,
    ) -> BasicBlock:
        header_b = self._new_block()
        body_b   = self._new_block()
        after_b  = self._new_block()

        self._connect(current, header_b)
        self._connect(header_b, body_b)   # loop taken
        self._connect(header_b, after_b)  # loop not taken / exhausted

        # For ``for x in iter``: model loop variable as an assignment.
        if isinstance(stmt, ast.For):
            ir = _lower_for_iter(stmt)
            if ir:
                body_b.stmts.append(ir)

        body_exit = self._build_body(stmt.body, body_b, exit_b)
        self._connect(body_exit, header_b)  # back-edge

        # Loop else-clause (runs when loop exhausts without break).
        if stmt.orelse:
            orelse_b = self._new_block()
            self._connect(header_b, orelse_b)
            orelse_exit = self._build_body(stmt.orelse, orelse_b, exit_b)
            self._connect(orelse_exit, after_b)

        return after_b

    def _build_try(
        self,
        stmt: ast.Try,
        current: BasicBlock,
        exit_b: BasicBlock,
    ) -> BasicBlock:
        join_b = self._new_block()

        # Try body.
        try_b    = self._new_block()
        self._connect(current, try_b)
        try_exit = self._build_body(stmt.body, try_b, exit_b)
        self._connect(try_exit, join_b)

        # Exception handlers — each can receive taint from try_b.
        for handler in stmt.handlers:
            handler_b    = self._new_block()
            self._connect(try_b, handler_b)
            handler_exit = self._build_body(handler.body, handler_b, exit_b)
            self._connect(handler_exit, join_b)

        # Finally body (runs regardless — flatten into join).
        if stmt.finalbody:
            self._build_body(stmt.finalbody, join_b, exit_b)

        return join_b

    # ── Public entry point ────────────────────────────────────────────────────

    def build(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionIR:
        entry  = self._new_block()
        exit_b = self._new_block()  # virtual exit — never yields findings
        self._build_body(func.body, entry, exit_b)
        return FunctionIR(
            name=func.name,
            filepath=self._filepath,
            entry=entry.id,
            blocks=self._blocks,
        )


def build_function_ir(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    filepath: str,
) -> FunctionIR:
    """Public entry point: lower one AST function to a FunctionIR CFG."""
    return _CFGBuilder(filepath).build(func)
