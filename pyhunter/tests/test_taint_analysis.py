"""Tests for the four-layer taint analysis pipeline.

Structure
---------
  TestTaintPathTypes      — TaintPath / PathStep / TaintAnalysis construction
  TestCFGAnalysis         — CFGAnalyzer end-to-end (typed TaintPath output)
  TestTaintSkillContract  — analyze_taint_path() with mocked Claude (Layer 3)
  TestScannerIntegration  — scanner populates Finding.taint_path as TaintPath
"""
from __future__ import annotations

import ast
from unittest.mock import AsyncMock, patch

import pytest

from pyhunter.taint import CFGAnalyzer
from pyhunter.taint.analysis import analyze_function
from pyhunter.taint.cfg import build_function_ir
from pyhunter.taint.types import (
    PathStep, SourceLocation, StepKind,
    TaintAnalysis, TaintPath,
)


# ── Fixtures: hard-coded TaintPath instances ─────────────────────────────────
# These are the Layer 3 inputs — built without running any real analysis
# so that the LLM skill tests are independent of the taint engine.

def _make_step(line: int, var: str, kind: StepKind, desc: str,
               sanitizer: str | None = None) -> PathStep:
    return PathStep(
        location    = SourceLocation("app.py", line),
        variable    = var,
        kind        = kind,
        description = desc,
        sanitizer   = sanitizer,
    )


@pytest.fixture
def cmd_inject_path() -> TaintPath:
    """A simple 2-hop path: request.args → cmd → os.system."""
    return TaintPath(
        id            = "test0001",
        rule_id       = "CMD-INJECT",
        source_label  = "request.args.get",
        sink_label    = "os.system",
        function_name = "run",
        filepath      = "app.py",
        steps         = [
            _make_step(4, "cmd",      StepKind.SOURCE,      "assigned from request.args.get"),
            _make_step(5, "os.system", StepKind.SINK,        "reaches sink os.system()"),
        ],
        sanitized     = False,
        sanitizer     = None,
        finding_line  = 5,
    )


@pytest.fixture
def sanitized_path() -> TaintPath:
    """A path where shlex.quote is applied before the sink."""
    return TaintPath(
        id            = "test0002",
        rule_id       = "CMD-INJECT",
        source_label  = "request.args.get",
        sink_label    = "os.system",
        function_name = "run",
        filepath      = "app.py",
        steps         = [
            _make_step(4, "raw",       StepKind.SOURCE,       "assigned from request.args.get"),
            _make_step(5, "safe",      StepKind.SANITIZATION,
                       "sanitized by shlex.quote() → `safe`", sanitizer="shlex.quote"),
            _make_step(6, "os.system", StepKind.SINK,         "reaches sink os.system()"),
        ],
        sanitized     = True,
        sanitizer     = "shlex.quote",
        finding_line  = 6,
    )


@pytest.fixture
def multihop_path() -> TaintPath:
    """A 4-hop path: source → a → b → c → sink."""
    return TaintPath(
        id            = "test0003",
        rule_id       = "FLOW-WEB",
        source_label  = "request.args",
        sink_label    = "eval",
        function_name = "view",
        filepath      = "app.py",
        steps         = [
            _make_step(2, "a",    StepKind.SOURCE,      "assigned from request.args"),
            _make_step(3, "b",    StepKind.PROPAGATION, "propagated to `b`"),
            _make_step(4, "c",    StepKind.PROPAGATION, "propagated to `c`"),
            _make_step(5, "eval", StepKind.SINK,        "reaches sink eval()"),
        ],
        sanitized     = False,
        sanitizer     = None,
        finding_line  = 5,
    )


# ── Layer 2 typed contracts ───────────────────────────────────────────────────

class TestTaintPathTypes:
    def test_path_step_is_frozen(self, cmd_inject_path):
        step = cmd_inject_path.steps[0]
        with pytest.raises((AttributeError, TypeError)):
            step.variable = "hacked"  # type: ignore[misc]

    def test_source_line_returns_first_source_step(self, cmd_inject_path):
        assert cmd_inject_path.source_line() == 4

    def test_source_line_none_when_no_source_step(self):
        path = TaintPath(
            id="x", rule_id="X", source_label="src", sink_label="sink",
            function_name="f", filepath="f.py",
            steps=[_make_step(1, "eval", StepKind.SINK, "reaches sink eval()")],
            sanitized=False, sanitizer=None, finding_line=1,
        )
        assert path.source_line() is None

    def test_sink_step_returns_last_sink(self, multihop_path):
        sink = multihop_path.sink_step()
        assert sink is not None
        assert sink.kind == StepKind.SINK
        assert sink.variable == "eval"

    def test_to_step_dicts_backward_compat(self, cmd_inject_path):
        """to_step_dicts() must produce the legacy [{line, variable, description}] format."""
        dicts = cmd_inject_path.to_step_dicts()
        assert isinstance(dicts, list)
        assert len(dicts) == 2
        for d in dicts:
            assert "line" in d
            assert "variable" in d
            assert "description" in d

    def test_to_step_dicts_line_is_int(self, multihop_path):
        for d in multihop_path.to_step_dicts():
            assert isinstance(d["line"], int)

    def test_taint_analysis_fields_accessible(self):
        ta = TaintAnalysis(
            path_id               = "test0001",
            sanitizer_bypass_risk = "shlex.quote can be bypassed …",
            chain_potential       = "Arbitrary command execution",
            assessment            = "Full response text here",
        )
        assert ta.path_id == "test0001"
        assert ta.sanitizer_bypass_risk is not None
        assert ta.chain_potential
        assert ta.assessment

    def test_taint_analysis_no_sanitizer_risk_is_none(self, cmd_inject_path):
        ta = TaintAnalysis(
            path_id               = cmd_inject_path.id,
            sanitizer_bypass_risk = None,
            chain_potential       = "RCE",
            assessment            = "Unguarded flow.",
        )
        assert ta.sanitizer_bypass_risk is None


# ── Layer 2: CFG-based analysis produces TaintPath ───────────────────────────

def _analyze(src: str, filepath: str = "test.py"):
    tree = ast.parse(src)
    func = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    func_ir = build_function_ir(func, filepath)
    return analyze_function(func_ir, "TEST-RULE")


class TestCFGAnalysis:
    def test_returns_list_of_taint_paths(self):
        src = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
        paths = _analyze(src)
        assert isinstance(paths, list)
        assert all(isinstance(p, TaintPath) for p in paths)

    def test_detects_simple_source_to_sink(self):
        src = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
        paths = _analyze(src)
        assert any(p.sink_label == "os.system" for p in paths)

    def test_source_label_contains_request(self):
        src = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
        paths = _analyze(src)
        os_paths = [p for p in paths if p.sink_label == "os.system"]
        assert os_paths
        assert "request" in os_paths[0].source_label

    def test_path_has_source_and_sink_steps(self):
        src = """\
from flask import request
def view():
    x = request.args
    eval(x)
"""
        paths = _analyze(src)
        assert paths
        kinds = {step.kind for step in paths[0].steps}
        assert StepKind.SOURCE in kinds
        assert StepKind.SINK   in kinds

    def test_multihop_path_has_propagation_steps(self):
        src = """\
from flask import request
def view():
    a = request.args
    b = a
    c = b
    eval(c)
"""
        paths = _analyze(src)
        assert paths
        prop_steps = [s for s in paths[0].steps if s.kind == StepKind.PROPAGATION]
        assert len(prop_steps) >= 2

    def test_sanitized_path_marked_sanitized(self):
        src = """\
import shlex, os
from flask import request
def run():
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    os.system(safe)
"""
        paths = _analyze(src)
        assert paths
        assert paths[0].sanitized is True
        assert paths[0].sanitizer == "shlex.quote"

    def test_sanitized_path_has_sanitization_step(self):
        src = """\
import shlex, os
from flask import request
def run():
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    os.system(safe)
"""
        paths = _analyze(src)
        assert paths
        san_steps = [s for s in paths[0].steps if s.kind == StepKind.SANITIZATION]
        assert san_steps
        assert san_steps[0].sanitizer == "shlex.quote"

    def test_clean_function_returns_no_paths(self):
        src = """\
import os
def run():
    os.system("ls /tmp")
"""
        paths = _analyze(src)
        assert paths == []

    def test_if_branch_taint_propagates(self):
        """Taint introduced inside an if-branch must still reach a downstream sink."""
        src = """\
import os
from flask import request
def run(flag):
    cmd = "ls"
    if flag:
        cmd = request.args.get("cmd")
    os.system(cmd)
"""
        paths = _analyze(src)
        assert any(p.sink_label == "os.system" for p in paths), (
            "taint from if-branch must propagate to post-if sink"
        )

    def test_path_ids_are_unique(self):
        src = """\
from flask import request
def view():
    a = request.args
    b = request.form
    eval(a)
    eval(b)
"""
        paths = _analyze(src)
        ids = [p.id for p in paths]
        assert len(ids) == len(set(ids)), "each TaintPath must have a unique id"

    def test_finding_line_is_sink_line(self):
        src = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
        paths = _analyze(src)
        os_paths = [p for p in paths if p.sink_label == "os.system"]
        assert os_paths
        # os.system is on line 5
        assert os_paths[0].finding_line == 5

    def test_async_function_analyzed(self):
        src = """\
import subprocess
async def handler(request):
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)
"""
        paths = _analyze(src)
        assert any("subprocess" in p.sink_label for p in paths)


# ── CFGAnalyzer facade ────────────────────────────────────────────────────────

class TestCFGAnalyzerFacade:
    def test_find_enclosing_function_returns_func(self):
        src = """\
def outer():
    def inner():
        pass
"""
        tree = ast.parse(src)
        analyzer = CFGAnalyzer()
        # Line 2 is inside inner — innermost function should be returned
        func = analyzer.find_enclosing_function(tree, 2)
        assert func is not None
        assert func.name == "inner"

    def test_find_enclosing_function_returns_none_outside(self):
        src = "x = 1\n"
        tree = ast.parse(src)
        analyzer = CFGAnalyzer()
        func = analyzer.find_enclosing_function(tree, 1)
        assert func is None

    def test_analyze_function_returns_taint_paths(self):
        src = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
        tree = ast.parse(src)
        analyzer = CFGAnalyzer()
        func = analyzer.find_enclosing_function(tree, 5)
        assert func is not None
        paths = analyzer.analyze_function(func, "test.py", "CMD-INJECT")
        assert paths
        assert all(isinstance(p, TaintPath) for p in paths)
        assert paths[0].rule_id == "CMD-INJECT"


# ── Layer 3: LLM taint skill (mocked Claude) ─────────────────────────────────

class TestTaintSkillContract:
    @pytest.mark.asyncio
    async def test_skill_returns_taint_analysis(self, cmd_inject_path):
        mock_response = """\
### Taint Path Assessment
Direct flow — taint reaches the sink unconditionally.

### Sanitizer Analysis
No sanitizer detected — flow is unguarded.

### Chain Potential
Arbitrary command execution enables writing a reverse-shell cron job.
"""
        with patch(
            "pyhunter.skills.taint_skill.async_call_claude",
            new=AsyncMock(return_value=mock_response),
        ):
            from pyhunter.skills.taint_skill import analyze_taint_path
            result = await analyze_taint_path(cmd_inject_path)

        assert isinstance(result, TaintAnalysis)
        assert result.path_id == "test0001"
        assert result.assessment == mock_response

    @pytest.mark.asyncio
    async def test_skill_extracts_chain_potential(self, cmd_inject_path):
        mock_response = """\
### Taint Path Assessment
Unconditional.

### Sanitizer Analysis
None.

### Chain Potential
RCE enables pivoting to container escape.
"""
        with patch(
            "pyhunter.skills.taint_skill.async_call_claude",
            new=AsyncMock(return_value=mock_response),
        ):
            from pyhunter.skills.taint_skill import analyze_taint_path
            result = await analyze_taint_path(cmd_inject_path)

        assert "RCE" in result.chain_potential or "container" in result.chain_potential

    @pytest.mark.asyncio
    async def test_skill_sets_bypass_risk_for_sanitized_path(self, sanitized_path):
        mock_response = """\
### Taint Path Assessment
Path goes through shlex.quote.

### Sanitizer Analysis
shlex.quote does NOT protect against os.system when the argument is a full
command string — bypass via shell metacharacters in some configurations.

### Chain Potential
If bypassed: full RCE.
"""
        with patch(
            "pyhunter.skills.taint_skill.async_call_claude",
            new=AsyncMock(return_value=mock_response),
        ):
            from pyhunter.skills.taint_skill import analyze_taint_path
            result = await analyze_taint_path(sanitized_path)

        assert result.sanitizer_bypass_risk is not None
        assert len(result.sanitizer_bypass_risk) > 0

    @pytest.mark.asyncio
    async def test_skill_bypass_risk_none_for_unsanitized(self, cmd_inject_path):
        mock_response = """\
### Taint Path Assessment
Direct.

### Sanitizer Analysis
No sanitizer detected.

### Chain Potential
Full RCE.
"""
        with patch(
            "pyhunter.skills.taint_skill.async_call_claude",
            new=AsyncMock(return_value=mock_response),
        ):
            from pyhunter.skills.taint_skill import analyze_taint_path
            result = await analyze_taint_path(cmd_inject_path)

        # cmd_inject_path.sanitized is False → bypass_risk must be None
        assert result.sanitizer_bypass_risk is None

    @pytest.mark.asyncio
    async def test_skill_does_not_receive_ast_nodes(self, cmd_inject_path):
        """Verify the message sent to Claude contains only string data."""
        captured_user = []

        async def capture(system, user, **kwargs):
            captured_user.append(user)
            return "### Taint Path Assessment\nX\n### Sanitizer Analysis\nX\n### Chain Potential\nX"

        with patch("pyhunter.skills.taint_skill.async_call_claude", new=capture):
            from pyhunter.skills.taint_skill import analyze_taint_path
            await analyze_taint_path(cmd_inject_path)

        msg = captured_user[0]
        assert isinstance(msg, str)
        assert "ast" not in msg.lower() or "assessment" in msg.lower()
        assert "CMD-INJECT" in msg
        assert "os.system" in msg
