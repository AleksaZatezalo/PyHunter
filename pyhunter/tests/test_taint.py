"""Unit tests for the intra-procedural taint engine.

Organised into test classes by feature area:

  TestSourceDetection       — is_source() recognises all supported frameworks
  TestTaintPropagation      — taint spreads correctly through assignments
  TestSinkDetection         — known sinks are matched
  TestTaintFlowMetadata     — function_name, sink_line, tainted_vars populated
  TestTaintStep             — TaintStep dataclass construction
  TestPathTracking          — TaintFlow.path records the source→sink chain
  TestSanitizerDetection    — known sanitizers mark flows sanitized=True
  TestPathMetadataConsistency — path recording doesn't break pre-existing fields
"""

import ast
import pytest

from pyhunter.taint import TaintEngine, TaintFlow, TaintStep


def _analyze(src: str, filepath: str = "test.py"):
    tree = ast.parse(src)
    engine = TaintEngine()
    return engine.analyze(tree, src.splitlines(), filepath)


# ── Source detection ──────────────────────────────────────────────────────────

class TestSourceDetection:
    def test_request_args_is_source(self):
        src = """\
from flask import request
def view():
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        assert any(f.sink == "eval" for f in flows)

    def test_request_form_is_source(self):
        src = """\
def view(request):
    data = request.form
    eval(data)
"""
        flows = _analyze(src)
        assert any(f.sink == "eval" for f in flows)

    def test_sys_argv_is_source(self):
        src = """\
import sys
def main():
    cmd = sys.argv
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        assert any("system" in f.sink for f in flows)

    def test_input_builtin_is_source(self):
        src = """\
def run():
    user = input("enter: ")
    eval(user)
"""
        flows = _analyze(src)
        assert any(f.sink == "eval" for f in flows)


# ── Propagation ───────────────────────────────────────────────────────────────

class TestTaintPropagation:
    def test_single_hop_assignment(self):
        src = """\
def view(request):
    raw = request.args
    result = eval(raw)
"""
        flows = _analyze(src)
        assert any(f.sink == "eval" and "raw" in f.tainted_vars for f in flows)

    def test_multi_hop_propagation(self):
        src = """\
def view(request):
    a = request.args
    b = a
    c = b
    eval(c)
"""
        flows = _analyze(src)
        assert any(f.sink == "eval" for f in flows)

    def test_concatenation_propagates_taint(self):
        src = """\
def view(request):
    user = request.args
    cmd = "echo " + user
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        assert any("system" in f.sink for f in flows)

    def test_clean_variable_no_flow(self):
        src = """\
def view():
    cmd = "ls /tmp"
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        assert flows == []

    def test_taint_does_not_cross_function_boundary(self):
        """Intra-procedural: taint in func_a must not appear in func_b."""
        src = """\
def func_a(request):
    tainted = request.args

def func_b():
    eval(tainted)   # 'tainted' is not in scope here
"""
        flows = _analyze(src)
        b_flows = [f for f in flows if f.function_name == "func_b"]
        assert b_flows == []


# ── Sink detection ────────────────────────────────────────────────────────────

class TestSinkDetection:
    def test_eval_sink(self):
        src = """\
def f(request):
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        assert any(f.sink == "eval" for f in flows)

    def test_subprocess_run_sink(self):
        src = """\
import subprocess
def f(request):
    cmd = request.form
    subprocess.run(cmd, shell=True)
"""
        flows = _analyze(src)
        assert any("subprocess" in f.sink for f in flows)

    def test_pickle_loads_sink(self):
        src = """\
import pickle
def f(request):
    data = request.data
    pickle.loads(data)
"""
        flows = _analyze(src)
        assert any("pickle" in f.sink for f in flows)

    def test_open_with_tainted_path(self):
        src = """\
def f(request):
    path = request.args
    open(path, 'r')
"""
        flows = _analyze(src)
        assert any(f.sink == "open" for f in flows)


# ── TaintFlow metadata ────────────────────────────────────────────────────────

class TestTaintFlowMetadata:
    def test_flow_records_function_name(self):
        src = """\
def my_handler(request):
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        assert all(f.function_name == "my_handler" for f in flows)

    def test_flow_records_sink_line(self):
        src = """\
def f(request):
    x = request.args
    y = x
    eval(y)
"""
        flows = _analyze(src)
        eval_flows = [f for f in flows if f.sink == "eval"]
        assert eval_flows
        assert eval_flows[0].sink_line == 4

    def test_flow_records_tainted_vars(self):
        src = """\
def f(request):
    danger = request.form
    eval(danger)
"""
        flows = _analyze(src)
        assert any("danger" in f.tainted_vars for f in flows)


# ── TaintStep dataclass ───────────────────────────────────────────────────────

class TestTaintStep:
    def test_fields_accessible(self):
        step = TaintStep(line=7, variable="cmd", description="assigned from request.args")
        assert step.line == 7
        assert step.variable == "cmd"
        assert step.description == "assigned from request.args"

    def test_different_instances_are_independent(self):
        s1 = TaintStep(line=1, variable="a", description="first")
        s2 = TaintStep(line=2, variable="b", description="second")
        assert s1.line != s2.line
        assert s1.variable != s2.variable


# ── Path tracking ─────────────────────────────────────────────────────────────

class TestPathTracking:
    def test_single_hop_path_has_two_steps(self):
        """source assignment + sink = 2 steps."""
        src = """\
def view(request):
    cmd = request.args.get("cmd")
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        system_flows = [f for f in flows if "system" in f.sink]
        assert system_flows, "expected an os.system flow"
        assert len(system_flows[0].path) == 2

    def test_multi_hop_path_length(self):
        """Each intermediate assignment adds one step; sink adds one more."""
        src = """\
def view(request):
    a = request.args
    b = a
    c = b
    eval(c)
"""
        flows = _analyze(src)
        eval_flows = [f for f in flows if f.sink == "eval"]
        assert eval_flows
        # a (source) + b (hop) + c (hop) + eval (sink) = 4 steps
        assert len(eval_flows[0].path) == 4

    def test_path_first_step_is_source_assignment(self):
        src = """\
def view(request):
    user_input = request.form.get("q")
    eval(user_input)
"""
        flows = _analyze(src)
        f = next(x for x in flows if x.sink == "eval")
        assert f.path[0].variable == "user_input"
        assert "assigned from" in f.path[0].description

    def test_path_last_step_is_sink(self):
        src = """\
def view(request):
    cmd = request.args
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        f = next(x for x in flows if "system" in x.sink)
        last = f.path[-1]
        assert "system" in last.variable
        assert "reaches sink" in last.description

    def test_path_step_line_numbers_are_correct(self):
        src = """\
def view(request):
    raw = request.args
    safe = raw
    eval(safe)
"""
        # lines: def=1, raw=2, safe=3, eval=4
        flows = _analyze(src)
        f = next(x for x in flows if x.sink == "eval")
        lines = [step.line for step in f.path]
        assert lines == sorted(lines), "path steps should be in source order"
        assert 2 in lines  # raw assignment
        assert 4 in lines  # eval call

    def test_path_through_augmented_assignment(self):
        """cmd += user_input should appear as a step in the path."""
        src = """\
import os
def view(request):
    user_input = request.args.get("x")
    cmd = "echo "
    cmd += user_input
    os.system(cmd)
"""
        flows = _analyze(src)
        system_flows = [f for f in flows if "system" in f.sink]
        assert system_flows
        descriptions = [step.description for step in system_flows[0].path]
        assert any("augmented" in d for d in descriptions)

    def test_path_is_list_of_taint_steps(self):
        src = """\
def view(request):
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        f = flows[0]
        assert isinstance(f.path, list)
        assert all(isinstance(step, TaintStep) for step in f.path)

    def test_path_source_description_includes_source_name(self):
        """The first step's description should name the taint source."""
        src = """\
def view(request):
    data = request.form
    eval(data)
"""
        flows = _analyze(src)
        f = next(x for x in flows if x.sink == "eval")
        assert "request.form" in f.path[0].description or "form" in f.path[0].description

    def test_propagation_step_description_names_variable(self):
        """Intermediate steps should name the variable they assign to."""
        src = """\
def view(request):
    a = request.args
    b = a
    eval(b)
"""
        flows = _analyze(src)
        f = next(x for x in flows if x.sink == "eval")
        # step for 'b' should mention propagation
        b_steps = [s for s in f.path if s.variable == "b"]
        assert b_steps
        assert "propagated" in b_steps[0].description

    def test_no_path_on_clean_flow(self):
        """A sink reached by a constant has no taint flow at all."""
        src = """\
def view():
    cmd = "ls"
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        assert flows == []

    def test_path_not_empty_for_any_detected_flow(self):
        """Every detected flow must have at least one path step."""
        src = """\
def f(request):
    x = request.args
    eval(x)

def g(request):
    y = request.form
    import subprocess
    subprocess.run(y, shell=True)
"""
        flows = _analyze(src)
        assert flows
        for flow in flows:
            assert flow.path, f"flow {flow.sink} has an empty path"


# ── Sanitizer detection ───────────────────────────────────────────────────────

class TestSanitizerDetection:
    def test_shlex_quote_marks_flow_sanitized(self):
        src = """\
import shlex, subprocess
def view(request):
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        assert flows, "expected a flow even through sanitizer"
        assert flows[0].sanitized is True

    def test_shlex_quote_records_sanitizer_name(self):
        src = """\
import shlex, subprocess
def view(request):
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        assert flows[0].sanitizer == "shlex.quote"

    def test_html_escape_marks_flow_sanitized(self):
        src = """\
import html
def view(request):
    user = request.args.get("q")
    escaped = html.escape(user)
    eval(escaped)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is True
        assert flows[0].sanitizer == "html.escape"

    def test_re_escape_marks_flow_sanitized(self):
        src = """\
import re, subprocess
def view(request):
    raw = request.args.get("pattern")
    safe = re.escape(raw)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is True
        assert flows[0].sanitizer == "re.escape"

    def test_bare_quote_import_marks_flow_sanitized(self):
        """from shlex import quote; quote(x) should be recognised."""
        src = """\
from shlex import quote
import subprocess
def view(request):
    raw = request.args.get("cmd")
    safe = quote(raw)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is True
        assert flows[0].sanitizer == "quote"

    def test_bare_escape_marks_flow_sanitized(self):
        """from html import escape; escape(x) should be recognised."""
        src = """\
from html import escape
def view(request):
    user = request.args.get("q")
    safe = escape(user)
    eval(safe)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is True

    def test_unguarded_flow_is_not_sanitized(self):
        """A flow with no sanitizer must have sanitized=False."""
        src = """\
def view(request):
    cmd = request.args.get("cmd")
    import os
    os.system(cmd)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is False

    def test_sanitized_flow_still_reaches_sink(self):
        """Sanitized data is still tracked — the flow must be reported."""
        src = """\
import shlex, os
def view(request):
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    os.system(safe)
"""
        flows = _analyze(src)
        system_flows = [f for f in flows if "system" in f.sink]
        assert system_flows, "sanitized flow must still be reported"

    def test_sanitizer_step_appears_in_path(self):
        """The path must contain a step describing the sanitizer application."""
        src = """\
import shlex, subprocess
def view(request):
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        assert flows
        descriptions = [s.description for s in flows[0].path]
        assert any("sanitized" in d for d in descriptions), (
            f"expected a 'sanitized' step in path; got: {descriptions}"
        )

    def test_sanitizer_step_names_the_sanitizer_function(self):
        """The sanitizer step description must name the function used."""
        src = """\
import shlex, subprocess
def view(request):
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        descriptions = [s.description for s in flows[0].path]
        assert any("shlex.quote" in d for d in descriptions)

    def test_sanitizing_clean_variable_does_not_create_flow(self):
        """Sanitizing a non-tainted variable must not produce any taint flow."""
        src = """\
import shlex, subprocess
def view():
    cmd = "ls /tmp"
    safe = shlex.quote(cmd)
    subprocess.run(safe, shell=True)
"""
        flows = _analyze(src)
        assert flows == []

    def test_sanitizer_none_field_on_unsanitized_flow(self):
        """sanitizer must be None when no sanitizer was applied."""
        src = """\
def view(request):
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        assert flows[0].sanitizer is None

    def test_bleach_clean_marks_flow_sanitized(self):
        src = """\
import bleach
def view(request):
    user = request.args.get("content")
    clean = bleach.clean(user)
    eval(clean)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is True
        assert flows[0].sanitizer == "bleach.clean"

    def test_markupsafe_escape_marks_flow_sanitized(self):
        src = """\
from markupsafe import escape
def view(request):
    user = request.args.get("name")
    safe = escape(user)
    eval(safe)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].sanitized is True


# ── Path metadata consistency ─────────────────────────────────────────────────
# Verify that adding path tracking didn't break the pre-existing metadata fields.

class TestPathMetadataConsistency:
    def test_tainted_vars_still_populated_with_path(self):
        src = """\
def f(request):
    danger = request.form
    eval(danger)
"""
        flows = _analyze(src)
        assert any("danger" in f.tainted_vars for f in flows)

    def test_function_name_still_populated_with_path(self):
        src = """\
def my_view(request):
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        assert all(f.function_name == "my_view" for f in flows)

    def test_source_expr_still_populated(self):
        src = """\
def f(request):
    x = request.args
    eval(x)
"""
        flows = _analyze(src)
        assert flows[0].source_expr  # non-empty string

    def test_sink_line_still_correct_with_path(self):
        src = """\
def f(request):
    x = request.args
    y = x
    eval(y)
"""
        # eval is on line 4
        flows = _analyze(src)
        eval_flows = [f for f in flows if f.sink == "eval"]
        assert eval_flows[0].sink_line == 4

    def test_source_line_earlier_than_sink_line(self):
        src = """\
def f(request):
    tainted = request.form
    subprocess_cmd = tainted
    import subprocess
    subprocess.run(subprocess_cmd, shell=True)
"""
        flows = _analyze(src)
        assert flows
        f = flows[0]
        assert f.source_line < f.sink_line

    def test_async_function_path_tracked(self):
        """Path tracking works inside async def as well as regular def."""
        src = """\
import subprocess
async def handler(request):
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)
"""
        flows = _analyze(src)
        assert flows
        assert flows[0].path  # path must be populated in async functions too

    def test_multiple_flows_each_have_independent_paths(self):
        """Two independent flows in the same function have separate paths."""
        src = """\
def f(request):
    a = request.args
    b = request.form
    eval(a)
    eval(b)
"""
        flows = _analyze(src)
        assert len(flows) == 2
        paths = [tuple(s.variable for s in f.path) for f in flows]
        assert paths[0] != paths[1], "each flow should have its own path"
