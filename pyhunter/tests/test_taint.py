"""Unit tests for the intra-procedural taint engine."""

import ast
import pytest

from pyhunter.taint import TaintEngine


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
        # func_b has no tainted assignment so no flow should be found there
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
        # eval is on line 4
        assert eval_flows[0].sink_line == 4

    def test_flow_records_tainted_vars(self):
        src = """\
def f(request):
    danger = request.form
    eval(danger)
"""
        flows = _analyze(src)
        assert any("danger" in f.tainted_vars for f in flows)
