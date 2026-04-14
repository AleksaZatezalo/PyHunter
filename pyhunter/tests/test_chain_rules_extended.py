"""
Extended tests for DESER-RCE, CMD-INJECT, and FILE-UPLOAD.

Focuses on what test_chain_rules.py does NOT cover:
  - Tornado and DRF/Starlette request sources
  - Multi-hop taint (request → variable → variable → sink)
  - Alternative dynamic-string syntax (concat, %, .format())
  - Edge cases and real-world code patterns
  - Additional negative (safe) cases
"""

import ast

import pytest

from pyhunter.rules.registry import all_rules

_RULES = {r.rule_id: r for r in all_rules()}


def _p(src: str):
    return ast.parse(src), src.splitlines()


# ── DESER-RCE — extended ──────────────────────────────────────────────────────

class TestDeserRCEExtended:
    r = _RULES["DESER-RCE"]

    def test_dill_loads_with_request_data(self):
        src = """\
import dill
from flask import request
def load():
    return dill.loads(request.get_data())
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("dill.loads" in x.sink for x in f)

    def test_tornado_body_to_pickle(self):
        src = """\
import pickle
class Handler:
    def post(self):
        data = self.request.body
        return pickle.loads(data)
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_drf_request_data_to_yaml_unsafe(self):
        src = """\
import yaml
class ConfigView:
    def post(self, request):
        raw = request.data.get("config")
        return yaml.load(raw, Loader=yaml.FullLoader)
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_multihop_taint_to_pickle(self):
        """request body → decoded → pickle.loads"""
        src = """\
import pickle
from flask import request
def load():
    raw = request.get_data()
    decoded = raw
    return pickle.loads(decoded)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_yaml_fullloader_is_unsafe(self):
        """FullLoader is still exploitable — only SafeLoader/BaseLoader are safe."""
        src = """\
import yaml
from flask import request
def load():
    return yaml.load(request.data, Loader=yaml.FullLoader)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_yaml_base_loader(self):
        src = """\
import yaml
from flask import request
def load():
    return yaml.load(request.data, Loader=yaml.BaseLoader)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_pickle_from_local_file(self):
        src = """\
import pickle
def load():
    with open("model.pkl", "rb") as f:
        return pickle.load(f)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── CMD-INJECT — extended ─────────────────────────────────────────────────────

class TestCmdInjectExtended:
    r = _RULES["CMD-INJECT"]

    def test_os_popen_with_query_arg(self):
        src = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    return os.popen(cmd).read()
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("os.popen" in x.sink for x in f)

    def test_check_output_with_drf_data(self):
        src = """\
import subprocess
class RunView:
    def post(self, request):
        cmd = request.data.get("command")
        return subprocess.check_output(cmd, shell=True)
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_multihop_format_string_to_system(self):
        """request.args → format into command string → os.system"""
        src = """\
import os
from flask import request
def ping():
    host = request.args.get("host")
    cmd = "ping -c 1 {}".format(host)
    os.system(cmd)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_tornado_query_arg_to_subprocess(self):
        src = """\
import subprocess
class Handler:
    def get(self):
        script = self.get_query_argument("script")
        subprocess.run(script, shell=True)
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_starlette_query_params_to_popen(self):
        src = """\
import os
async def endpoint(request):
    cmd = request.query_params.get("cmd")
    os.popen(cmd)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_subprocess_literal_list(self):
        src = """\
import subprocess
def backup():
    subprocess.run(["tar", "-czf", "/backups/app.tar.gz", "/app"])
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_popen_hardcoded_command(self):
        src = """\
import os
def get_uptime():
    return os.popen("uptime").read()
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── FILE-UPLOAD — extended ────────────────────────────────────────────────────

class TestFileUploadRCEExtended:
    r = _RULES["FILE-UPLOAD"]

    def test_django_request_files_write(self):
        src = """\
def upload(request):
    f = request.FILES["upload"]
    path = request.POST.get("dest")
    with open(path, "wb") as out:
        out.write(f.read())
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_user_supplied_filename_no_sanitisation(self):
        src = """\
from flask import request
import os
def upload():
    f = request.files["file"]
    filename = request.form.get("filename")
    dest = os.path.join("/uploads", filename)
    f.save(dest)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_upload_with_splitext_check(self):
        src = """\
from flask import request
import os
ALLOWED = {".png", ".jpg", ".gif"}
def upload():
    f = request.files["file"]
    _, ext = os.path.splitext(f.filename)
    if ext.lower() not in ALLOWED:
        return "Bad type", 400
    f.save(os.path.join("/uploads", f.filename))
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []
