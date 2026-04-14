"""Tests for DESER-RCE, CMD-INJECT, and FILE-UPLOAD across Flask, Django, FastAPI, Tornado."""

import ast

import pytest

from pyhunter.rules.registry import all_rules

_RULES = {r.rule_id: r for r in all_rules()}


def _p(src: str):
    return ast.parse(src), src.splitlines()


# ── DESER-RCE ─────────────────────────────────────────────────────────────────

class TestDeserRCE:
    r = _RULES["DESER-RCE"]

    def test_pickle_loads_flask_body(self):
        src = """\
import pickle
from flask import request
def load():
    return pickle.loads(request.get_data())
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("pickle.loads" in x.sink for x in f)

    def test_pickle_loads_django_body(self):
        src = """\
import pickle
def load(request):
    return pickle.loads(request.body)
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_yaml_load_unsafe_fastapi(self):
        src = """\
import yaml
from fastapi import Body
async def load(data: bytes = Body(...)):
    return yaml.load(data, Loader=yaml.Loader)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_yaml_safe_load_ok(self):
        src = """\
import yaml
from flask import request
def load():
    return yaml.safe_load(request.get_data())
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_jsonpickle_decode(self):
        src = """\
import jsonpickle
from flask import request
def load():
    return jsonpickle.decode(request.data)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_marshal_loads(self):
        src = """\
import marshal
from flask import request
def load():
    return marshal.loads(request.get_data())
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1


# ── CMD-INJECT ────────────────────────────────────────────────────────────────

class TestCmdInject:
    r = _RULES["CMD-INJECT"]

    def test_os_system_flask(self):
        src = """\
import os
from flask import request
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("os.system" in x.sink for x in f)

    def test_subprocess_shell_true_django(self):
        src = """\
import subprocess
def run(request):
    cmd = request.GET.get("cmd")
    subprocess.run(cmd, shell=True)
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_subprocess_no_shell_safe(self):
        src = """\
import subprocess
from flask import request
def run():
    cmd = request.args.get("file")
    subprocess.run(["ls", cmd], shell=False)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_tornado_get_argument_to_system(self):
        src = """\
import os
class Handler:
    def get(self):
        host = self.get_argument("host")
        os.system(f"ping {host}")
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_fastapi_query_to_popen(self):
        src = """\
import os
from fastapi import Query
async def run(cmd: str = Query(...)):
    os.popen(cmd)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1


# ── FILE-UPLOAD ───────────────────────────────────────────────────────────────

class TestFileUploadRCE:
    r = _RULES["FILE-UPLOAD"]

    def test_flask_file_save_user_path(self):
        src = """\
from flask import request
def upload():
    f = request.files["file"]
    path = request.form.get("path")
    f.save(path)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_fastapi_open_write_user_path(self):
        src = """\
from fastapi import UploadFile, Form
async def upload(file: UploadFile, dest: str = Form(...)):
    with open(dest, "wb") as out:
        out.write(await file.read())
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_upload_with_secure_filename(self):
        src = """\
from flask import request
from werkzeug.utils import secure_filename
def upload():
    f = request.files["file"]
    name = secure_filename(f.filename)
    f.save("/uploads/" + name)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []
