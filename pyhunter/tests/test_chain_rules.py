"""Tests for all 15 root-chain rules across Flask, Django, FastAPI, Tornado."""

import ast
import pytest

from pyhunter.rules.r01_ssti             import SSTIRule
from pyhunter.rules.r02_deser_rce        import DeserRCERule
from pyhunter.rules.r03_cmd_inject       import CmdInjectRule
from pyhunter.rules.r04_debug_exposed    import DebugExposedRule
from pyhunter.rules.r05_file_upload_rce  import FileUploadRCERule
from pyhunter.rules.r06_sqli             import SQLInjectRule
from pyhunter.rules.r07_ssrf             import SSRFRule
from pyhunter.rules.r08_xxe              import XXERule
from pyhunter.rules.r09_path_traversal   import PathTraversalRule
from pyhunter.rules.r10_hardcoded_secrets import HardcodedSecretsRule
from pyhunter.rules.r11_auth_bypass      import AuthBypassRule
from pyhunter.rules.r12_mass_assign      import MassAssignRule
from pyhunter.rules.r13_suid_risk        import SUIDRiskRule
from pyhunter.rules.r14_writable_path    import WritablePathRule
from pyhunter.rules.r15_container_escape import ContainerEscapeRule


def _p(src: str):
    return ast.parse(src), src.splitlines()


# ── Rule 01: SSTI ─────────────────────────────────────────────────────────────

class TestSSTI:
    r = SSTIRule()

    def test_flask_render_template_string(self):
        src = """\
from flask import request, render_template_string
def view():
    t = request.args.get("t")
    return render_template_string(t)
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("render_template_string" in x.sink for x in f)

    def test_jinja2_template_from_user(self):
        src = """\
from jinja2 import Template
from flask import request
def view():
    tmpl = request.args.get("tmpl")
    return Template(tmpl).render()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_fastapi_jinja2_dynamic_template(self):
        src = """\
from jinja2 import Environment
from fastapi import Query
async def view(t: str = Query(...)):
    env = Environment()
    return env.from_string(t).render()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_django_template_dynamic(self):
        src = """\
from django import template as tmpl
def view(request):
    t = request.GET.get("template")
    return tmpl.Template(t).render(tmpl.Context({}))
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_safe_literal_template(self):
        src = """\
from jinja2 import Template
def view():
    return Template("Hello {{ name }}").render(name="world")
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 02: DESER-RCE ────────────────────────────────────────────────────────

class TestDeserRCE:
    r = DeserRCERule()

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


# ── Rule 03: CMD-INJECT ───────────────────────────────────────────────────────

class TestCmdInject:
    r = CmdInjectRule()

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


# ── Rule 04: DEBUG-EXPOSED ────────────────────────────────────────────────────

class TestDebugExposed:
    r = DebugExposedRule()

    def test_flask_run_debug_true(self):
        f = self.r.check(*_p("app.run(debug=True)"), "app.py")
        assert len(f) == 1 and "debug=True" in f[0].sink

    def test_django_debug_true(self):
        f = self.r.check(*_p("DEBUG = True"), "settings.py")
        assert len(f) == 1

    def test_django_allowed_hosts_empty(self):
        f = self.r.check(*_p("ALLOWED_HOSTS = []"), "settings.py")
        assert len(f) == 1

    def test_tornado_application_debug(self):
        f = self.r.check(*_p("app = Application(handlers, debug=True)"), "app.py")
        assert len(f) == 1

    def test_fastapi_docs_exposed(self):
        f = self.r.check(*_p("app = FastAPI()"), "main.py")
        assert len(f) == 1   # docs_url defaults to /docs — unauthenticated

    def test_fastapi_docs_disabled_ok(self):
        f = self.r.check(*_p("app = FastAPI(docs_url=None, redoc_url=None)"), "main.py")
        assert f == []

    def test_debug_false_ok(self):
        f = self.r.check(*_p("DEBUG = False"), "settings.py")
        assert f == []


# ── Rule 05: FILE-UPLOAD-RCE ──────────────────────────────────────────────────

class TestFileUploadRCE:
    r = FileUploadRCERule()

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


# ── Rule 06: SQL-INJECT ───────────────────────────────────────────────────────

class TestSQLInject:
    r = SQLInjectRule()

    def test_raw_cursor_fstring(self):
        src = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_sqlalchemy_text_fstring(self):
        src = 'db.execute(text(f"SELECT * FROM users WHERE name = \'{name}\'"))'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_django_raw_fstring(self):
        src = 'User.objects.raw(f"SELECT * FROM users WHERE name = \'{name}\'")'
        f = self.r.check(*_p(src), "views.py")
        assert len(f) == 1

    def test_django_extra_where_fstring(self):
        src = 'qs.extra(where=[f"name = \'{name}\'"])'
        f = self.r.check(*_p(src), "views.py")
        assert len(f) == 1

    def test_safe_parameterised(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_literal_query(self):
        src = 'cursor.execute("SELECT 1")'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 07: SSRF ─────────────────────────────────────────────────────────────

class TestSSRF:
    r = SSRFRule()

    def test_flask_request_args_to_requests_get(self):
        src = """\
import requests
from flask import request
def fetch():
    url = request.args.get("url")
    return requests.get(url)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_django_post_to_requests(self):
        src = """\
import requests
def proxy(request):
    url = request.POST.get("target")
    return requests.post(url)
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_fastapi_query_to_httpx(self):
        src = """\
import httpx
from fastapi import Query
async def fetch(url: str = Query(...)):
    async with httpx.AsyncClient() as c:
        return await c.get(url)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_hardcoded_url_safe(self):
        src = """\
import requests
def fetch():
    return requests.get("https://api.example.com/data")
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 08: XXE ──────────────────────────────────────────────────────────────

class TestXXE:
    r = XXERule()

    def test_lxml_parse_no_safe_parser(self):
        src = "from lxml import etree\ntree = etree.parse(f)"
        f = self.r.check(*_p(src), "app.py")
        assert any("lxml.parse" in x.sink for x in f)

    def test_lxml_fromstring_unsafe(self):
        src = "from lxml import etree\ndoc = etree.fromstring(xml_data)"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_lxml_xmlparser_default_unsafe(self):
        src = "from lxml import etree\np = etree.XMLParser()"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_xml_sax_parse(self):
        src = "import xml.sax\nxml.sax.parseString(data, handler)"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_lxml_with_parser_kwarg(self):
        src = """\
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse(f, parser=parser)
"""
        f = self.r.check(*_p(src), "app.py")
        assert not any("lxml.parse" in x.sink for x in f)


# ── Rule 09: PATH-TRAVERSAL ───────────────────────────────────────────────────

class TestPathTraversal:
    r = PathTraversalRule()

    def test_open_flask_arg(self):
        src = """\
from flask import request
def read():
    path = request.args.get("file")
    return open(path).read()
"""
        f = self.r.check(*_p(src), "app.py")
        assert any(x.sink == "open" for x in f)

    def test_open_django_get(self):
        src = """\
def read(request):
    path = request.GET.get("file")
    return open(path).read()
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_flask_send_file(self):
        src = """\
from flask import request, send_file
def download():
    fname = request.args.get("file")
    return send_file(fname)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_zip_slip(self):
        src = """\
import zipfile
from flask import request
def extract():
    dest = request.args.get("dest")
    with zipfile.ZipFile(archive) as z:
        z.extractall(dest)
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("Zip Slip" in x.sink for x in f)

    def test_safe_literal_path(self):
        src = 'open("/etc/hosts", "r")'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 10: HARDCODED-SECRET ─────────────────────────────────────────────────

class TestHardcodedSecrets:
    r = HardcodedSecretsRule()

    def test_django_secret_key(self):
        f = self.r.check(*_p('SECRET_KEY = "django-insecure-abc123XYZsuperlong"'), "settings.py")
        assert len(f) == 1

    def test_aws_access_key(self):
        f = self.r.check(*_p('aws_secret = "AKIAIOSFODNN7EXAMPLE"'), "config.py")
        assert len(f) == 1

    def test_api_key_kwarg(self):
        f = self.r.check(*_p('client = Stripe(api_key="sk-liveABCDEF123456789012345678901234")'), "payments.py")
        assert len(f) == 1

    def test_placeholder_ignored(self):
        f = self.r.check(*_p('api_key = "<your-api-key-here>"'), "app.py")
        assert f == []

    def test_empty_string_ignored(self):
        f = self.r.check(*_p('password = ""'), "app.py")
        assert f == []

    def test_non_secret_var_ignored(self):
        f = self.r.check(*_p('username = "admin"'), "app.py")
        assert f == []


# ── Rule 11: AUTH-BYPASS ──────────────────────────────────────────────────────

class TestAuthBypass:
    r = AuthBypassRule()

    def test_jwt_algorithms_none(self):
        f = self.r.check(*_p("jwt.decode(token, algorithms=None)"), "app.py")
        assert any("algorithms=None" in x.sink for x in f)

    def test_jwt_algorithms_list_none(self):
        f = self.r.check(*_p('jwt.decode(token, key, algorithms=["none"])'), "app.py")
        assert len(f) >= 1

    def test_jwt_verify_signature_false(self):
        f = self.r.check(*_p('jwt.decode(token, options={"verify_signature": False})'), "app.py")
        assert len(f) >= 1

    def test_drf_authentication_classes_empty(self):
        src = """\
from rest_framework.views import APIView
class MyView(APIView):
    authentication_classes = []
    permission_classes = []
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_fastapi_admin_route_no_auth(self):
        src = """\
from fastapi import FastAPI
app = FastAPI(docs_url=None)
@app.delete("/admin/delete_user")
async def delete_user(user_id: int):
    pass
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("admin" in x.sink.lower() or "delete_user" in x.sink for x in f)

    def test_jwt_with_algorithm_ok(self):
        f = self.r.check(*_p('jwt.decode(token, key, algorithms=["HS256"])'), "app.py")
        assert f == []


# ── Rule 12: MASS-ASSIGN ──────────────────────────────────────────────────────

class TestMassAssign:
    r = MassAssignRule()

    def test_flask_request_json_unpack(self):
        src = """\
from flask import request
def create():
    return User(**request.json)
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("User" in x.sink for x in f)

    def test_django_post_dict_unpack(self):
        src = """\
def create(request):
    return User(**request.POST.dict())
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_fastapi_body_dict_unpack(self):
        src = """\
from fastapi import Body
async def create(data: dict = Body(...)):
    return User(**data)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_explicit_fields(self):
        src = """\
from flask import request
def create():
    d = request.json
    return User(name=d["name"], email=d["email"])
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_static_dict_unpack(self):
        src = """\
def create():
    defaults = {"role": "user", "active": True}
    return User(**defaults)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 13: SUID-RISK ────────────────────────────────────────────────────────

class TestSUIDRisk:
    r = SUIDRiskRule()

    def test_setuid_zero(self):
        f = self.r.check(*_p("import os\nos.setuid(0)"), "app.py")
        assert any("setuid(0)" in x.sink for x in f)

    def test_chmod_suid_bit(self):
        f = self.r.check(*_p("import os\nos.chmod('/bin/bash', 0o4755)"), "app.py")
        assert any("SUID" in x.sink for x in f)

    def test_ctypes_setuid(self):
        f = self.r.check(*_p("import ctypes\nctypes.CDLL(None).setuid(0)"), "app.py")
        assert any("setuid" in x.sink for x in f)

    def test_os_system_suid_bin(self):
        f = self.r.check(*_p('import os\nos.system("python3 -c \'import os; os.setuid(0)\'")', ), "app.py")
        assert len(f) >= 1

    def test_normal_chmod_ok(self):
        f = self.r.check(*_p("import os\nos.chmod('file.txt', 0o644)"), "app.py")
        assert f == []


# ── Rule 14: WRITABLE-PATH ────────────────────────────────────────────────────

class TestWritablePath:
    r = WritablePathRule()

    def test_write_cron(self):
        f = self.r.check(*_p('open("/etc/cron.d/evil", "w")'), "app.py")
        assert len(f) == 1 and f[0].severity.value == "CRITICAL"

    def test_write_passwd(self):
        f = self.r.check(*_p('open("/etc/passwd", "a")'), "app.py")
        assert len(f) == 1

    def test_write_authorized_keys(self):
        f = self.r.check(*_p('open("/root/.ssh/authorized_keys", "a")'), "app.py")
        assert len(f) == 1

    def test_write_sudoers(self):
        f = self.r.check(*_p('open("/etc/sudoers.d/pwned", "w")'), "app.py")
        assert len(f) == 1

    def test_shutil_copy_to_cron(self):
        f = self.r.check(*_p('import shutil\nshutil.copy("payload.sh", "/etc/cron.d/backdoor")'), "app.py")
        assert len(f) == 1

    def test_read_only_open_ok(self):
        f = self.r.check(*_p('open("/etc/passwd", "r")'), "app.py")
        assert f == []

    def test_write_tmp_not_flagged(self):
        # /tmp writes are common and not flagged at this severity
        f = self.r.check(*_p('open("/tmp/output.txt", "w")'), "app.py")
        assert f == []


# ── Rule 15: CONTAINER-ESCAPE ─────────────────────────────────────────────────

class TestContainerEscape:
    r = ContainerEscapeRule()

    def test_open_docker_sock(self):
        f = self.r.check(*_p('open("/var/run/docker.sock", "rb")'), "app.py")
        assert len(f) == 1 and "docker.sock" in f[0].sink

    def test_subprocess_privileged_flag(self):
        f = self.r.check(*_p('import subprocess\nsubprocess.run(["docker", "run", "--privileged", "alpine"])'), "app.py")
        assert len(f) >= 1

    def test_subprocess_mount_host_root(self):
        f = self.r.check(*_p('import subprocess\nsubprocess.run("docker run -v /:/mnt alpine chroot /mnt", shell=True)'), "app.py")
        assert len(f) >= 1

    def test_docker_sdk_privileged(self):
        src = """\
import docker
client = docker.from_env()
client.containers.run("alpine", privileged=True, command="id")
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("privileged" in x.sink for x in f)

    def test_docker_sdk_pid_host(self):
        src = """\
import docker
client = docker.from_env()
client.containers.run("alpine", pid_mode="host")
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_normal_subprocess(self):
        f = self.r.check(*_p('import subprocess\nsubprocess.run(["ls", "-la"])'), "app.py")
        assert f == []
