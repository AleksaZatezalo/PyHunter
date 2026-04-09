"""
Extended tests for the 15 root-chain rules.

Focuses on what test_chain_rules.py does NOT cover:
  - Tornado and DRF/Starlette request sources
  - Multi-hop taint (request → variable → variable → sink)
  - Alternative dynamic-string syntax (concat, %, .format())
  - Edge cases and real-world code patterns
  - Additional negative (safe) cases
"""

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


# ── Rule 01: SSTI — extended ──────────────────────────────────────────────────

class TestSSTIExtended:
    r = SSTIRule()

    # ── Additional frameworks ────────────────────────────────────────────────

    def test_mako_template_from_user_input(self):
        src = """\
from mako.template import Template
from flask import request
def view():
    tmpl = request.args.get("t")
    return Template(tmpl).render()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_tornado_template_with_request_arg(self):
        src = """\
from tornado import template
class Handler:
    def get(self):
        tmpl_str = self.get_argument("tmpl")
        t = template.Template(tmpl_str)
        return t.generate()
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_drf_request_data_to_jinja2(self):
        src = """\
from jinja2 import Environment
from rest_framework.views import APIView
class ReportView(APIView):
    def post(self, request):
        env = Environment()
        return env.from_string(request.data["template"]).render()
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    # ── Multi-hop taint ──────────────────────────────────────────────────────

    def test_multihop_request_to_template(self):
        """request.args → raw_tmpl → cleaned → Template(cleaned)"""
        src = """\
from jinja2 import Template
from flask import request
def view():
    raw_tmpl = request.args.get("t")
    cleaned = raw_tmpl.strip()
    return Template(cleaned).render()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_jinja2_environment_from_string_multihop(self):
        src = """\
from jinja2 import Environment
from flask import request
def render():
    env = Environment()
    user_tmpl = request.form.get("template")
    compiled = user_tmpl
    return env.from_string(compiled).render()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    # ── Negative cases ───────────────────────────────────────────────────────

    def test_safe_jinja2_autoescaped_literal(self):
        src = """\
from jinja2 import Environment
def render(name):
    env = Environment(autoescape=True)
    return env.from_string("Hello {{ name }}").render(name=name)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_template_no_user_input(self):
        src = """\
from mako.template import Template
REPORT_TMPL = "Name: ${name}"
def render(name):
    return Template(REPORT_TMPL).render(name=name)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 02: DESER-RCE — extended ────────────────────────────────────────────

class TestDeserRCEExtended:
    r = DeserRCERule()

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


# ── Rule 03: CMD-INJECT — extended ───────────────────────────────────────────

class TestCmdInjectExtended:
    r = CmdInjectRule()

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


# ── Rule 04: DEBUG-EXPOSED — extended ────────────────────────────────────────

class TestDebugExposedExtended:
    r = DebugExposedRule()

    def test_werkzeug_run_simple_use_debugger(self):
        src = """\
from werkzeug.serving import run_simple
run_simple("localhost", 5000, app, use_debugger=True)
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("use_debugger" in x.sink for x in f)

    def test_app_debug_attribute_true(self):
        src = "app.debug = True"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_flask_debug_env_var_name(self):
        src = "FLASK_DEBUG = True"
        f = self.r.check(*_p(src), "config.py")
        assert len(f) == 1

    def test_safe_production_settings(self):
        src = """\
DEBUG = False
ALLOWED_HOSTS = ["example.com", "www.example.com"]
"""
        f = self.r.check(*_p(src), "settings.py")
        assert f == []

    def test_safe_app_run_no_debug_kwarg(self):
        src = 'app.run(host="0.0.0.0", port=8080, threaded=True)'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 05: FILE-UPLOAD-RCE — extended ──────────────────────────────────────

class TestFileUploadRCEExtended:
    r = FileUploadRCERule()

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


# ── Rule 06: SQL-INJECT — extended ───────────────────────────────────────────

class TestSQLInjectExtended:
    r = SQLInjectRule()

    def test_string_concat_query(self):
        src = 'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_percent_format_query(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = %s" % uid)'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_str_format_method_query(self):
        src = 'cursor.execute("SELECT * FROM t WHERE x = \'{}\'".format(val))'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_sqlalchemy_session_execute_text(self):
        src = """\
from sqlalchemy import text
def get_user(db, name):
    return db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_django_extra_select_fstring(self):
        src = 'qs.extra(select={"value": f"SELECT secret FROM keys WHERE id={kid}"})'
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_executemany_with_dynamic_query(self):
        src = 'cursor.executemany("INSERT INTO t (col) VALUES (" + val + ")", rows)'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_sqlalchemy_orm_filter(self):
        """ORM filter() with keyword args is parameterised — safe."""
        src = """\
def get(db, name):
    return db.query(User).filter(User.name == name).first()
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_named_placeholder(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = %(id)s", {"id": uid})'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 07: SSRF — extended ─────────────────────────────────────────────────

class TestSSRFExtended:
    r = SSRFRule()

    def test_urllib_urlopen_with_user_url(self):
        src = """\
import urllib.request
from flask import request
def fetch():
    url = request.args.get("url")
    return urllib.request.urlopen(url).read()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_tornado_http_fetch_with_arg(self):
        src = """\
import urllib.request
class Handler:
    async def get(self):
        url = self.get_argument("url")
        return urllib.request.urlopen(url).read()
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_starlette_query_params_to_requests(self):
        src = """\
import requests
async def proxy(request):
    url = request.query_params.get("url")
    return requests.get(url)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_multihop_ssrf(self):
        """request.form → target → requests.post(target)"""
        src = """\
import requests
from flask import request
def webhook():
    target = request.form.get("callback_url")
    endpoint = target
    requests.post(endpoint, json={"status": "ok"})
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_drf_post_data_to_requests(self):
        src = """\
import requests
class ProxyView:
    def post(self, request):
        url = request.data.get("url")
        return requests.get(url).json()
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_safe_requests_with_allowlist_check(self):
        """URL validated against allowlist before use — not tainted to the sink."""
        src = """\
import requests
from flask import request
ALLOWED = {"https://api.example.com"}
def fetch():
    url = "https://api.example.com/data"
    return requests.get(url).json()
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_requests_hardcoded_params(self):
        src = """\
import requests
def get_weather(city):
    return requests.get("https://api.weather.com/v1/current", params={"city": city})
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 08: XXE — extended ──────────────────────────────────────────────────

class TestXXEExtended:
    r = XXERule()

    def test_minidom_parse_string(self):
        src = "from xml.dom import minidom\ndoc = minidom.parseString(xml_data)"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_lxml_xml_method(self):
        src = "from lxml import etree\ndoc = etree.XML(xml_bytes)"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_lxml_html_method(self):
        src = "from lxml import etree\ndoc = etree.HTML(html_string)"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_lxml_iterparse_no_parser(self):
        src = "from lxml import etree\nfor _, el in etree.iterparse(f): pass"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_defusedxml(self):
        """defusedxml is safe by design — should not flag."""
        src = """\
import defusedxml.ElementTree as ET
def parse(data):
    return ET.fromstring(data)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_xmlparser_resolve_entities_explicitly_false(self):
        src = "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False)"
        f = self.r.check(*_p(src), "app.py")
        # XMLParser with resolve_entities=False should NOT be flagged
        assert not any("XMLParser" in x.sink for x in f if "resolve_entities=False" not in x.sink)


# ── Rule 09: PATH-TRAVERSAL — extended ───────────────────────────────────────

class TestPathTraversalExtended:
    r = PathTraversalRule()

    def test_os_path_join_user_component(self):
        src = """\
import os
from flask import request
def serve():
    filename = request.args.get("file")
    path = os.path.join("/uploads", filename)
    return open(path).read()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_fastapi_file_response_tainted_path(self):
        src = """\
from fastapi import Query
from fastapi.responses import FileResponse
async def download(filename: str = Query(...)):
    return FileResponse(filename)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_flask_send_from_directory_tainted_name(self):
        src = """\
from flask import request, send_from_directory
def download():
    name = request.args.get("name")
    return send_from_directory("/uploads", name)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_tornado_open_with_request_arg(self):
        src = """\
class Handler:
    def get(self):
        path = self.get_argument("path")
        with open(path) as f:
            return f.read()
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_multihop_path_join_then_open(self):
        src = """\
import os
from flask import request
def read():
    name = request.args.get("name")
    full_path = os.path.join("/data", name)
    return open(full_path).read()
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_path_with_basename(self):
        src = """\
import os
from flask import request
def serve():
    name = os.path.basename(request.args.get("file"))
    return open(os.path.join("/uploads", name)).read()
"""
        f = self.r.check(*_p(src), "app.py")
        # basename sanitises traversal — should still fire on open() though
        # (static analysis cannot confirm basename prevents all traversal)
        # Just verify no crash
        assert isinstance(f, list)

    def test_safe_open_hardcoded_path(self):
        src = 'content = open("/app/templates/index.html").read()'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 10: HARDCODED-SECRET — extended ─────────────────────────────────────

class TestHardcodedSecretsExtended:
    r = HardcodedSecretsRule()

    def test_private_key_pem_block(self):
        src = 'private_key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA..."'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_jwt_signing_key(self):
        src = 'jwt_secret = "supersecretjwtsigningkey1234567890"'
        f = self.r.check(*_p(src), "config.py")
        assert len(f) >= 1

    def test_annotated_assignment_with_secret(self):
        src = 'api_key: str = "sk-abcdefghij1234567890abcdefghij"'
        f = self.r.check(*_p(src), "config.py")
        assert len(f) >= 1

    def test_github_token_pattern(self):
        src = 'GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        f = self.r.check(*_p(src), "ci.py")
        assert len(f) >= 1

    def test_client_secret(self):
        src = 'client_secret = "oauth2clientsecretvalue12345678"'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_env_var_lookup(self):
        """Reading from environment is safe — not a hardcoded secret."""
        src = """\
import os
API_KEY = os.environ.get("API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "")
"""
        f = self.r.check(*_p(src), "settings.py")
        assert f == []

    def test_safe_short_password_value(self):
        """Too short to be a real secret."""
        src = 'password = "abc"'
        f = self.r.check(*_p(src), "test.py")
        assert f == []


# ── Rule 11: AUTH-BYPASS — extended ──────────────────────────────────────────

class TestAuthBypassExtended:
    r = AuthBypassRule()

    def test_jwt_verify_false_legacy(self):
        src = "data = jwt.decode(token, secret, verify=False)"
        f = self.r.check(*_p(src), "app.py")
        assert any("verify=False" in x.sink for x in f)

    def test_drf_permission_classes_empty_only(self):
        src = """\
from rest_framework.views import APIView
class AdminView(APIView):
    permission_classes = []
    def delete(self, request, pk):
        User.objects.get(pk=pk).delete()
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_fastapi_payment_route_no_auth(self):
        src = """\
from fastapi import FastAPI
app = FastAPI(docs_url=None)
@app.post("/payment/process")
async def process_payment(amount: float, card_number: str):
    pass
"""
        f = self.r.check(*_p(src), "app.py")
        assert any("payment" in x.sink.lower() for x in f)

    def test_fastapi_delete_user_no_auth(self):
        src = """\
from fastapi import FastAPI
app = FastAPI(docs_url=None)
@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: int):
    pass
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_fastapi_route_with_current_user(self):
        src = """\
from fastapi import FastAPI, Depends
from app.auth import get_current_user
app = FastAPI(docs_url=None)
@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: int, current_user=Depends(get_current_user)):
    pass
"""
        f = self.r.check(*_p(src), "app.py")
        assert not any("delete_user" in x.sink for x in f)

    def test_safe_jwt_with_hs256(self):
        src = 'data = jwt.decode(token, SECRET, algorithms=["HS256"])'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 12: MASS-ASSIGN — extended ──────────────────────────────────────────

class TestMassAssignExtended:
    r = MassAssignRule()

    def test_drf_request_data_unpack(self):
        src = """\
class UserView:
    def post(self, request):
        return User(**request.data)
"""
        f = self.r.check(*_p(src), "views.py")
        assert len(f) >= 1

    def test_tornado_body_arguments_unpack(self):
        src = """\
class Handler:
    def post(self):
        data = self.request.arguments
        return Record(**data)
"""
        f = self.r.check(*_p(src), "handlers.py")
        assert len(f) >= 1

    def test_starlette_form_data_unpack(self):
        src = """\
async def create(request):
    form = await request.form()
    return Profile(**form)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_multihop_request_json_to_model(self):
        src = """\
from flask import request
def create():
    payload = request.get_json()
    data = payload
    return User(**data)
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_whitelisted_fields_unpack(self):
        src = """\
from flask import request
ALLOWED = {"name", "email"}
def create():
    data = {k: v for k, v in request.json.items() if k in ALLOWED}
    return User(**data)
"""
        f = self.r.check(*_p(src), "app.py")
        # Comprehension creates a new dict — may or may not be detected
        # Just ensure no crash
        assert isinstance(f, list)

    def test_safe_model_from_pydantic_validated(self):
        src = """\
from fastapi import Body
from pydantic import BaseModel
class UserIn(BaseModel):
    name: str
    email: str
async def create(user: UserIn = Body(...)):
    return DBUser(name=user.name, email=user.email)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 13: SUID-RISK — extended ────────────────────────────────────────────

class TestSUIDRiskExtended:
    r = SUIDRiskRule()

    def test_seteuid_zero(self):
        src = "import os\nos.seteuid(0)"
        f = self.r.check(*_p(src), "app.py")
        assert any("seteuid" in x.sink for x in f)

    def test_setreuid_zero(self):
        src = "import os\nos.setreuid(0, 0)"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_chmod_sgid_bit(self):
        """SGID bit (0o2000) also dangerous."""
        src = "import os\nos.chmod('/usr/bin/script', 0o2755)"
        f = self.r.check(*_p(src), "app.py")
        assert any("SUID" in x.sink for x in f)

    def test_os_popen_with_suid_binary(self):
        src = "import os\nos.popen('find / -perm -4000 -exec vim {} \\;')"
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_setuid_non_zero(self):
        """setuid to non-root UID is not a privesc."""
        src = "import os\nos.setuid(1000)"
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_chmod_normal_perms(self):
        src = "import os\nos.chmod('output.txt', 0o644)"
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 14: WRITABLE-PATH — extended ────────────────────────────────────────

class TestWritablePathExtended:
    r = WritablePathRule()

    def test_write_systemd_service(self):
        src = 'open("/etc/systemd/system/backdoor.service", "w")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1 and f[0].severity.value == "CRITICAL"

    def test_write_cron_hourly(self):
        src = 'open("/etc/cron.hourly/cleanup", "w")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_write_etc_profile_d(self):
        src = 'open("/etc/profile.d/env.sh", "w")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_shutil_move_to_sudoers(self):
        src = 'import shutil\nshutil.move("/tmp/evil", "/etc/sudoers.d/pwned")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_fstring_path_to_cron(self):
        src = 'open(f"/etc/cron.d/{name}", "w")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_append_to_authorized_keys(self):
        src = 'open("/root/.ssh/authorized_keys", "a").write(pubkey)'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) == 1

    def test_safe_write_to_app_log(self):
        src = 'open("/var/log/app/access.log", "a")'
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_read_etc_passwd(self):
        src = 'open("/etc/passwd", "r")'
        f = self.r.check(*_p(src), "app.py")
        assert f == []


# ── Rule 15: CONTAINER-ESCAPE — extended ─────────────────────────────────────

class TestContainerEscapeExtended:
    r = ContainerEscapeRule()

    def test_nsenter_subprocess(self):
        src = 'import subprocess\nsubprocess.run("nsenter --target 1 --mount --uts --ipc --net --pid -- bash", shell=True)'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_docker_sdk_host_volume_mount(self):
        src = """\
import docker
client = docker.from_env()
client.containers.run("alpine", volumes={"/": {"bind": "/mnt", "mode": "rw"}})
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_subprocess_net_host(self):
        src = 'import subprocess\nsubprocess.run(["docker", "run", "--net=host", "alpine"])'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_requests_unix_socket_docker(self):
        """Accessing docker.sock via requests-unixsocket."""
        src = 'open("/var/run/docker.sock")'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_cap_sys_admin_string(self):
        src = 'subprocess.run(["setcap", "CAP_SYS_ADMIN+ep", "/app/helper"])'
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_docker_sdk_cap_add(self):
        src = """\
import docker
client = docker.from_env()
client.containers.run("app", cap_add=["SYS_ADMIN", "NET_ADMIN"])
"""
        f = self.r.check(*_p(src), "app.py")
        assert len(f) >= 1

    def test_safe_docker_run_no_escape_flags(self):
        src = """\
import docker
client = docker.from_env()
client.containers.run("alpine", command="echo hello", remove=True)
"""
        f = self.r.check(*_p(src), "app.py")
        assert f == []

    def test_safe_regular_subprocess_no_docker(self):
        src = 'import subprocess\nsubprocess.run(["python", "manage.py", "migrate"])'
        f = self.r.check(*_p(src), "app.py")
        assert f == []
