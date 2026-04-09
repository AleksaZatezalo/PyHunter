"""Unit tests for all new AST-based rules (no LLM calls)."""

import ast
import pytest

from pyhunter.rules.sql_injection    import SQLInjectionRule
from pyhunter.rules.nosql_injection  import NoSQLInjectionRule
from pyhunter.rules.log_injection    import LogInjectionRule
from pyhunter.rules.header_injection import HeaderInjectionRule
from pyhunter.rules.weak_crypto      import WeakCryptoRule
from pyhunter.rules.hardcoded_secrets import HardcodedSecretsRule
from pyhunter.rules.insecure_random  import InsecureRandomRule
from pyhunter.rules.weak_jwt         import WeakJWTRule
from pyhunter.rules.insecure_cookie  import InsecureCookieRule
from pyhunter.rules.ssrf             import SSRFRule
from pyhunter.rules.xxe              import XXERule
from pyhunter.rules.insecure_tls     import InsecureTLSRule
from pyhunter.rules.debug_enabled    import DebugEnabledRule
from pyhunter.rules.stack_trace_leak import StackTraceLeakRule
from pyhunter.rules.toctou           import TOCTOURule
from pyhunter.rules.redos            import ReDoSRule
from pyhunter.rules.open_redirect    import OpenRedirectRule
from pyhunter.rules.mass_assignment  import MassAssignmentRule
from pyhunter.rules.cors_misconfig   import CORSMisconfigRule


def _parse(src: str):
    return ast.parse(src), src.splitlines()


# ── SQL Injection ─────────────────────────────────────────────────────────────

class TestSQLInjectionRule:
    rule = SQLInjectionRule()

    def test_detects_string_concat(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert findings[0].sink == "execute"

    def test_detects_fstring(self):
        src = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_percent_format(self):
        src = 'cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_str_format_method(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_safe_parameterised_query(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_safe_literal_query(self):
        src = 'cursor.execute("SELECT 1")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_detects_executemany_fstring(self):
        src = 'cursor.executemany(f"INSERT INTO t VALUES ({val})", rows)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert findings[0].sink == "executemany"


# ── NoSQL / LDAP / XPath Injection ───────────────────────────────────────────

class TestNoSQLInjectionRule:
    rule = NoSQLInjectionRule()

    def test_detects_mongodb_where(self):
        src = 'collection.find({"$where": "this.user == \'" + user + "\'"})'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "mongodb" in findings[0].sink

    def test_detects_xpath_fstring(self):
        src = 'tree.xpath(f"/users[@id=\'{user_id}\']")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "xpath" in findings[0].sink

    def test_detects_xpath_variable(self):
        src = "tree.xpath(user_xpath)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_ldap_filter_concat(self):
        src = 'conn.search("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + user + ")")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "ldap" in findings[0].sink

    def test_detects_ldap_filter_kwarg(self):
        src = 'conn.search_s("dc=example,dc=com", 2, filterstr="(uid=" + user + ")")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_safe_mongodb_no_where(self):
        src = 'collection.find({"user": user_id})'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_safe_xpath_literal(self):
        src = 'tree.xpath("/users/user")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Log Injection ─────────────────────────────────────────────────────────────

class TestLogInjectionRule:
    rule = LogInjectionRule()

    def test_detects_user_input_in_log(self):
        src = """\
import logging
from flask import request
def view():
    user = request.args.get("name")
    logging.info(user)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any(f.sink == "logging" for f in findings)

    def test_detects_password_in_log(self):
        src = """\
import logging
def login(password):
    logging.debug(password)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any("password" in (f.source or "") for f in findings)

    def test_detects_token_in_log(self):
        src = """\
import logging
def auth(access_token):
    logging.info("Token: %s", access_token)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_static_log_message(self):
        src = """\
import logging
def start():
    logging.info("Server started")
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Header Injection ──────────────────────────────────────────────────────────

class TestHeaderInjectionRule:
    rule = HeaderInjectionRule()

    def test_detects_header_assignment_from_request(self):
        src = """\
from flask import request, make_response
def view():
    val = request.args.get("x")
    response.headers["X-Custom"] = val
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any("headers" in f.sink for f in findings)

    def test_detects_direct_request_in_header(self):
        src = """\
from flask import request
def view():
    response.headers["X-Val"] = request.args.get("val")
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_static_header_value(self):
        src = """\
def view():
    response.headers["X-Frame-Options"] = "DENY"
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Weak Cryptography ─────────────────────────────────────────────────────────

class TestWeakCryptoRule:
    rule = WeakCryptoRule()

    def test_detects_md5(self):
        src = "import hashlib\nh = hashlib.md5(data)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "md5" for f in findings)

    def test_detects_sha1(self):
        src = "import hashlib\nh = hashlib.sha1(data)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "sha1" for f in findings)

    def test_detects_ecb_mode(self):
        src = "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("ECB" in f.sink for f in findings)

    def test_detects_des(self):
        src = "from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_CBC)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("DES" in f.sink for f in findings)

    def test_detects_arc4(self):
        src = "from Crypto.Cipher import ARC4\ncipher = ARC4.new(key)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("ARC4" in f.sink for f in findings)

    def test_safe_sha256(self):
        src = "import hashlib\nh = hashlib.sha256(data)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_safe_aes_cbc(self):
        src = "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_CBC)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Hardcoded Secrets ─────────────────────────────────────────────────────────

class TestHardcodedSecretsRule:
    rule = HardcodedSecretsRule()

    def test_detects_hardcoded_api_key(self):
        src = 'api_key = "sk-abc123supersecretvalue"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert findings[0].sink == "api_key"

    def test_detects_hardcoded_password(self):
        src = 'password = "hunter2password99"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_hardcoded_secret(self):
        src = 'SECRET_KEY = "supersecretdjangokeyvalue"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_password_kwarg(self):
        src = 'db.connect(host="localhost", password="prodpassword123")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any(f.sink == "password" for f in findings)

    def test_ignores_placeholder(self):
        src = 'api_key = "<your-api-key-here>"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_ignores_empty_string(self):
        src = 'password = ""'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_ignores_non_secret_variable(self):
        src = 'username = "admin"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Insecure Random ───────────────────────────────────────────────────────────

class TestInsecureRandomRule:
    rule = InsecureRandomRule()

    def test_detects_token_from_random(self):
        src = "import random\ntoken = random.randint(0, 999999)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "random.randint" in findings[0].sink

    def test_detects_random_in_password_function(self):
        src = """\
import random
import string
def generate_password():
    return ''.join(random.choice(string.ascii_letters) for _ in range(16))
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_session_token_from_random(self):
        src = "import random\nsession_token = random.getrandbits(128)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_safe_random_for_non_security_use(self):
        src = "import random\nroll = random.randint(1, 6)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Weak JWT ──────────────────────────────────────────────────────────────────

class TestWeakJWTRule:
    rule = WeakJWTRule()

    def test_detects_algorithms_none(self):
        src = "import jwt\ndata = jwt.decode(token, algorithms=None)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert findings[0].sink == "jwt.decode"

    def test_detects_algorithms_list_none(self):
        src = 'import jwt\ndata = jwt.decode(token, key, algorithms=["none"])'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_verify_signature_false(self):
        src = 'import jwt\ndata = jwt.decode(token, options={"verify_signature": False})'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_verify_false_legacy(self):
        src = "import jwt\ndata = jwt.decode(token, verify=False)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_safe_jwt_with_algorithm(self):
        src = 'import jwt\ndata = jwt.decode(token, key, algorithms=["HS256"])'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Insecure Cookie ───────────────────────────────────────────────────────────

class TestInsecureCookieRule:
    rule = InsecureCookieRule()

    def test_detects_missing_httponly(self):
        src = 'response.set_cookie("session", value, secure=True)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "httponly" in findings[0].sink

    def test_detects_httponly_false(self):
        src = 'response.set_cookie("session", value, httponly=False, secure=True)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "httponly=False" in findings[0].sink

    def test_detects_missing_secure(self):
        src = 'response.set_cookie("session", value, httponly=True)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "secure" in findings[0].sink

    def test_detects_django_session_cookie_secure_false(self):
        src = "SESSION_COOKIE_SECURE = False"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "settings.py")
        assert len(findings) == 1
        assert findings[0].sink == "SESSION_COOKIE_SECURE"

    def test_detects_django_session_cookie_httponly_false(self):
        src = "SESSION_COOKIE_HTTPONLY = False"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "settings.py")
        assert len(findings) == 1

    def test_safe_cookie_with_all_flags(self):
        src = 'response.set_cookie("session", value, httponly=True, secure=True, samesite="Lax")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── SSRF ──────────────────────────────────────────────────────────────────────

class TestSSRFRule:
    rule = SSRFRule()

    def test_detects_request_args_to_requests_get(self):
        src = """\
import requests
from flask import request
def fetch():
    url = request.args.get("url")
    return requests.get(url)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any("requests.get" in f.sink for f in findings)

    def test_detects_tainted_url_to_requests_post(self):
        src = """\
import requests
from flask import request
def proxy():
    target = request.form.get("target")
    return requests.post(target, data={})
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_urllib_urlopen(self):
        src = """\
import urllib.request
from flask import request
def fetch():
    url = request.args.get("url")
    return urllib.request.urlopen(url)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_hardcoded_url(self):
        src = """\
import requests
def fetch():
    return requests.get("https://api.example.com/data")
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── XXE ───────────────────────────────────────────────────────────────────────

class TestXXERule:
    rule = XXERule()

    def test_detects_lxml_parse_no_parser(self):
        src = "from lxml import etree\ntree = etree.parse(f)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "lxml.parse" in findings[0].sink

    def test_detects_lxml_fromstring_no_parser(self):
        src = "from lxml import etree\ndoc = etree.fromstring(xml_data)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "lxml.fromstring" in findings[0].sink

    def test_detects_unsafe_xmlparser(self):
        src = "from lxml import etree\nparser = etree.XMLParser()"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_safe_lxml_with_safe_parser(self):
        src = """\
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse(f, parser=parser)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        # parse() is safe because parser= is provided; XMLParser itself flags but resolve_entities=False
        assert not any("lxml.parse" in f.sink for f in findings)


# ── Insecure TLS ──────────────────────────────────────────────────────────────

class TestInsecureTLSRule:
    rule = InsecureTLSRule()

    def test_detects_requests_verify_false(self):
        src = "import requests\nrequests.get(url, verify=False)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "verify=False" in findings[0].sink

    def test_detects_create_unverified_context(self):
        src = "import ssl\nctx = ssl._create_unverified_context()"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "_create_unverified_context" in findings[0].sink

    def test_detects_check_hostname_false(self):
        src = "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("check_hostname" in f.sink for f in findings)

    def test_detects_cert_none(self):
        src = "import ssl\nctx.verify_mode = ssl.CERT_NONE"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("CERT_NONE" in f.sink for f in findings)

    def test_detects_weak_tls_protocol(self):
        src = "import ssl\nssl.SSLContext(ssl.PROTOCOL_TLSv1)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert any("TLSv1" in f.sink for f in findings)

    def test_safe_verify_true(self):
        src = "import requests\nrequests.get(url, verify=True)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Debug Enabled ─────────────────────────────────────────────────────────────

class TestDebugEnabledRule:
    rule = DebugEnabledRule()

    def test_detects_debug_true(self):
        src = "DEBUG = True"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "settings.py")
        assert len(findings) == 1
        assert findings[0].sink == "DEBUG"

    def test_detects_app_run_debug_true(self):
        src = "app.run(debug=True)"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "app.run" in findings[0].sink

    def test_detects_app_debug_attribute(self):
        src = "app.debug = True"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_safe_debug_false(self):
        src = "DEBUG = False"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "settings.py")
        assert findings == []

    def test_safe_app_run_no_debug(self):
        src = 'app.run(host="0.0.0.0", port=8080)'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Stack Trace Leak ──────────────────────────────────────────────────────────

class TestStackTraceLeakRule:
    rule = StackTraceLeakRule()

    def test_detects_format_exc_returned(self):
        src = """\
import traceback
def view():
    try:
        risky()
    except Exception:
        return traceback.format_exc()
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_str_exception_returned(self):
        src = """\
def view():
    try:
        risky()
    except Exception as e:
        return str(e)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_print_exc(self):
        src = """\
import traceback
def view():
    try:
        risky()
    except Exception:
        traceback.print_exc()
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_generic_error_response(self):
        src = """\
def view():
    try:
        risky()
    except Exception:
        return "An error occurred", 500
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── TOCTOU ────────────────────────────────────────────────────────────────────

class TestTOCTOURule:
    rule = TOCTOURule()

    def test_detects_exists_then_open(self):
        src = """\
import os
def read_file(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert "path" in findings[0].sink

    def test_detects_isfile_then_open(self):
        src = """\
import os
def process(filename):
    if os.path.isfile(filename):
        open(filename, "r")
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_access_then_remove(self):
        src = """\
import os
def delete(path):
    if os.access(path, os.W_OK):
        os.remove(path)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_try_except_open(self):
        src = """\
def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_no_false_positive_different_paths(self):
        src = """\
import os
def process(a, b):
    if os.path.exists(a):
        open(b)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── ReDoS ─────────────────────────────────────────────────────────────────────

class TestReDoSRule:
    rule = ReDoSRule()

    def test_detects_user_controlled_pattern(self):
        src = """\
import re
from flask import request
def search():
    pattern = request.args.get("pattern")
    return re.compile(pattern)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any("re.compile" in f.sink for f in findings)

    def test_detects_tainted_pattern_in_match(self):
        src = """\
import re
from flask import request
def validate():
    pat = request.args.get("regex")
    return re.match(pat, data)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_catastrophic_backtracking_pattern(self):
        src = r'import re\nre.compile("(a+)+")'
        # Use proper multiline string
        src = 'import re\nre.compile("(a+)+")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_literal_pattern(self):
        src = 'import re\nre.compile("^[a-zA-Z0-9]+$")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_safe_non_security_user_input(self):
        src = """\
import re
def search(text, term):
    return re.search(term, text)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Open Redirect ─────────────────────────────────────────────────────────────

class TestOpenRedirectRule:
    rule = OpenRedirectRule()

    def test_detects_request_args_to_redirect(self):
        src = """\
from flask import request, redirect
def login():
    next_url = request.args.get("next")
    return redirect(next_url)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any(f.sink == "redirect" for f in findings)

    def test_detects_django_http_response_redirect(self):
        src = """\
from django.http import HttpResponseRedirect
from django.http import HttpRequest
def view(request):
    url = request.GET.get("next")
    return HttpResponseRedirect(url)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "views.py")
        assert len(findings) >= 1

    def test_detects_tainted_redirect_through_variable(self):
        src = """\
from flask import request, redirect
def after_login():
    dest = request.form.get("destination")
    target = dest
    return redirect(target)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_hardcoded_redirect(self):
        src = """\
from flask import redirect
def logout():
    return redirect("/login")
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── Mass Assignment ───────────────────────────────────────────────────────────

class TestMassAssignmentRule:
    rule = MassAssignmentRule()

    def test_detects_request_json_unpacked(self):
        src = """\
from flask import request
def create():
    return User(**request.json)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1
        assert any("User" in f.sink for f in findings)

    def test_detects_request_form_unpacked(self):
        src = """\
from flask import request
def update():
    return Profile(**request.form)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_detects_tainted_dict_unpacked(self):
        src = """\
from flask import request
def create():
    data = request.get_json()
    return User(**data)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) >= 1

    def test_safe_explicit_field_assignment(self):
        src = """\
from flask import request
def create():
    data = request.json
    return User(name=data.get("name"), email=data.get("email"))
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_safe_non_request_unpack(self):
        src = """\
def create():
    defaults = {"name": "anonymous", "role": "user"}
    return User(**defaults)
"""
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []


# ── CORS Misconfiguration ─────────────────────────────────────────────────────

class TestCORSMisconfigRule:
    rule = CORSMisconfigRule()

    def test_detects_cors_wildcard_origins(self):
        src = 'from flask_cors import CORS\nCORS(app, origins="*")'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "origins='*'" in findings[0].sink

    def test_detects_wildcard_in_origins_list(self):
        src = 'from flask_cors import CORS\nCORS(app, origins=["*"])'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1

    def test_detects_acao_header_wildcard(self):
        src = 'response.headers["Access-Control-Allow-Origin"] = "*"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert len(findings) == 1
        assert "Access-Control-Allow-Origin" in findings[0].sink

    def test_detects_django_cors_allow_all(self):
        src = "CORS_ALLOW_ALL_ORIGINS = True"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "settings.py")
        assert len(findings) == 1
        assert findings[0].sink == "CORS_ALLOW_ALL_ORIGINS"

    def test_detects_cors_origin_allow_all_legacy(self):
        src = "CORS_ORIGIN_ALLOW_ALL = True"
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "settings.py")
        assert len(findings) == 1

    def test_safe_specific_origin(self):
        src = 'from flask_cors import CORS\nCORS(app, origins=["https://example.com"])'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []

    def test_safe_acao_specific_domain(self):
        src = 'response.headers["Access-Control-Allow-Origin"] = "https://example.com"'
        tree, lines = _parse(src)
        findings = self.rule.check(tree, lines, "app.py")
        assert findings == []
