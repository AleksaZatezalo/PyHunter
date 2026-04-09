"""
examples/vulnerable_app.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
A deliberately vulnerable Flask application for testing PyHunter.
DO NOT run this in production.
"""

import os
import pickle
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)


# ── RCE via eval ──────────────────────────────────────────────────────────────
@app.route("/calc")
def calculator():
    """Dangerous: executes user-supplied expression."""
    expr = request.args.get("expr", "")
    result = eval(expr)                      # PY-RCE-001
    return str(result)


# ── Command injection ─────────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    """Dangerous: injects user input into shell command."""
    host = request.args.get("host", "localhost")
    output = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)  # PY-CMD-001
    return output.stdout.decode()


@app.route("/ls")
def list_files():
    folder = request.args.get("folder", "/tmp")
    os.system(f"ls {folder}")               # PY-CMD-002
    return "ok"


# ── Unsafe deserialization ────────────────────────────────────────────────────
@app.route("/load", methods=["POST"])
def load_object():
    """Dangerous: deserialises arbitrary bytes from the request body."""
    data = request.get_data()
    obj = pickle.loads(data)                 # PY-DESER-001
    return str(obj)


@app.route("/config")
def load_config():
    raw = request.args.get("config", "{}")
    cfg = yaml.load(raw, Loader=yaml.Loader)  # PY-DESER-002  (unsafe Loader)
    return str(cfg)


# ── Dunder / object model abuse ───────────────────────────────────────────────
@app.route("/info")
def class_info():
    obj = request.args.get("obj", "")
    # Sandbox escape attempt
    subclasses = obj.__class__.__mro__[-1].__subclasses__()  # PY-DUNDER-001/002/003
    return str(subclasses)


if __name__ == "__main__":
    app.run(debug=True)
