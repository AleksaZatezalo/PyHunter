# PyHunter

> Static analysis tool for finding remote code execution vulnerabilities in Python web applications.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PyHunter scans Python web applications for paths that lead to **remote code execution**. It combines AST-based detection rules, an intra-procedural taint engine, and an optional Claude enrichment pipeline that validates whether each finding is genuinely exploitable, generates a proof-of-concept payload, and chains related findings into a complete attack narrative.

Supported frameworks: **Flask, Django, DRF, FastAPI, Tornado, Starlette**.

---

## What it detects

PyHunter focuses exclusively on vulnerability classes that result in, or directly enable, remote code execution.

### Phase 1 — Initial Access

How an attacker gets user-controlled input into dangerous code.

| Rule | Description | Example sinks |
|------|-------------|---------------|
| `FLOW-WEB` | Web or CLI input flows to a dangerous sink within a function | `eval(request.args["q"])`, `os.system(form["cmd"])` |
| `CMD-INJECT` | Tainted input reaches an OS command executor | `os.system`, `os.popen`, `subprocess.run(shell=True)` |
| `DESER-RCE` | Tainted input passed to an unsafe deserialiser | `pickle.loads`, `yaml.load`, `dill.loads`, `jsonpickle.decode` |
| `FILE-UPLOAD` | File saved without extension validation to an executable path | `f.save(user_path)`, `open(user_path, "wb")` |
| `PICKLE-NET` | Pickle deserialization of data read from a network socket | `pickle.loads(sock.recv(...))`, `pickle.loads(response.content)` |

### Phase 2 — Code Execution

The mechanism that turns attacker input into arbitrary code execution.

| Rule | Description | Example sinks |
|------|-------------|---------------|
| `RCE-EVAL` | Dynamic code execution via built-in functions | `eval(x)`, `exec(x)`, `compile(x, ...)` |
| `EXEC-DECORATOR` | Dangerous or user-controlled expression used as a decorator | `@eval(user_expr)`, `@app.route(user_path)` |

### Phase 3 — Supply Chain

Code that runs at build or import time, enabling persistence across deployments.

| Rule | Description | Trigger |
|------|-------------|---------|
| `RCE-BUILD` | Dangerous `setup()` arguments in `setup.py` | `setup(cmdclass=...)`, `setup(ext_modules=...)` |
| `RCE-IMPORT` | Dangerous call executed at import time | `eval(...)` or `os.system(...)` in `__init__.py` or `setup.py` |

---

## How it works

```
.py source files
      │
      ▼
AST rules (9 rules)  +  taint engine
      │
      ▼  raw findings
      │
      ├─▶ Claude: analyze       is this genuinely exploitable? (confidence 0.0–1.0)
      │          ▼ false positive? → dropped
      ├─▶ Claude: explain       plain-English description + attack scenario
      ├─▶ Claude: poc           minimal safe payload (e.g. id, whoami, echo pwned)
      ├─▶ Claude: demo          runnable self-contained Python exploit script
      └─▶ Claude: context       standalone vs. chained? prerequisites? impact?
      │
      ▼  verified per-finding reports
      │
Chain engine: group confirmed findings by attack phase (1 → 2 → 3)
      │
      └─▶ Claude: chain         end-to-end attack narrative for multi-phase chains
```

Each enrichment step is a modular async skill in `pyhunter/skills/`. Chain analysis only runs on findings Claude has confirmed as exploitable.

---

## Installation

```bash
git clone https://github.com/AleksaZatezalo/pyhunter
cd pyhunter
pip install -e ".[dev]"
```

Set your Anthropic API key (required for LLM enrichment; not needed for `--no-llm` mode):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Running a scan

### Scan a file or directory

```bash
# Full scan: AST rules + taint + Claude enrichment + chain analysis
pyhunter scan ./target_app/

# AST + taint only — no API calls, instant results, useful for CI
pyhunter scan ./target_app/ --no-llm

# Include findings Claude marks as false positives
pyhunter scan ./target_app/ --keep-fp

# Write a consolidated markdown report
pyhunter scan ./target_app/ --output report.md

# Machine-readable JSON (findings array + chains array)
pyhunter scan ./target_app/ --output report.json --format json

# Plain-text report
pyhunter scan ./target_app/ --output report.txt --format text
```

### Scan packages from PyPI

```bash
# Scan one or more packages
pyhunter pypi celery requests fabric

# AST-only, save results + keep extracted sources
pyhunter pypi celery \
  --no-llm \
  --output-dir ./pyhunter_results \
  --keep-sources
```

Each package gets a subdirectory under `--output-dir` containing per-finding `.md` files and a `summary.json`.

### Example terminal output

```
  AST scan complete — 4 raw findings  (0.1s)
  ────────────────────────────────────────────────────────────────────
  FLOW-WEB              ████████████████████████████  2
  CMD-INJECT            ████████████████              1
  DESER-RCE             ████████                      1
  ────────────────────────────────────────────────────────────────────
  Enriching with Claude …

  ✓ [CRITICAL ] FLOW-WEB-0031      eval              exploitable    1/4 (25%)
  ✓ [CRITICAL ] CMD-INJECT-0058    os.system         exploitable    2/4 (50%)
  ✗ [CRITICAL ] FLOW-WEB-0074      pickle.loads      false-positive 3/4 (75%)
  ✓ [CRITICAL ] DESER-RCE-0091     yaml.load(unsafe) exploitable    4/4 (100%)

  ══════════════════════════════════════════════════════════════════════
  EXPLOIT CHAINS — 1 chain(s) identified
  ══════════════════════════════════════════════════════════════════════

  [CRITICAL]  CHAIN-001  —  FLOW-WEB → CMD-INJECT

  ┌─ Attack Steps ─────────────────────────────────────────────────────
  │  1. [CRITICAL]  FLOW-WEB    views.py:31
  │  2. [CRITICAL]  CMD-INJECT  views.py:58
  └────────────────────────────────────────────────────────────────────

  ┌─ Attack Narrative ──────────────────────────────────────────────────
  │  An unauthenticated attacker sends a crafted HTTP request to the
  │  search endpoint at views.py:31, where request.args flows directly
  │  into eval(). The evaluated expression spawns a subprocess through
  │  os.system at views.py:58, granting full shell access as the web
  │  server process.
  └─────────────────────────────────────────────────────────────────────
```

---

## Configuration

Create `.pyhunterrc` (JSON) in your project root or home directory:

```json
{
    "disabled_rules": ["RCE-BUILD"],
    "min_severity": "HIGH",
    "cache_enabled": true
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `disabled_rules` | `[]` | Rule IDs to skip |
| `min_severity` | `null` | Drop findings below this level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `cache_enabled` | `true` | Cache Claude responses on disk (`~/.cache/pyhunter/`) |

---

## JSON output schema

```json
{
  "findings": [
    {
      "id": "FLOW-WEB-0031",
      "rule_id": "FLOW-WEB",
      "severity": "CRITICAL",
      "file": "app/views.py",
      "line": 31,
      "snippet": "...",
      "sink": "eval",
      "source": "request.args",
      "exploitable": true,
      "confidence": 0.97,
      "analysis": "request.args flows into eval() with no sanitisation.",
      "explanation": "...",
      "poc": "'; import os; os.system('id') #",
      "demo": "...",
      "context": "..."
    }
  ],
  "chains": [
    {
      "id": "CHAIN-001",
      "title": "FLOW-WEB → CMD-INJECT",
      "severity": "CRITICAL",
      "steps": ["FLOW-WEB-0031", "CMD-INJECT-0058"],
      "narrative": "...",
      "prerequisites": "Unauthenticated HTTP access to the search endpoint.",
      "impact": "Arbitrary shell command execution as the web server process."
    }
  ]
}
```

---

## Project structure

```
pyhunter/
├── cli.py                    # CLI — scan, pypi commands; terminal output
├── models.py                 # Finding and ExploitChain dataclasses
├── config.py                 # .pyhunterrc / .pyhunter.json loader
├── engine/
│   ├── scanner.py            # pipeline: collect → parse → enrich → chain
│   ├── chainer.py            # groups findings by phase, builds chain candidates
│   └── pypi.py               # PyPI package download, extract, scan, report
├── rules/
│   ├── __init__.py           # BaseRule abstract base class (Template Method)
│   ├── registry.py           # registers all 9 active rules (Registry pattern)
│   ├── _sources.py           # shared taint-source vocabulary for all frameworks
│   ├── web_flow.py           # FLOW-WEB
│   ├── cmd_injection.py      # CMD-INJECT
│   ├── deser_rce.py          # DESER-RCE
│   ├── file_upload_rce.py    # FILE-UPLOAD
│   ├── pickle_socket.py      # PICKLE-NET
│   ├── rce_eval.py           # RCE-EVAL
│   ├── decorator_exec.py     # EXEC-DECORATOR
│   ├── build_rce.py          # RCE-BUILD
│   └── import_time_exec.py   # RCE-IMPORT
├── skills/
│   ├── __init__.py           # async_call_claude() with disk cache (Strategy)
│   ├── enrich.py             # 5-stage per-finding pipeline (Chain of Responsibility)
│   ├── analyze.py            # exploitability verdict + confidence score
│   ├── explain.py            # developer-friendly explanation
│   ├── poc.py                # minimal safe payload
│   ├── demo.py               # runnable self-contained exploit script
│   ├── context.py            # standalone vs. chained context
│   └── chain.py              # cross-finding chain narrative
└── taint/
    └── __init__.py           # intra-procedural taint engine (Visitor pattern)
tests/
├── test_rules.py             # unit tests for all 9 rules (no LLM)
├── test_chain_rules.py       # tests for DESER-RCE, CMD-INJECT, FILE-UPLOAD
├── test_chain_rules_extended.py
├── test_taint.py
├── test_cli.py
├── test_pypi_scanner.py
└── test_integration.py
```

---

## Running tests

No API key is needed for the test suite. All rule tests use direct AST input with no LLM calls.

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full test suite
pytest tests/ -v

# Run only the rule unit tests (fastest)
pytest tests/test_rules.py tests/test_chain_rules.py tests/test_chain_rules_extended.py -v

# Run with coverage
pytest tests/ --cov=pyhunter --cov-report=term-missing
```

The test files each have a clear scope:

| File | What it tests |
|------|---------------|
| `test_rules.py` | Every rule individually: correct detections + safe negatives |
| `test_chain_rules.py` | DESER-RCE, CMD-INJECT, FILE-UPLOAD across Flask/Django/FastAPI/Tornado |
| `test_chain_rules_extended.py` | Multi-hop taint, alternative string formats, edge cases |
| `test_taint.py` | Standalone taint engine: source detection, propagation, sink matching |
| `test_cli.py` | CLI flag behaviour, output format selection |
| `test_pypi_scanner.py` | PyPI download/extract/report pipeline |
| `test_integration.py` | End-to-end scan on a real vulnerable fixture file |

---

## Adding a rule

1. Create `pyhunter/rules/my_rule.py` subclassing `BaseRule`
2. Implement `check(tree, source_lines, filepath) → List[Finding]`
3. Register it in `pyhunter/rules/registry.py`

```python
from pyhunter.rules import BaseRule
from pyhunter.rules._sources import is_tainted_expr, collect_taint
from pyhunter.models import Finding, Severity
import ast

class MyRule(BaseRule):
    rule_id     = "MY-RULE"
    description = "Short description of what this detects."

    def check(self, tree, source_lines, filepath):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tainted, _ = collect_taint(node)
                for call in ast.walk(node):
                    if not isinstance(call, ast.Call):
                        continue
                    # match your pattern, check is_tainted_expr(arg, tainted)
                    findings.append(Finding(
                        id=f"{self.rule_id}-{call.lineno:04d}",
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=filepath,
                        line=call.lineno,
                        snippet=self._snippet(source_lines, call.lineno),
                        sink="dangerous_function",
                    ))
        return findings
```

To include the rule in chain analysis, add its `rule_id` to `PHASE_MAP` in `engine/chainer.py`.

---

## Safety

PyHunter is a defensive security testing tool. Use it only on applications you own or have explicit written permission to test.

- PoC payloads use safe commands only (`id`, `whoami`, `echo pwned`) — no destructive operations
- Follow responsible disclosure when reporting findings to third parties

---

## License

MIT
