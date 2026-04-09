# PyHunter

> AI-powered Python vulnerability scanner — finds bugs, validates exploitability, generates PoCs.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PyHunter combines **AST-based static analysis**, an **intra-procedural taint engine**, and **Claude-powered enrichment** to go beyond pattern matching. It validates whether a finding is actually exploitable, explains it in plain English, generates a minimal PoC payload, and produces a runnable exploit script — all automatically.

---

## How It Works

```
.py files
    ↓
AST rule match  +  taint engine  →  raw findings
    ↓
Claude → analyze    (exploitable or false positive?)
    ↓
Claude → explain    (plain-English explanation)
    ↓
Claude → poc        (minimal non-destructive payload)
    ↓
Claude → demo       (runnable self-contained exploit script)
    ↓
Claude → context    (standalone vs. chained exploitation)
    ↓
per-finding markdown reports
```

Each LLM stage is a modular skill in `pyhunter/skills/`. Enrichment runs asynchronously with up to 5 concurrent Claude API calls. Add new skills or swap models without touching the engine.

---

## Installation

```bash
git clone https://github.com/yourname/pyhunter
cd pyhunter
pip install -e ".[dev]"
```

Set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

### Scan a file or directory

```bash
# Full scan with Claude enrichment
pyhunter scan ./target_project

# AST + taint only (no API calls)
pyhunter scan ./target_project --no-llm

# Keep findings Claude marks as false positives
pyhunter scan ./target_project --keep-fp

# Write per-finding markdown reports to a directory
pyhunter scan ./target_project --output ./reports/
```

### Scan PyPI packages

```bash
# Download packages from PyPI and scan each one
pyhunter pypi celery requests fabric

# Options
pyhunter pypi celery \
  --no-llm \
  --output-dir ./pyhunter_results \
  --keep-sources
```

Each package gets a subdirectory under `--output-dir` with one markdown file per finding, plus a `summary.json`.

### Example terminal output

```
  ██████╗ ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ...

  AST scan complete — 4 raw findings  (0.1s)
  ────────────────────────────────────────────────────────────────────
  RCE-EVAL              ████████████████████████████  3
  CMD-INJECT            ████████                       1
  ────────────────────────────────────────────────────────────────────
  Enriching with Claude …

  ✓ [CRITICAL ] PY-RCE-001-...   eval                 exploitable    1/4 (25%)
  ✗ [HIGH     ] PY-RCE-002-...   exec                 false-positive 2/4 (50%)
  ...
```

---

## Vulnerability Coverage

| Rule ID | Description | Sinks / Patterns | Severity |
|---------|-------------|------------------|----------|
| `RCE-EVAL` | Dynamic code execution | `eval`, `exec`, `compile` | CRITICAL |
| `CMD-INJECT` | Command injection | `os.system`, `os.popen`, `subprocess(shell=True)` | CRITICAL |
| `DESER-UNSAFE` | Unsafe deserialization | `pickle.loads`, `yaml.load`, `dill` | CRITICAL |
| `PATH-TRAVERSAL` | Path traversal | `open()` with unsanitised paths | HIGH |
| `SSTI` | Server-side template injection | Jinja2/Mako dynamic render calls | HIGH |
| `UNSAFE-SUBPROCESS` | Subprocess with dynamic command | `subprocess.*` with non-literal args | HIGH |
| `PICKLE-NET` | Pickle over network socket | `pickle.loads` on socket-received data | CRITICAL |

Additional rules are implemented but not yet registered by default:

| Rule ID | Description |
|---------|-------------|
| `RCE-BUILD` | Build-time RCE via dangerous `setup()` arguments |
| `RCE-IMPORT` | Dangerous code executed at import time |
| `INJ-IMPORT` | Dynamic import with attacker-controlled module name |
| `DUNDER-ABUSE` | Access to dangerous dunder attributes |
| `EXEC-DECORATOR` | Dangerous or dynamic expression used as a decorator |
| `FLOW-WEB` | Web/CLI user input flowing directly into a sink |

---

## Project Structure

```
pyhunter/
├── engine/
│   ├── scanner.py        # orchestrates rules + taint → async LLM enrichment
│   └── pypi.py           # PyPI download, extract, scan, report
├── rules/
│   ├── __init__.py       # BaseRule interface
│   ├── registry.py       # active rule list
│   ├── rce_eval.py
│   ├── cmd_injection.py
│   ├── unsafe_deserialization.py
│   ├── path_traversal.py
│   ├── ssti.py
│   ├── unsafe_subprocess.py
│   ├── pickle_socket.py
│   └── ...               # additional rules (not yet registered)
├── skills/
│   ├── __init__.py       # call_claude() wrapper
│   ├── enrich.py         # orchestrates all skill stages per finding
│   ├── analyze.py        # exploitability validation
│   ├── explain.py        # human-readable explanation
│   ├── poc.py            # minimal payload generation
│   ├── demo.py           # runnable exploit script
│   └── context.py        # standalone vs. chained exploitation context
├── taint/
│   └── __init__.py       # intra-procedural taint engine
├── cli.py                # Click CLI (scan, pypi commands)
└── models.py             # Finding dataclass + markdown/dict serialization
examples/
└── vulnerable_app.py     # deliberately vulnerable Flask app
scripts/
└── github_scan.py        # mass-scan GitHub repos
tests/
├── test_rules.py
├── test_taint.py
├── test_cli.py
├── test_pypi_scanner.py
└── test_integration.py
```

---

## Adding a New Rule

1. Create `pyhunter/rules/my_rule.py` subclassing `BaseRule`
2. Implement `check(tree, source_lines, filepath) -> List[Finding]`
3. Add it to the list in `pyhunter/rules/registry.py`

```python
from pyhunter.rules import BaseRule
from pyhunter.models import Finding, Severity
import ast

class MyRule(BaseRule):
    rule_id     = "MY-RULE"
    description = "Detects dangerous pattern X."

    def check(self, tree, source_lines, filepath):
        findings = []
        for node in ast.walk(tree):
            # ... match the pattern ...
            findings.append(Finding(
                id=f"PY-MY-{node.lineno:04d}",
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                file=filepath,
                line=node.lineno,
                snippet=self._snippet(source_lines, node.lineno),
                sink="dangerous_function",
            ))
        return findings
```

---

## Running Tests

```bash
# Unit + integration tests (no API key needed)
pytest tests/ -v

# With coverage
pytest --cov=pyhunter --cov-report=term-missing
```

---

## Mass GitHub Scanning

```bash
pip install PyGithub
export GITHUB_TOKEN=ghp_...

python scripts/github_scan.py \
  --query "eval request.args language:Python" \
  --limit 20 \
  --output github_report.json
```

---

## Safety

PyHunter is a defensive security research tool.

- Generated payloads demonstrate exploitability without causing real harm (e.g. `id`, not `rm -rf`)
- Always follow responsible disclosure when reporting findings to third parties
- Do not scan systems you do not own or have explicit permission to test

---

## License

MIT
