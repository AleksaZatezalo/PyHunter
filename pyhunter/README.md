# 🐍 PyHunter

> AI-powered Python vulnerability scanner — finds bugs, proves exploitability, generates PoCs.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PyHunter combines **AST-based static analysis** with **Claude-powered reasoning** to go beyond pattern matching. It validates whether a finding is actually exploitable, explains it in plain English, and generates a working proof-of-concept — all automatically.

---

## How It Works

```
AST Rule Match
     ↓
Claude → analyze   (is it exploitable? drop false positives)
     ↓
Claude → explain   (plain-English explanation)
     ↓
Claude → poc       (minimal non-destructive payload)
     ↓
Claude → demo      (runnable self-contained exploit script)
```

Each stage is a **modular skill** in `pyhunter/skills/`. Add new skills or swap models without touching the engine.

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

```bash
# Full scan with LLM enrichment
pyhunter scan ./target_project

# AST-only (fast, no API calls)
pyhunter scan ./target_project --no-llm

# Verbose output (explanation + PoC in terminal)
pyhunter scan ./target_project --verbose

# Write JSON report
pyhunter scan ./target_project --output report.json

# Write runnable demo scripts for each finding
pyhunter scan ./target_project --demo-dir ./demos/

# Keep confirmed false positives in output
pyhunter scan ./target_project --keep-fp
```

### Example output

```
[CRITICAL] PY-RCE-001 — RCE-EVAL
  File : examples/vulnerable_app.py:18
  Sink : eval
  Code : result = eval(expr)

  Explanation:
  User input from request.args flows directly into eval(), allowing an attacker
  to execute arbitrary Python code on the server. This is a complete server
  takeover via a single HTTP request.

  PoC payload: __import__('os').system('id')
```

---

## Vulnerability Coverage

| ID | Type | Sink / Pattern | Severity |
|----|------|----------------|----------|
| RCE-EVAL | Dynamic code execution | `eval`, `exec`, `compile` | CRITICAL |
| CMD-INJECT | Command injection | `os.system`, `subprocess(shell=True)` | CRITICAL |
| DESER-UNSAFE | Unsafe deserialization | `pickle.loads`, `yaml.load`, `dill` | CRITICAL |
| DUNDER-ABUSE | Object model abuse | `__class__`, `__mro__`, `__subclasses__` | HIGH |

More rules are straightforward to add — see [Contributing](#contributing).

---

## Project Structure

```
pyhunter/
├── engine/
│   └── scanner.py        # orchestrates rules → skills pipeline
├── rules/
│   ├── __init__.py       # BaseRule interface
│   ├── registry.py       # loads all rules
│   ├── rce_eval.py       # eval/exec/compile
│   ├── cmd_injection.py  # os.system / subprocess shell=True
│   ├── unsafe_deserialization.py
│   └── dunder_abuse.py
├── skills/
│   ├── __init__.py       # call_claude() wrapper
│   ├── analyze.py        # exploitability validation
│   ├── explain.py        # human-readable explanation
│   ├── poc.py            # minimal payload generation
│   └── demo.py           # runnable demo script
├── taint/
│   └── __init__.py       # planned taint engine (stub)
├── cli.py                # Click-based CLI
└── models.py             # Finding dataclass
examples/
└── vulnerable_app.py     # deliberately vulnerable Flask app
scripts/
└── github_scan.py        # mass-scan GitHub repos
tests/
├── test_rules.py         # unit tests (no LLM)
└── test_integration.py   # integration tests (no LLM)
```

---

## Adding a New Rule

1. Create `pyhunter/rules/my_rule.py` subclassing `BaseRule`
2. Implement `check(tree, source_lines, filepath) -> List[Finding]`
3. Register it in `pyhunter/rules/registry.py`

```python
from pyhunter.rules import BaseRule
from pyhunter.models import Finding, Severity

class MyRule(BaseRule):
    rule_id = "MY-RULE"
    description = "Detects dangerous pattern X."

    def check(self, tree, source_lines, filepath):
        findings = []
        for node in ast.walk(tree):
            # ... match the pattern ...
            findings.append(Finding(
                id="PY-MY-001",
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
# Unit tests only (no API key needed)
pytest tests/test_rules.py tests/test_integration.py -v

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

## Roadmap

- [ ] Intra-procedural taint tracking
- [ ] Inter-procedural taint (call graph)
- [ ] Framework-aware source detection (Flask, FastAPI, Django)
- [ ] Import-time & build-time RCE rules
- [ ] Web input → sink flow rules
- [ ] PyPI package scanning
- [ ] CVE report generation
- [ ] Auto-fix suggestions
- [ ] CI/CD integration (GitHub Actions)

---

## Safety

PyHunter is designed for **defensive security research only**.

- Generated payloads demonstrate exploitability without causing real harm (e.g. `id`, not `rm -rf`)
- Always follow responsible disclosure when reporting findings to third parties
- Do not scan systems you do not own or have explicit permission to test

---

## Contributing

PRs welcome. Areas of highest value:

- New AST rules for uncovered vulnerability classes
- Improved Claude skill prompts (better PoC quality, fewer false positives)
- Real taint propagation engine
- Additional test cases with real-world CVE samples

---

## License

MIT
