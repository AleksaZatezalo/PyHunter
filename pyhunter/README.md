# PyHunter

> AI-augmented Python vulnerability scanner — finds bugs, confirms exploitability, chains findings into end-to-end attack paths.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PyHunter combines **AST-based static analysis**, an **intra-procedural taint engine**, and a **Claude-powered enrichment pipeline** to produce findings that go far beyond pattern matching. It validates whether each finding is genuinely exploitable, generates a minimal proof-of-concept payload and a runnable exploit script, then reasons about how multiple confirmed findings chain together into a complete attack path — from initial web-app access to host root.

---

## How It Works

```
.py files
    │
    ▼
AST rule match (15 rules)  +  taint engine
    │
    ▼  raw findings
    │
    ├─▶ Claude: analyze       is this genuinely exploitable? (confidence 0.0–1.0)
    │          ▼ false positive? → dropped
    ├─▶ Claude: explain       plain-English description + attack scenario
    ├─▶ Claude: poc           minimal safe payload (e.g. {{7*7}}, id, whoami)
    ├─▶ Claude: demo          runnable self-contained Python exploit script
    └─▶ Claude: context       standalone vs. chained? prerequisites? impact?
    │
    ▼  per-finding verified reports
    │
    ▼
Chain engine: group confirmed findings by attack phase
    │
    └─▶ Claude: chain         end-to-end attack narrative for cross-phase chains
    │
    ▼  ExploitChain reports
```

Each enrichment stage is a modular async skill in `pyhunter/skills/`. The chain engine runs after all findings are verified, so it only reasons about confirmed exploitable issues.

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
# Full scan: AST + taint + Claude enrichment + chain analysis
pyhunter scan ./target_project

# AST + taint only — no API calls, instant results
pyhunter scan ./target_project --no-llm

# Keep findings Claude marks as false positives
pyhunter scan ./target_project --keep-fp

# Write per-finding and per-chain markdown reports
pyhunter scan ./target_project --output ./reports/

# Machine-readable JSON (findings + chains)
pyhunter scan ./target_project --output report.json --format json
```

### Scan PyPI packages

```bash
pyhunter pypi celery requests fabric

pyhunter pypi celery \
  --no-llm \
  --output-dir ./pyhunter_results \
  --keep-sources
```

Each package gets a subdirectory under `--output-dir` with one markdown file per finding and a `summary.json`.

### Example terminal output

```
  ██████╗ ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ...

  AST scan complete — 6 raw findings  (0.1s)
  ────────────────────────────────────────────────────────────────────
  AUTH-BYPASS           ████████████████████████████  2
  CMD-INJECT            ████████████████              1
  CONTAINER-ESCAPE      ████████████████              1
  HARDCODED-SECRET      ████████                      1
  SSTI                  ████████                      1
  ────────────────────────────────────────────────────────────────────
  Enriching with Claude …

  ✓ [CRITICAL ] AUTH-BYPASS-0023   jwt.decode(verify=False)  exploitable    1/6 (16%)
  ✓ [CRITICAL ] SSTI-0041          render_template_string    exploitable    2/6 (33%)
  ✓ [HIGH     ] CMD-INJECT-0089    os.system                 exploitable    3/6 (50%)
  ✓ [CRITICAL ] HARDCODED-SECRET   SECRET_KEY                exploitable    4/6 (66%)
  ✓ [CRITICAL ] CONTAINER-ESCAPE   docker.run(privileged)    exploitable    5/6 (83%)
  ✗ [HIGH     ] AUTH-BYPASS-0061   permission_classes=[]     false-positive 6/6 (100%)

  ══════════════════════════════════════════════════════════════════════
  EXPLOIT CHAINS — 1 chain(s) identified
  ══════════════════════════════════════════════════════════════════════

  [CRITICAL]  CHAIN-001  —  AUTH-BYPASS + SSTI → CMD-INJECT → Container Escape

  ┌─ Attack Steps ────────────────────────────────────────────────────
  │  1. [CRITICAL]  AUTH-BYPASS          views.py:23
  │  2. [CRITICAL]  SSTI                 views.py:41
  │  3. [HIGH    ]  CMD-INJECT           views.py:89
  │  4. [CRITICAL]  CONTAINER-ESCAPE     deploy.py:14
  └────────────────────────────────────────────────────────────────────

  ┌─ Attack Narrative ─────────────────────────────────────────────────
  │  An unauthenticated attacker first exploits the JWT bypass at
  │  views.py:23 to forge an admin token. Using this token they reach
  │  the admin template endpoint at views.py:41, injecting a Jinja2
  │  payload to achieve RCE as www-data. They then pivot through the
  │  os.system call at views.py:89 to write a cron backdoor, and
  │  finally exploit the privileged Docker container at deploy.py:14
  │  to escape to the host and obtain root.
  └────────────────────────────────────────────────────────────────────

  ┌─ Impact ───────────────────────────────────────────────────────────
  │  Unauthenticated remote attacker achieves root on the Docker host.
  └────────────────────────────────────────────────────────────────────
```

---

## Vulnerability Coverage

The 15 active rules cover the complete web-app-to-root attack chain across Flask, Django, FastAPI, Tornado, and Starlette.

### Phase 1 — Initial Access / RCE

| Rule ID | Description | Key Sinks | Severity |
|---------|-------------|-----------|----------|
| `SSTI` | Server-side template injection | Jinja2/Mako/Django `Template`, `render_template_string`, `from_string` | CRITICAL |
| `DESER-RCE` | Unsafe deserialization | `pickle.loads`, `yaml.load`, `dill.loads`, `jsonpickle.decode` | CRITICAL |
| `CMD-INJECT` | OS command injection | `os.system`, `os.popen`, `subprocess.run(shell=True)` | CRITICAL |
| `DEBUG-EXPOSED` | Exposed debug console | `app.run(debug=True)`, `DEBUG=True`, Werkzeug REPL | HIGH |
| `FILE-UPLOAD-RCE` | Unrestricted file upload | `f.save()` with unsanitised filename, write to executable paths | HIGH |

### Phase 2 — Data Exfiltration / Lateral Movement

| Rule ID | Description | Key Sinks | Severity |
|---------|-------------|-----------|----------|
| `SQL-INJECT` | SQL injection | `cursor.execute(f"...")`, `queryset.raw(f"...")`, `.extra(where=[f"..."])` | HIGH |
| `SSRF` | Server-side request forgery | `requests.get(url)`, `urllib.request.urlopen(url)` with user-controlled URL | HIGH |
| `XXE` | XML external entity injection | `etree.parse`, `minidom.parse`, `lxml.etree.XML` without safe parser | HIGH |
| `PATH-TRAVERSAL` | Path traversal / zip slip | `open(user_path)`, `send_from_directory`, `FileResponse(tainted)` | HIGH |

### Phase 3 — Credential Theft

| Rule ID | Description | Key Patterns | Severity |
|---------|-------------|--------------|----------|
| `HARDCODED-SECRET` | Credentials in source | API keys, JWT secrets, private keys, DB passwords assigned as literals | HIGH |

### Phase 4 — Auth / Privilege Bypass

| Rule ID | Description | Key Patterns | Severity |
|---------|-------------|--------------|----------|
| `AUTH-BYPASS` | Authentication bypass | `jwt.decode(verify=False)`, DRF `permission_classes=[]`, unprotected FastAPI sensitive routes | HIGH |
| `MASS-ASSIGN` | Mass assignment | `Model(**request.json)`, `User(**request.data)`, `Profile(**form)` | HIGH |

### Phase 5 — Host Privilege Escalation

| Rule ID | Description | Key Sinks | Severity |
|---------|-------------|-----------|----------|
| `SUID-RISK` | SUID / privilege escalation | `os.setuid(0)`, `os.chmod(path, 0o4755)`, SUID binary exec | HIGH |
| `WRITABLE-PATH` | Write to sensitive paths | Write to `/etc/cron*`, `/etc/sudoers*`, `/root/.ssh/authorized_keys`, `systemd` units | CRITICAL |
| `CONTAINER-ESCAPE` | Container escape | Docker socket access, `privileged=True`, `--pid=host`, `cap_add`, `volumes={"/": ...}` | CRITICAL |

---

## Exploit Chain Analysis

When multiple confirmed findings span two or more attack phases, the chain engine identifies them as a cross-phase sequence and asks Claude to write a specific, realistic attack narrative.

### How chains are built

```
Confirmed findings
    │
    ▼
Group by attack phase (1–5)
    │
    ▼  2+ phases present?
    │
    ├─ Full chain: one best-severity finding per phase, in attack-timeline order
    │  (auth bypass → credential theft → data exfil → RCE → host privesc)
    │
    ├─ RCE → Container Escape  (phases 1 + 5)
    │
    └─ Auth Bypass → Data Exfil  (phases 4 + 2)
    │
    ▼
Claude writes narrative, prerequisites, and impact for each chain
```

### `ExploitChain` fields

| Field | Description |
|-------|-------------|
| `id` | `CHAIN-001`, `CHAIN-002`, … |
| `title` | `AUTH-BYPASS + SSTI → CONTAINER-ESCAPE` |
| `severity` | Maximum severity across steps |
| `steps` | Ordered list of `Finding` objects |
| `narrative` | Step-by-step attack story (Claude) |
| `prerequisites` | Minimum attacker access required |
| `impact` | Final attacker capability |

Chains appear in console output after the per-finding summary, in markdown output files as `CHAIN-NNN.md`, and in JSON output under the `chains` key.

---

## JSON Output Schema

```json
{
  "findings": [
    {
      "id": "SSTI-0041",
      "rule_id": "SSTI",
      "severity": "CRITICAL",
      "file": "app/views.py",
      "line": 41,
      "snippet": "...",
      "sink": "render_template_string",
      "source": "request.args",
      "exploitable": true,
      "confidence": 0.95,
      "analysis": "User input reaches render_template_string with no sanitisation.",
      "explanation": "...",
      "poc": "{{7*7}}",
      "demo": "...",
      "context": "..."
    }
  ],
  "chains": [
    {
      "id": "CHAIN-001",
      "title": "AUTH-BYPASS + SSTI → CONTAINER-ESCAPE",
      "severity": "CRITICAL",
      "steps": ["AUTH-BYPASS-0023", "SSTI-0041", "CONTAINER-ESCAPE-0014"],
      "narrative": "...",
      "prerequisites": "Unauthenticated remote access to the login endpoint.",
      "impact": "Root on the Docker host."
    }
  ]
}
```

---

## Project Structure

```
pyhunter/
├── cli.py                    # Click CLI — scan, pypi commands; chain display
├── models.py                 # Finding + ExploitChain dataclasses
├── config.py                 # .pyhunterrc / .pyhunter.json loader
├── engine/
│   ├── scanner.py            # orchestrates rules + taint → enrichment → chains
│   ├── chainer.py            # groups findings by phase, builds chain candidates
│   └── pypi.py               # PyPI download, extract, scan, report
├── rules/
│   ├── __init__.py           # BaseRule interface
│   ├── registry.py           # 15 active rules
│   ├── _sources.py           # multi-framework taint source helpers
│   ├── r01_ssti.py           # … r15_container_escape.py
│   └── ...                   # additional experimental rules
├── skills/
│   ├── __init__.py           # async_call_claude() with disk caching
│   ├── enrich.py             # 5-stage per-finding pipeline orchestrator
│   ├── analyze.py            # exploitability verdict + confidence score
│   ├── explain.py            # developer-friendly explanation
│   ├── poc.py                # minimal safe payload
│   ├── demo.py               # runnable self-contained exploit script
│   ├── context.py            # standalone vs. chained context per finding
│   └── chain.py              # cross-finding chain narrative (Claude JSON)
└── taint/
    └── __init__.py           # intra-procedural taint engine (multi-hop)
examples/
└── vulnerable_app.py         # deliberately vulnerable Flask app
scripts/
└── github_scan.py            # mass-scan GitHub repositories
tests/
├── test_rules.py
├── test_chain_rules.py
├── test_chain_rules_extended.py
├── test_taint.py
├── test_cli.py
├── test_pypi_scanner.py
└── test_integration.py
```

---

## Adding a New Rule

1. Create `pyhunter/rules/my_rule.py` subclassing `BaseRule`
2. Implement `check(tree, source_lines, filepath) -> List[Finding]`
3. Register it in `pyhunter/rules/registry.py`

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
                id=f"{self.rule_id}-{node.lineno:04d}",
                rule_id=self.rule_id,
                severity=Severity.HIGH,
                file=filepath,
                line=node.lineno,
                snippet=self._snippet(source_lines, node.lineno),
                sink="dangerous_function",
            ))
        return findings
```

To place the rule in the exploit chain, add its `rule_id` to `PHASE_MAP` in `pyhunter/engine/chainer.py`.

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

- Generated payloads demonstrate exploitability without causing real harm (`id`, `whoami`, `{{7*7}}` — not destructive commands)
- Always follow responsible disclosure when reporting findings to third parties
- Do not scan systems you do not own or have explicit permission to test

---

## License

MIT
