# PyHunter

**AI-augmented vulnerability scanner for Python codebases.**

PyHunter detects exploitable vulnerabilities using a hybrid pipeline of AST-based static analysis and LLM-powered reasoning. Unlike traditional linters, it doesn't just flag risky patterns — it validates exploitability, generates explanations, and produces working proof-of-concept demonstrations.

---

## How It Works

PyHunter runs each finding through a five-stage reasoning pipeline:

```
AST Pattern Match → Exploitability Validation → Explanation → PoC + Demo Script → Context
```

Each stage is driven by a modular Claude skill. The analyze stage also emits a **confidence score** (0.0–1.0) alongside the exploitable/false-positive verdict. LLM responses are cached on disk (`~/.cache/pyhunter/`) so repeated scans of the same code skip the API entirely.

---

## Installation

```bash
git clone https://github.com/yourname/pyhunter
cd pyhunter
pip install -e .
```

For GitHub mass-scanning support:

```bash
pip install -e ".[github]"
```

For development and testing:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
pyhunter scan ./target_project
```

### Options

```
pyhunter scan TARGET [OPTIONS]

  --no-llm         AST rules only, skip Claude enrichment
  --keep-fp        Keep findings marked as false positives
  --output PATH    Write output here (file for --format json/text, dir for markdown)
  --format FORMAT  Output format: json or text
  --verbose        Show snippet in enrichment progress

pyhunter pypi PACKAGE [PACKAGE ...] [OPTIONS]

  --no-llm         AST rules only, skip Claude enrichment
  --keep-fp        Keep findings marked as false positives
  --output-dir DIR Directory to write per-package reports (default: ./pyhunter_results)
  --keep-sources   Preserve downloaded source trees
```

### Example Output

```json
{
  "id": "CMD-INJECT-0012",
  "severity": "CRITICAL",
  "file": "app.py",
  "line": 12,
  "sink": "os.system",
  "source": "request.args",
  "exploitable": true,
  "confidence": 0.95,
  "explanation": "User-controlled input flows into os.system(), allowing arbitrary command execution.",
  "poc": "; id",
  "demo": "# runnable exploit script..."
}
```

### JSON output for CI/CD

```bash
pyhunter scan ./src --no-llm --output results.json --format json
# exits 0 = no findings, 1 = findings found
```

---

## Configuration

Create a `.pyhunterrc` (JSON) in your project root or `~/.pyhunterrc` for global defaults:

```json
{
  "disabled_rules": ["DUNDER-ABUSE", "RCE-BUILD"],
  "min_severity": "MEDIUM",
  "cache_enabled": true
}
```

PyHunter walks up from the current directory to find the config file.

---

## Detection Coverage

PyHunter targets high-impact Python vulnerability classes:

| ID | Category | Examples |
|----|----------|---------|
| RCE-001 | Dynamic Code Execution | `eval()`, `exec()`, `compile()` |
| CMD-INJECT | Command Injection | `os.system`, `subprocess` with `shell=True` |
| DESER-UNSAFE | Unsafe Deserialization | `pickle`, `yaml.load`, `dill`, `jsonpickle` |
| DUNDER-ABUSE | Python Object Model Abuse | `__class__`, `__mro__`, `__subclasses__()` |
| RCE-IMPORT | Import-Time Execution | Malicious logic in `__init__.py` |
| RCE-BUILD | Build/Install-Time RCE | `setup.py` hooks (`cmdclass`, `ext_modules`) |
| PATH-TRAVERSAL | Path Traversal & File Abuse | User-controlled paths, Zip Slip |
| INJ-IMPORT | Dynamic Imports | `__import__`, `importlib` with user input |
| FLOW-WEB | Web Input → Sink Flows | HTTP/CLI input to `eval`, `subprocess`, file ops |
| EXEC-DECORATOR | Decorator-Based Execution | `@run(user_input)` patterns |
| PICKLE-NET | Network Deserialization | Pickle over sockets |
| SSTI | Template Injection | Jinja2/Mako/Flask with dynamic template strings |
| UNSAFE-SUBPROCESS | Subprocess with Dynamic Args | `subprocess.*` with non-constant commands |

---

## Project Structure

```
pyhunter/
├── engine/        # Scanning orchestration and pipeline coordination
├── rules/         # AST-based pattern detectors (13 active)
├── skills/        # Claude-powered reasoning modules
│   ├── analyze/   # Exploitability validation + confidence score
│   ├── explain/   # Vulnerability explanation
│   ├── poc/       # Payload generation
│   ├── demo/      # Runnable exploit script generation
│   └── context/   # Exploitation prerequisites analysis
├── taint/         # Intra-procedural data flow tracking
├── config.py      # .pyhunterrc config file loader
├── examples/      # Vulnerable code samples for testing
└── scripts/       # GitHub and PyPI scanning utilities
```

---

## Claude Skills

Each skill is a focused, reusable reasoning unit:

| Skill | Purpose |
|-------|---------|
| `analyze` | Determine exploitability + emit a confidence score (0.0–1.0) |
| `explain` | Generate a clear, accurate description of the vulnerability |
| `poc` | Produce a targeted, non-destructive exploit payload |
| `demo` | Build a self-contained, runnable demonstration script |
| `context` | Analyse exploitation prerequisites (standalone vs. chained) |

Skills reduce false positives by applying LLM reasoning after pattern matching, not instead of it. Responses are cached on disk so re-scanning identical code costs nothing.

---

## Testing

```bash
pip install -e ".[dev]"
pytest                              # 69 tests
pytest --cov=pyhunter               # with coverage

# Manual test against the bundled vulnerable Flask app
pyhunter scan examples/vulnerable_app.py --no-llm
```

---

## Roadmap

- [ ] Inter-procedural taint tracking (cross-function data flow)
- [ ] GitHub mass scanning integration
- [ ] PyPI package analysis pipeline
- [ ] CVE/CWE report generation mode
- [ ] Auto-fix suggestions
- [ ] SARIF output for GitHub Code Scanning

---

## Safety

PyHunter is designed for **defensive security research only**.

- Payloads are non-destructive and scoped to demonstration
- No exploit generation targeting production systems
- Responsible disclosure practices are assumed and encouraged

---

## Contributing

Contributions are welcome. Priority areas:

- New vulnerability rules under `rules/`
- Improved or additional Claude skills
- Real-world vulnerable samples for `examples/`
- Inter-procedural taint tracking engine

Please open an issue before submitting a significant PR.

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**. You are responsible for ensuring your use complies with applicable laws and responsible disclosure norms.

---

## Vision

PyHunter is built toward a single goal: an AI-assisted security researcher for the Python ecosystem — one that doesn't just find bugs, but proves, explains, and helps fix them.
