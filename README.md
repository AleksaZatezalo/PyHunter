# PyHunter

**AI-augmented vulnerability scanner for Python codebases.**

PyHunter detects exploitable vulnerabilities using a hybrid pipeline of AST-based static analysis and LLM-powered reasoning. Unlike traditional linters, it doesn't just flag risky patterns — it validates exploitability, generates explanations, and produces working proof-of-concept demonstrations.

---

## How It Works

PyHunter runs each finding through a four-stage reasoning pipeline:

```
AST Pattern Match → Exploitability Validation → Explanation → PoC + Demo Script
```

Each stage is driven by a modular Claude skill, making the pipeline easy to extend, tune, or replace.

---

## Installation

```bash
git clone https://github.com/yourname/pyhunter
cd pyhunter
pip install -e .
```

## Usage

```bash
pyhunter scan ./target_project
```

### Example Output

```json
{
  "id": "PY-RCE-001",
  "severity": "CRITICAL",
  "file": "app.py",
  "line": 12,
  "source": "request.args",
  "sink": "eval",
  "explanation": "User-controlled input flows into eval(), allowing arbitrary code execution.",
  "poc": "__import__('os').system('id')",
  "demo": "# runnable exploit script..."
}
```

---

## Detection Coverage

PyHunter targets high-impact Python vulnerability classes:

| ID | Category | Examples |
|----|----------|---------|
| RCE-001 | Dynamic Code Execution | `eval()`, `exec()`, `compile()` |
| RCE-002 | Command Injection | `os.system`, `subprocess` with `shell=True` |
| RCE-003 | Unsafe Deserialization | `pickle`, `yaml.load`, `dill`, `jsonpickle` |
| RCE-004 | Python Object Model Abuse | `__class__`, `__mro__`, `__subclasses__()` |
| RCE-005 | Import-Time Execution | Malicious logic in `__init__.py` |
| RCE-006 | Build/Install-Time RCE | `setup.py`, `pyproject.toml` hooks |
| PATH-001 | Path Traversal & File Abuse | User-controlled paths, Zip Slip |
| INJ-001 | Dynamic Imports | `__import__`, `importlib` with user input |
| FLOW-001 | Web Input → Sink Flows | HTTP/CLI input to `eval`, `subprocess`, file ops |
| EXEC-001 | Decorator-Based Execution | `@run(user_input)` patterns |

---

## Project Structure

```
pyhunter/
├── engine/        # Scanning orchestration and pipeline coordination
├── rules/         # AST-based pattern detectors
├── skills/        # Claude-powered reasoning modules
│   ├── analyze/   # Exploitability validation
│   ├── explain/   # Vulnerability explanation
│   ├── poc/       # Payload generation
│   └── demo/      # Runnable exploit script generation
├── taint/         # (planned) Data flow tracking
├── examples/      # Vulnerable code samples for testing
└── scripts/       # GitHub and PyPI scanning utilities
```

---

## Claude Skills

Each skill is a focused, reusable reasoning unit:

| Skill | Purpose |
|-------|---------|
| `analyze/` | Determine whether a pattern is actually exploitable in context |
| `explain/` | Generate a clear, accurate description of the vulnerability |
| `poc/` | Produce a targeted, non-destructive exploit payload |
| `demo/` | Build a self-contained, runnable demonstration script |

Skills reduce false positives by applying LLM reasoning after pattern matching, not instead of it.

---

## Roadmap

- [ ] Taint tracking engine
- [ ] GitHub mass scanning integration
- [ ] PyPI package analysis pipeline
- [ ] CVE report generation mode
- [ ] Auto-fix suggestions
- [ ] CI/CD integration

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
- Taint tracking engine work

Please open an issue before submitting a significant PR.

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**. You are responsible for ensuring your use complies with applicable laws and responsible disclosure norms.

---

## Vision

PyHunter is built toward a single goal: an AI-assisted security researcher for the Python ecosystem — one that doesn't just find bugs, but proves, explains, and helps fix them.
