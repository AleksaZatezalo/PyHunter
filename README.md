# PyHunter (MVP)

PyHunter is an experimental security tool that detects and proves exploitable vulnerabilities in Python codebases using a hybrid approach:

    🔍 Static analysis (AST-based rules)

    🧠 LLM-powered reasoning (“Claude skills”)

    💣 Automatic Proof-of-Concept (PoC) generation

    🧪 Self-contained exploit demos

Unlike traditional linters like Bandit, PyHunter doesn’t just flag risky patterns—it attempts to validate exploitability and generate working demonstrations.
🚀 MVP Goals

The MVP focuses on:

    Detecting high-impact vulnerabilities (especially RCE)

    Reducing false positives via LLM validation

    Generating:

        Clear explanations

        Exploit payloads

        Runnable demo scripts

🧠 How It Works

PyHunter uses a hybrid pipeline:

Pattern Match (AST)
        ↓
Claude Skill → Validate exploitability
        ↓
Claude Skill → Explain vulnerability
        ↓
Claude Skill → Generate PoC
        ↓
Claude Skill → Generate demo script

Each step is modular and driven by reusable “skills”.
🧩 Vulnerability Categories (MVP Scope)

PyHunter balances Python-specific attack surfaces with general security issues commonly seen in real-world code.
🔥 1. Dynamic Code Execution (RCE)

Type: Generic (high impact)

Detects unsafe execution of user-controlled input:

    eval(), exec(), compile()

Example:

eval(user_input)

🖥️ 2. Command Injection

Type: Generic

Detects unsafe shell execution:

    os.system

    subprocess with shell=True

Example:

subprocess.run(f"ls {user_input}", shell=True)

🧪 3. Unsafe Deserialization

Type: Generic (Python-heavy)

Targets:

    pickle

    yaml.load

    dill, jsonpickle

Why it matters:
Deserialization can lead directly to RCE.
🧬 4. Python Object Model Abuse (Dunder Escapes)

Type: Python-specific 🔥

Detects dangerous traversal:

    __class__

    __mro__

    __subclasses__()

Used for:

    Sandbox escapes

    Hidden RCE chains

📦 5. Import-Time Code Execution

Type: Python-specific

Python executes code on import.

Detects:

    Malicious logic in __init__.py

    Side effects during module import

🛠️ 6. Build / Install-Time RCE

Type: Python ecosystem-specific 🔥

Targets:

    setup.py

    pyproject.toml

Impact:
Code execution during:

pip install package

📂 7. Path Traversal & File Abuse

Type: Generic

Detects unsafe file handling:

    User-controlled file paths

    Archive extraction issues (Zip Slip)

🔌 8. Dynamic Imports & Module Injection

Type: Python-specific

Detects:

    __import__

    importlib with user input

    sys.path manipulation

🌐 9. Web Input → Sink Flows

Type: Generic (framework-aware)

Tracks user input from:

    HTTP requests

    CLI arguments

To dangerous sinks:

    eval

    subprocess

    file operations

🎭 10. Decorator-Based Execution

Type: Python-specific (often missed)

Detects execution hidden in decorators:

@run(user_input)
def handler():
    pass

🧪 Example Output

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

🏗️ Project Structure (Simplified)

pyhunter/
├── engine/        # scanning + orchestration
├── rules/         # AST-based detectors
├── skills/        # Claude-powered reasoning units
├── taint/         # (planned) data flow tracking
├── examples/      # vulnerable samples
└── scripts/       # GitHub / PyPI scanning

⚙️ Usage (MVP)

git clone https://github.com/yourname/pyhunter
cd pyhunter

pip install -e .

pyhunter scan ./target_project

🧠 Claude Skills

Each vulnerability is powered by modular prompts:

    analyze/ → Is it exploitable?

    explain/ → Why it matters

    poc/ → Generate payload

    demo/ → Create runnable exploit

This allows PyHunter to:

    Reduce false positives

    Provide actionable findings

    Assist in responsible disclosure

🔐 Safety Considerations

PyHunter is designed for defensive security research only.

    Generates non-destructive payloads only

    Encourages responsible disclosure

    Avoids harmful exploit generation

🧭 Roadmap

    Taint tracking engine

    GitHub mass scanning integration

    PyPI package analysis

    CVE report generation mode

    Auto-fix suggestions

    CI/CD integration

🤝 Contributing

Contributions welcome! Areas of interest:

    New vulnerability rules

    Improved Claude skills

    Test cases & real-world samples

⚠️ Disclaimer

This tool is for educational and defensive security purposes only. Always follow responsible disclosure practices when reporting vulnerabilities.
💡 Vision

PyHunter aims to evolve into:

    🧠 An AI-assisted security researcher for Python ecosystems

Not just finding bugs—but proving, explaining, and helping fix them.
