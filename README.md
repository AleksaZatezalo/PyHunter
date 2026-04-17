# PyHunter

**RCE-focused vulnerability scanner for Python AI agents and web applications.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PyHunter is built specifically to find **remote code execution vulnerabilities** in Python codebases — with a primary focus on **AI agent frameworks** such as LangChain, CrewAI, AutoGPT, LlamaIndex, Haystack, and custom agent tooling built on the Anthropic or OpenAI SDKs.

AI agents are a uniquely high-risk target class: they accept untrusted input (user prompts, tool outputs, fetched web content) and frequently pass it into dangerous sinks — `eval()`, `exec()`, `subprocess.run()`, `pickle.loads()` — either directly or through dynamically composed strings. A single prompt-injection that reaches an unguarded `eval()` call gives an attacker arbitrary code execution in the agent's process. PyHunter exists to find those paths before an attacker does.

It combines four layers of analysis:

1. **AST rule engine** — 9 rules across 3 attack phases that flag dangerous patterns without any API calls
2. **Intra-procedural taint engine** — traces user-controlled data from source to sink, records the full propagation path, and detects when sanitizers are applied (and whether they can be bypassed)
3. **Claude LLM enrichment pipeline** — validates exploitability, assesses sanitizer bypass risk, generates proof-of-concept payloads, writes runnable exploit scripts, and produces an exploit chain narrative when multiple findings span different attack phases
4. **Agentic exploit loop** — when a local target instance is running, a Claude agent reads source files, fires live HTTP requests, and iterates until RCE is confirmed with a safe payload (`id` / `whoami` / `echo PWNEDBYRESEARCHER`), then writes a verified `exploit.py`

---

## What it detects

PyHunter targets vulnerability classes that result in, or directly enable, remote code execution. Rules are organised by attack phase.

### Phase 1 — Initial Access

How attacker-controlled data enters the application and reaches dangerous code.

| Rule ID | Description | Common sinks |
|---------|-------------|--------------|
| `FLOW-WEB` | Web or CLI input flows to a dangerous sink within a single function | `eval(request.args["q"])`, `os.system(form["cmd"])` |
| `CMD-INJECT` | Tainted input reaches an OS command executor | `os.system`, `os.popen`, `subprocess.run(shell=True)`, `subprocess.Popen` |
| `DESER-RCE` | Tainted input passed to an unsafe deserialiser | `pickle.loads`, `yaml.load(Loader=None)`, `dill.loads`, `jsonpickle.decode` |
| `FILE-UPLOAD` | File saved without extension validation to an executable path | `f.save(user_path)`, `open(user_path, "wb")` |
| `PICKLE-NET` | Pickle deserialisation of data read directly from a network socket | `pickle.loads(sock.recv(...))`, `pickle.loads(response.content)` |

### Phase 2 — Code Execution

The mechanism that turns attacker input into arbitrary code execution.

| Rule ID | Description | Common sinks |
|---------|-------------|--------------|
| `RCE-EVAL` | Dynamic code execution via built-in functions | `eval(x)`, `exec(x)`, `compile(x, ...)` |
| `EXEC-DECORATOR` | Dangerous or user-controlled expression used as a decorator | `@eval(user_expr)`, dynamic route decorators |

### Phase 3 — Supply Chain

Code that runs at build or import time, enabling persistence across deployments.

| Rule ID | Description | Trigger |
|---------|-------------|---------|
| `RCE-BUILD` | Dangerous `setup()` arguments in `setup.py` | `setup(cmdclass=...)`, `setup(ext_modules=...)` |
| `RCE-IMPORT` | Dangerous call executed at module import time | `eval(...)` or `os.system(...)` at top-level in `__init__.py` or `setup.py` |

### AI agent-specific patterns

The rules above already cover the most common RCE paths in agent frameworks. Typical patterns PyHunter catches:

- **LangChain `PythonREPLTool` / `BashTool`** — these are intentional shells; PyHunter flags surrounding code that feeds unvalidated user input into them (`CMD-INJECT`, `FLOW-WEB`)
- **Agent `eval()` loops** — agents that `eval()` their own outputs, tool responses, or fetched web content (`RCE-EVAL`)
- **Prompt-injection → `pickle.loads`** — agents that deserialise LLM-controlled data from an external store (`DESER-RCE`, `PICKLE-NET`)
- **Dynamic tool construction** — agents that build callables or import paths from user-supplied strings (`RCE-EVAL`, `EXEC-DECORATOR`)
- **Malicious dependency installs** — `setup.py` hooks in packages pulled in by agent dependency management (`RCE-BUILD`, `RCE-IMPORT`)

---

## How it works

```
.py source files
      │
      ▼
 AST rules (9)  +  taint engine
      │                │
      │                └── records source → variable chain → sink path
      │                    detects sanitizers; marks bypass risk
      ▼
   raw findings
      │
      ├─▶  Claude: analyze       exploitability verdict + confidence score (0.0–1.0)
      │             │
      │             └── false positive? → dropped here
      │
      ├─▶  Claude: taint         taint path assessment, sanitizer bypass analysis,
      │                          chain potential (what this sink unlocks)
      ├─▶  Claude: explain       plain-English description for developers
      ├─▶  Claude: poc           minimal safe payload (id, whoami, echo pwned, …)
      ├─▶  Claude: demo          runnable self-contained Python exploit script
      └─▶  Claude: context       standalone vs. chained? prerequisites? impact?
      │
      ▼
 verified per-finding reports
      │
 Chain engine: group confirmed findings by attack phase (1 → 2 → 3)
      │
      └─▶  Claude: chain         end-to-end attack narrative for multi-phase chains
      │
      ▼
 Static exploit generation (no --target-url)
      │
      └─▶  Claude: exploit_gen   complete Python3 exploit chain script (safe payload)
           Writes: output-dir/report.md + output-dir/exploit.py

── OR, when --target-url is set ─────────────────────────────────────────────

      ▼
 Agentic exploit loop (up to 12 iterations)
      │
      ├─▶  read_file    read source files to understand routes, params, auth
      ├─▶  http_request fire live requests against the running local instance
      └─▶  run_script   execute candidate exploit scripts in a subprocess
      │             │
      │             └── RCE output observed (id/whoami/PWNEDBYRESEARCHER)?
      │                    YES → write verified exploit.py, exit loop
      │                    NO  → analyse failure, adjust payload, retry
      ▼
 output-dir/report.md   — full vulnerability report (markdown)
 output-dir/exploit.py  — verified Python3 exploit chain (safe payload)
```

LLM enrichment is fully optional — `--no-llm` runs only the AST rules and taint engine, which have zero API cost and return results instantly. The chain engine only runs on findings Claude has confirmed as exploitable. All Claude responses are cached on disk (`~/.cache/pyhunter/`) keyed by a SHA-256 of the prompt, so re-scanning identical code costs nothing.

---

## Installation

```bash
git clone https://github.com/AleksaZatezalo/pyhunter
cd pyhunter
pip install -e ".[dev]"
```

Set your Anthropic API key (required for LLM enrichment and the agentic loop; not needed with `--no-llm`):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

### Scan a file or directory

```bash
# Full scan: AST + taint + Claude enrichment + chain analysis
pyhunter scan ./my_agent/

# AST + taint only — no API calls, instant results, useful for CI
pyhunter scan ./my_agent/ --no-llm

# Keep findings Claude marks as false positives
pyhunter scan ./my_agent/ --keep-fp

# Write report.md and exploit.py to a directory
pyhunter scan ./my_agent/ --output-dir ./results

# Show code snippets in live enrichment progress
pyhunter scan ./my_agent/ --verbose
```

Exit codes: `0` = no confirmed findings, `1` = one or more confirmed findings. Safe for use in CI pipelines.

### Agentic exploit confirmation

When a local instance of the target application is running, pass its URL with `--target-url`. PyHunter will start an agentic loop: Claude reads the source files it already scanned, fires real HTTP requests (or runs Python scripts) against the running instance, and iterates until it either confirms RCE with a safe payload or exhausts its attempts. The result is a **verified** `exploit.py`.

```bash
# Start the vulnerable application locally first:
python ./my_agent/app.py          # or: docker run -p 5000:5000 my_app

# Scan + agentic exploit confirmation in one command:
pyhunter scan ./my_agent/ \
  --output-dir ./results \
  --target-url http://localhost:5000
```

The agentic loop prints each tool call as it runs:

```
  Starting agentic exploit loop against http://localhost:5000 …
  [read] ./my_agent/app.py
  [read] ./my_agent/routes/run.py
  [http] POST /api/run
  [exec] import requests; r = requests.post("http://localhost:5000/api/run" ...
  [http] POST /api/run
  Exploit → ./results/exploit.py
```

Safe payload guarantee: the only command the agent may execute via RCE is `id`, `whoami`, or `echo PWNEDBYRESEARCHER`. This is enforced in the system prompt — the agent is instructed to use only these payloads and to never execute destructive commands.

`--target-url` has no effect with `--no-llm`. A warning is printed and the scan continues normally.

### Scan packages from PyPI

```bash
# Scan one or more PyPI packages (downloads source, scans, writes reports)
pyhunter pypi langchain crewai autogpt-libs

# AST-only, keep extracted sources for manual review
pyhunter pypi langchain \
  --no-llm \
  --output-dir ./pyhunter_results \
  --keep-sources
```

Each package gets a subdirectory under `--output-dir` containing a `report.md` and a `summary.json`.

### All options

```
pyhunter scan TARGET [OPTIONS]

  TARGET              File or directory to scan
  --no-llm            AST rules + taint engine only; skip all Claude calls
  --keep-fp           Include findings Claude marks as false positives
  --output-dir, -o    Write report.md + exploit.py to this directory
  --target-url URL    Base URL of a running local instance — activates the
                      agentic exploit loop for live RCE confirmation
  --verbose           Show code snippets in live enrichment progress

pyhunter pypi PACKAGE... [OPTIONS]

  PACKAGE             One or more PyPI package names
  --no-llm            AST rules + taint engine only
  --keep-fp           Include false positives
  --output-dir DIR    Directory for per-package reports (default: ./pyhunter_results)
  --keep-sources      Keep downloaded and extracted source trees
```

---

## Output

Every `pyhunter scan ... --output-dir <dir>` run produces exactly two files:

### `report.md`

A consolidated markdown report containing:

1. Summary table (severity breakdown, finding count, chain count)
2. Per-finding sections: metadata, code snippet, taint path + sanitizer status, taint analysis, exploitability verdict, explanation, PoC payload, runnable demo script, exploitation context
3. **Taint Flow Summary**: findings grouped by source type, sanitizer coverage, chain membership; high-severity unsanitized flows highlighted and cross-referenced to their chain
4. **Exploit Chains**: per-chain attack steps (with taint annotations), Claude-written attack narrative, prerequisites, impact

### `exploit.py`

A complete, runnable Python 3 exploit chain script. When generated statically (no `--target-url`), Claude writes it from the vulnerability report. When generated via the agentic loop (`--target-url`), Claude iterates against the live instance and the script is written only after RCE is confirmed.

All exploit scripts include:
- A `TARGET` variable the tester can reconfigure
- A `main()` function with `if __name__ == "__main__": main()`
- A responsible-disclosure header: `FOR RESPONSIBLE DISCLOSURE / RESEARCH ONLY — SAFE PAYLOAD ONLY`
- A safe RCE payload: `id`, `whoami`, or `echo PWNEDBYRESEARCHER`

---

## Taint tracking

PyHunter's taint engine performs intra-procedural data flow analysis on every function in the scanned codebase. For each confirmed flow from a user-controlled source to a dangerous sink, it records:

- **Propagation path** — every variable assignment from source to sink, with line numbers
- **Sanitizer detection** — whether the tainted value passed through a known sanitizer (`shlex.quote`, `html.escape`, `re.escape`, `bleach.clean`, `markupsafe.escape`, and equivalents)
- **Bypass risk** — Claude evaluates whether the specific sanitizer can be bypassed for the specific sink (e.g. `shlex.quote` does not protect `os.system` when `shell=True` is still set)

**Recognised sources:** Flask `request.*`, Django `request.GET/POST/body`, DRF `request.query_params`, Tornado `self.request.*`, Starlette `request.query_params`, `sys.argv`, `os.environ`, `input()`

**Recognised sinks:** `eval`, `exec`, `compile`, `open`, `os.system`, `os.popen`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`, `pickle.loads`, `pickle.load`, `yaml.load`

---

## Exploit chaining

After enrichment, the chain engine groups confirmed findings by attack phase and asks Claude to narrate the end-to-end attack:

- **Phase 1 + 2** (most common): user-controlled input reaches an initial-access sink, which feeds a code-execution sink — e.g. `FLOW-WEB → RCE-EVAL` or `CMD-INJECT → RCE-EVAL`
- **Phase 1 + 3**: initial-access finding enables persistence — e.g. `FILE-UPLOAD → RCE-IMPORT`
- **All phases**: full kill-chain across initial access, code execution, and supply-chain persistence

Each chain includes:
- Ordered attack steps with taint path annotations (source and sanitizer status per step)
- A Claude-written narrative describing exactly which file and function each step targets
- Prerequisites (minimum attacker access level)
- Impact (final capability)

---

## Configuration

PyHunter searches for a config file starting from the current directory, walking up to the filesystem root, then falling back to `~/.pyhunterrc`. Accepted filenames: `.pyhunterrc`, `.pyhunter.json`.

```json
{
    "disabled_rules": ["RCE-BUILD"],
    "min_severity": "HIGH",
    "cache_enabled": true
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `disabled_rules` | `string[]` | `[]` | Rule IDs to skip entirely (e.g. `"RCE-BUILD"` for library code with intentional `setup.py` hooks) |
| `min_severity` | `string\|null` | `null` | Drop findings below this severity: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `cache_enabled` | `bool` | `true` | Cache Claude responses on disk at `~/.cache/pyhunter/`; set to `false` to always re-query |

---

## Project structure

```
pyhunter/
├── cli.py                    # CLI commands (scan, pypi); terminal output; report builders
├── models.py                 # Finding and ExploitChain dataclasses + serialisation
├── config.py                 # .pyhunterrc / .pyhunter.json loader
├── engine/
│   ├── scanner.py            # pipeline: collect → parse → taint → enrich → chain
│   ├── chainer.py            # groups findings by phase; builds up to 3 chain candidates
│   └── pypi.py               # PyPI package download, extract, scan, per-package reports
├── rules/
│   ├── registry.py           # loads all rules from definitions/
│   ├── loader.py             # reads YAML rule files, instantiates YAMLRule + Matcher
│   ├── matchers.py           # 6 strategy implementations: Call, Taint, AssignTrack, …
│   └── definitions/          # YAML rule files (one per rule ID)
├── skills/
│   ├── __init__.py           # async_call_claude() with SHA-256 disk cache
│   ├── enrich.py             # 6-stage per-finding enrichment pipeline
│   ├── analyze.py            # exploitability verdict + confidence score
│   ├── taint_skill.py        # taint path assessment, sanitizer bypass, chain potential
│   ├── explain.py            # developer-friendly explanation
│   ├── poc.py                # minimal safe PoC payload
│   ├── demo.py               # runnable self-contained exploit script
│   ├── context.py            # standalone vs. chained exploitation context
│   ├── chain.py              # cross-finding chain narrative
│   ├── exploit_gen.py        # static exploit chain script generation (single LLM call)
│   ├── agent_exploit.py      # agentic exploit loop: tool-use, live HTTP, RCE confirmation
│   └── prompts/              # system prompt .md files for each skill
└── taint/
    ├── __init__.py           # CFGAnalyzer facade + legacy TaintEngine compat shim
    ├── cfg.py                # CFG builder: lowers AST → FunctionIR
    ├── analysis.py           # worklist may-taint dataflow analysis → List[TaintPath]
    ├── ir.py                 # IR node types: IRAssign, IRSanitize, IRCall, BasicBlock
    ├── types.py              # typed contracts: TaintPath, TaintAnalysis, PathStep, …
    └── _helpers.py           # shared AST helpers + source/sink/sanitizer tables
tests/
├── test_rules.py             # unit tests for all 9 rules (no LLM)
├── test_chain_rules.py       # DESER-RCE, CMD-INJECT, FILE-UPLOAD across frameworks
├── test_chain_rules_extended.py  # multi-hop taint, string formats, edge cases
├── test_taint.py             # taint engine: sources, propagation, sinks, metadata
├── test_taint_analysis.py    # CFG-based taint analysis
├── test_cfg.py               # CFG builder
├── test_cli.py               # CLI flags, output-dir behaviour, --target-url
├── test_agent_exploit.py     # agentic loop: tool sandboxing, code extraction, mock loop
├── test_pypi_scanner.py      # PyPI download/extract/report pipeline
└── test_integration.py       # end-to-end scan on a real vulnerable fixture file
```

---

## Running tests

No API key is required. All rule, taint, and agent tool tests use direct inputs with no LLM calls. The agentic loop tests mock the Anthropic client.

```bash
pip install -e ".[dev]"

# Full suite (227 tests)
pytest tests/ -v

# Fastest subset — rules + taint only
pytest tests/test_rules.py tests/test_chain_rules.py \
       tests/test_chain_rules_extended.py tests/test_taint.py -v

# Agentic loop unit tests only
pytest tests/test_agent_exploit.py -v

# With coverage
pytest tests/ --cov=pyhunter --cov-report=term-missing
```

| Test file | Scope |
|-----------|-------|
| `test_rules.py` | Every rule: correct detections and safe negatives |
| `test_chain_rules.py` | DESER-RCE, CMD-INJECT, FILE-UPLOAD across Flask/Django/FastAPI/Tornado |
| `test_chain_rules_extended.py` | Multi-hop taint, alternative string formats, edge cases |
| `test_taint.py` | Taint engine: source detection, propagation, sink matching, flow metadata |
| `test_taint_analysis.py` | CFG-based taint dataflow analysis |
| `test_cfg.py` | CFG builder: if/else, loops, try/except lowering |
| `test_cli.py` | CLI flags, output-dir, --target-url warning, report content |
| `test_agent_exploit.py` | read_file sandboxing, run_script timeout, code extraction, mocked tool-use loop |
| `test_pypi_scanner.py` | PyPI download/extract/report pipeline |
| `test_integration.py` | End-to-end scan on a real vulnerable fixture file |

---

## Adding a rule

Rules are defined in YAML files in `pyhunter/rules/definitions/`. No Python code changes needed.

```yaml
id: MY-RULE
description: Short description of what this detects.
severity: HIGH
phase: 2
tags: [rce]
strategy: taint
taint:
  sources: web_inputs        # named source set from sources.yaml
  sinks:
    - my_dangerous_function
```

Available strategies: `call`, `taint`, `assign_track`, `decorator`, `file_scope`, `save_heuristic`.

The `phase` field controls chain membership automatically — no changes to `chainer.py` needed.

---

## Safety

PyHunter is a **defensive security testing tool for responsible disclosure research**. Use it only on code you own or have explicit written permission to test.

- PoC payloads and the agentic loop use safe, non-destructive commands only: `id`, `whoami`, `echo PWNEDBYRESEARCHER`
- The agentic loop only connects to the URL you supply with `--target-url` — no outbound traffic to any other host
- `run_script` executes candidate exploit code in a subprocess with a 15-second timeout; the process is isolated from PyHunter's own environment
- `read_file` is sandboxed to the parent directory of the scanned target — it cannot read `/etc/passwd`, SSH keys, or other sensitive paths outside the project
- The agentic loop has a hard cap of 12 iterations
- Follow responsible disclosure practices when reporting findings to third parties

---

## License

MIT
