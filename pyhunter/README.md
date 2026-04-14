# PyHunter

**RCE-focused vulnerability scanner for Python AI agents and web applications.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PyHunter is built specifically to find **remote code execution vulnerabilities** in Python codebases — with a primary focus on **AI agent frameworks** such as LangChain, CrewAI, AutoGPT, LlamaIndex, Haystack, and custom agent tooling built on the Anthropic or OpenAI SDKs.

AI agents are a uniquely high-risk target class: they accept untrusted input (user prompts, tool outputs, fetched web content) and frequently pass it into dangerous sinks — `eval()`, `exec()`, `subprocess.run()`, `pickle.loads()` — either directly or through dynamically composed strings. A single prompt-injection that reaches an unguarded `eval()` call gives an attacker arbitrary code execution in the agent's process. PyHunter exists to find those paths before an attacker does.

It combines three layers of analysis:

1. **AST rule engine** — 9 rules across 3 attack phases that flag dangerous patterns without any API calls
2. **Intra-procedural taint engine** — traces user-controlled data from source to sink, records the full propagation path, and detects when sanitizers are applied (and whether they can be bypassed)
3. **Claude LLM enrichment pipeline** — validates exploitability, assesses sanitizer bypass risk, generates proof-of-concept payloads, writes runnable exploit scripts, and produces an exploit chain narrative when multiple findings span different attack phases

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
```

LLM enrichment is fully optional — `--no-llm` runs only the AST rules and taint engine, which have zero API cost and return results instantly. The chain engine only runs on findings Claude has confirmed as exploitable. All Claude responses are cached on disk (`~/.cache/pyhunter/`) keyed by a SHA-256 of the prompt, so re-scanning identical code costs nothing.

---

## Installation

```bash
git clone https://github.com/AleksaZatezalo/pyhunter
cd pyhunter
pip install -e ".[dev]"
```

Set your Anthropic API key (required for LLM enrichment; not needed with `--no-llm`):

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

# Write a consolidated markdown report
pyhunter scan ./my_agent/ --output report.md

# Machine-readable JSON (findings array + chains array)
pyhunter scan ./my_agent/ --output report.json --format json

# Plain-text columnar report
pyhunter scan ./my_agent/ --output report.txt --format text

# Show code snippets in live enrichment progress
pyhunter scan ./my_agent/ --verbose
```

Exit codes: `0` = no confirmed findings, `1` = one or more confirmed findings. Safe for use in CI pipelines.

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

Each package gets a subdirectory under `--output-dir` containing per-finding `.md` files and a `summary.json`.

### All options

```
pyhunter scan TARGET [OPTIONS]

  TARGET              File or directory to scan
  --no-llm            AST rules + taint engine only; skip all Claude calls
  --keep-fp           Include findings Claude marks as false positives
  --output PATH       Write structured output to this file
  --format FORMAT     Output format: markdown (default), json, text
  --verbose           Show code snippets in live enrichment progress

pyhunter pypi PACKAGE... [OPTIONS]

  PACKAGE             One or more PyPI package names
  --no-llm            AST rules + taint engine only
  --keep-fp           Include false positives
  --output-dir DIR    Directory for per-package reports (default: ./pyhunter_results)
  --keep-sources      Keep downloaded and extracted source trees
```

---

## Taint tracking

PyHunter uses a four-layer architecture where each layer communicates exclusively through typed data structures — no raw AST nodes or untyped dicts ever cross a layer boundary, so each layer can be independently swapped or tested.

```
Layer 1  Program Representation   AST → FunctionIR (CFG of typed IR instructions)
           cfg.py / ir.py
              │
              │  FunctionIR
              ▼
Layer 2  Taint Propagation        worklist may-taint dataflow → TaintPath
           analysis.py
              │
              │  TaintPath (typed: PathStep[], source_label, sink_label, sanitized, …)
              ▼
Layer 3  LLM Reasoning            Claude assesses path, bypass risk, chain potential → TaintAnalysis
           skills/taint_skill.py
              │
              │  TaintAnalysis (typed: sanitizer_bypass_risk, chain_potential, assessment)
              ▼
Layer 4  Output                   Finding serialisation (JSON, markdown, text)
           models.py / cli.py
```

### Layer 1 — CFG construction

The CFG builder lowers Python AST to typed IR instructions (`IRAssign`, `IRSanitize`, `IRCall`), then connects them into a `FunctionIR` graph of `BasicBlock`s:

- **if/else** — creates then-block, else-block, merge-block with correct predecessor/successor edges
- **for/while** — creates header, body, after-block with a back-edge (for loops also lower the iteration variable as an assignment)
- **try/except** — try-body and each handler are connected to a shared join block
- **with** — context manager body is flattened into the current block

### Layer 2 — Worklist dataflow analysis

May-taint analysis (forward, union-at-joins) over the CFG:

1. Initialise `taint_out[block] = {}` for all blocks; seed worklist with **all** blocks
2. For each block: join predecessor taint states, apply transfer function, collect sink paths
3. If state changed, add successors to worklist; repeat until convergence

Union-at-joins means a variable is considered tainted if it is tainted on **any** predecessor path — correctly handling code like `if flag: cmd = request.args.get(…); os.system(cmd)`.

### Layer 3 — LLM taint skill

`analyze_taint_path(TaintPath) → TaintAnalysis` — takes only the typed path, never touches AST nodes. Parses the Claude response into structured fields (bypass risk, chain potential, full assessment text).

### Recognised sources and sinks

**Sources:** Flask `request.*`, Django `request.GET/POST/body`, DRF `request.query_params`, Tornado `self.request.*`, Starlette `request.query_params`, `sys.argv`, `os.environ`, `input()`

**Sinks:** `eval`, `exec`, `compile`, `open`, `os.system`, `os.popen`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`, `pickle.loads`, `pickle.load`, `yaml.load`

**Sanitizers detected:** `shlex.quote`, `html.escape`, `re.escape`, `bleach.clean`, `markupsafe.escape` (and bare-import equivalents)

The taint path and sanitizer status appear in every output format — terminal, markdown, JSON, and text.

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

The **Taint Flow Summary** section in markdown reports cross-references which taint flows are members of a chain, grouped by source type, with high-severity unsanitized flows highlighted.

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

## Output formats

### JSON schema

```json
{
  "findings": [
    {
      "id": "FLOW-WEB-0031",
      "rule_id": "FLOW-WEB",
      "severity": "CRITICAL",
      "file": "agent/executor.py",
      "line": 31,
      "snippet": "    result = eval(tool_output)",
      "sink": "eval",
      "source": "request.args",
      "taint_path": [
        {"line": 24, "variable": "user_input", "description": "assigned from request.args"},
        {"line": 28, "variable": "tool_output", "description": "propagated to `tool_output`"},
        {"line": 31, "variable": "eval",        "description": "reaches sink eval()"}
      ],
      "sanitized": false,
      "sanitizer": null,
      "taint_assessment": "### Taint Path Assessment\n...\n### Chain Potential\n...",
      "exploitable": true,
      "confidence": 0.97,
      "analysis": "tool_output is derived from request.args with no guards before eval().",
      "explanation": "...",
      "poc": "'; import os; os.system('id') #",
      "demo": "...",
      "context": "..."
    }
  ],
  "chains": [
    {
      "id": "CHAIN-001",
      "title": "FLOW-WEB → RCE-EVAL",
      "severity": "CRITICAL",
      "steps": ["FLOW-WEB-0031", "RCE-EVAL-0044"],
      "narrative": "...",
      "prerequisites": "Unauthenticated HTTP access to the /run endpoint.",
      "impact": "Arbitrary code execution as the agent process."
    }
  ]
}
```

### Markdown report sections

A `--output report.md` file contains, in order:

1. Summary table (severity breakdown)
2. Per-finding sections: metadata, snippet, taint path + sanitizer status, taint analysis, exploitability verdict, explanation, PoC payload, runnable demo script, exploitation context
3. **Taint Flow Summary**: findings grouped by source type, sanitizer coverage, chain membership; highlighted high-severity unsanitized flows cross-referenced to their chain
4. Exploit Chains: per-chain attack steps (with taint annotations), narrative, prerequisites, impact

---

## Project structure

```
pyhunter/
├── cli.py                    # CLI commands (scan, pypi); terminal output; report builders
├── models.py                 # Finding and ExploitChain dataclasses + serialisation
├── config.py                 # .pyhunterrc / .pyhunter.json loader
├── engine/
│   ├── scanner.py            # pipeline: collect → parse → taint merge → enrich → chain
│   ├── chainer.py            # groups findings by phase; builds up to 3 chain candidates
│   └── pypi.py               # PyPI package download, extract, scan, per-package reports
├── rules/
│   ├── __init__.py           # BaseRule abstract class
│   ├── registry.py           # single entry point; delegates to loader.py
│   ├── loader.py             # reads definitions/*.yaml; Factory that produces YAMLRule
│   ├── matchers.py           # six strategy implementations:
│   │                         #   CallMatcher, TaintMatcher, AssignTrackMatcher,
│   │                         #   DecoratorMatcher, FileScopeMatcher, SaveHeuristicMatcher
│   └── definitions/          # ── YAML rule definitions ──────────────────────
│       ├── sources.yaml      #   shared taint-source vocabulary (all frameworks)
│       ├── rce_eval.yaml     #   RCE-EVAL        eval/exec/compile
│       ├── web_flow.yaml     #   FLOW-WEB        web/CLI input → dangerous sink
│       ├── cmd_inject.yaml   #   CMD-INJECT      OS command injection
│       ├── deser_rce.yaml    #   DESER-RCE       unsafe deserialisation
│       ├── file_upload.yaml  #   FILE-UPLOAD     unvalidated upload → webshell
│       ├── pickle_socket.yaml #  PICKLE-NET      pickle over network socket
│       ├── decorator_exec.yaml # EXEC-DECORATOR  dangerous/dynamic decorators
│       ├── build_rce.yaml    #   RCE-BUILD       setup.py cmdclass RCE
│       └── import_time_exec.yaml # RCE-IMPORT    import-time code execution
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
│   └── prompts/              # system prompt .md files for each skill
└── taint/
    ├── __init__.py           # legacy TaintEngine (backward compat) + CFGAnalyzer facade
    ├── _helpers.py           # shared AST helpers and source/sink/sanitizer tables
    ├── types.py              # typed layer contracts: SourceLocation, PathStep,
    │                         #   StepKind, TaintPath, TaintAnalysis
    ├── ir.py                 # IR node types: IRAssign, IRSanitize, IRCall,
    │                         #   BasicBlock, FunctionIR
    ├── cfg.py                # Layer 1: AST function → FunctionIR CFG builder
    └── analysis.py           # Layer 2: worklist may-taint dataflow → List[TaintPath]
tests/
├── test_rules.py             # unit tests for all 9 YAML-defined rules (no LLM)
├── test_chain_rules.py       # DESER-RCE, CMD-INJECT, FILE-UPLOAD across frameworks
├── test_chain_rules_extended.py  # multi-hop taint, string formats, edge cases
├── test_taint.py             # legacy TaintEngine: sources, propagation, sinks, metadata
├── test_cfg.py               # CFG builder: block structure, IR lowering, back-edges
├── test_taint_analysis.py    # typed contracts, worklist analysis, LLM skill (mocked)
├── test_cli.py               # CLI flag behaviour, output format selection
├── test_pypi_scanner.py      # PyPI download/extract/report pipeline
└── test_integration.py       # end-to-end scan on a real vulnerable fixture file
```

---

## Running tests

No API key is required. All rule and taint tests use direct AST input with no LLM calls.

```bash
pip install -e ".[dev]"

# Full suite (192 tests)
pytest tests/ -v

# Fastest subset — rules + taint only
pytest tests/test_rules.py tests/test_chain_rules.py \
       tests/test_chain_rules_extended.py tests/test_taint.py -v

# With coverage
pytest tests/ --cov=pyhunter --cov-report=term-missing
```

| Test file | Scope |
|-----------|-------|
| `test_rules.py` | Every rule: correct detections and safe negatives |
| `test_chain_rules.py` | DESER-RCE, CMD-INJECT, FILE-UPLOAD across Flask/Django/FastAPI/Tornado |
| `test_chain_rules_extended.py` | Multi-hop taint, alternative string formats, edge cases |
| `test_taint.py` | Legacy TaintEngine: source detection, propagation, sink matching, flow metadata |
| `test_cfg.py` | CFG builder: block structure, IR lowering, back-edges, async functions |
| `test_taint_analysis.py` | Typed contracts, worklist analysis, if-branch propagation, LLM skill (mocked) |
| `test_cli.py` | CLI flags, output format selection |
| `test_pypi_scanner.py` | PyPI download/extract/report pipeline |
| `test_integration.py` | End-to-end scan on a real vulnerable fixture file |

---

## Adding a rule

Rules are defined entirely in YAML. No Python changes are required.

### Quick example — detect a new dangerous function call

Create `pyhunter/rules/definitions/my_rule.yaml`:

```yaml
id: MY-RULE
description: "Short description of what this detects."
severity: HIGH
phase: 2          # 1=Initial Access  2=Code Execution  3=Supply Chain
tags: [rce, eval]

strategy: call
call:
  functions: [dangerous_func, other_func]
```

That's it. The rule is automatically loaded by `all_rules()` on the next run.

### Taint-aware rule

To flag user input flowing into a sink:

```yaml
id: MY-TAINT-RULE
description: "User input passed to a dangerous sink."
severity: CRITICAL
phase: 1
tags: [injection, taint]

strategy: taint
taint:
  sources: web_inputs      # vocabulary defined in sources.yaml
  sinks:
    - {module: mylib, function: dangerous}
    - {module: subprocess, function: run, require_shell_true: true}
```

### Available strategies

| Strategy | Use when |
|----------|----------|
| `call` | Match bare function calls by name (`eval`, `exec`, …) |
| `taint` | User-controlled data flows into a sink (per-function) |
| `assign_track` | Variable assigned from a network source reaches a deserialiser |
| `decorator` | Dangerous or dynamic decorator expressions |
| `file_scope` | Patterns that only apply to specific filenames (`setup.py`, `__init__.py`) |
| `save_heuristic` | File upload saved without extension/type validation |

Each strategy is implemented in `rules/matchers.py`. The shared source vocabulary (Flask, Django, FastAPI, Tornado, Starlette, CLI) lives in `rules/definitions/sources.yaml` and is referenced by name from taint rules.

The `phase` field controls exploit-chain grouping — the chain engine reads it directly from the YAML definition, so no changes to `engine/chainer.py` are needed.

---

## Safety

PyHunter is a defensive security testing tool. Use it only on code you own or have explicit written permission to test.

- PoC payloads use safe, non-destructive commands only (`id`, `whoami`, `echo pwned`)
- No exploit traffic is sent to any running system
- Follow responsible disclosure when reporting findings to third parties

---

## License

MIT
