"""PyHunter CLI."""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path
from typing import List, Optional

import click

from pyhunter.engine import Scanner
from pyhunter.engine.pypi import PyPIScanner
from pyhunter.models import ExploitChain, Finding

# ── Constants ─────────────────────────────────────────────────────────────────

_W = 68   # box width

_SEV_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "bright_red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "white",
}


# ── Commands ──────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("0.1.0", prog_name="pyhunter")
def cli():
    """PyHunter — AI-powered Python vulnerability scanner."""


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--no-llm",  is_flag=True, help="AST rules only, skip Claude enrichment.")
@click.option("--keep-fp", is_flag=True, help="Keep findings marked as false positives.")
@click.option("--output-dir", "-o", type=click.Path(), default=None,
              help="Write output to this directory (report.md + exploit.py).")
@click.option("--target-url", default=None, metavar="URL",
              help="Base URL of a running local instance (e.g. http://localhost:5000). "
                   "Activates the agentic exploit loop: Claude reads source files, "
                   "fires live requests, and iterates until RCE is confirmed.")
@click.option("--verbose", is_flag=True, help="Show snippet in enrichment progress.")
def scan(target, no_llm, keep_fp, output_dir, target_url, verbose):
    """Scan TARGET (file or directory) for vulnerabilities."""
    _banner()
    _kv("Target", target)
    _kv("Mode",   "AST only" if no_llm else "AST + Claude enrichment")
    if target_url:
        if no_llm:
            click.secho(
                "  Note: --target-url has no effect with --no-llm. "
                "Re-run without --no-llm to enable the agentic exploit loop.",
                fg="yellow",
            )
        else:
            _kv("Agent target", target_url)
    _rule()

    scanner  = Scanner(use_llm=not no_llm, skip_false_positives=not keep_fp)
    findings = _run_scan(scanner, target, use_llm=not no_llm)
    _print_results(
        findings,
        output_dir=output_dir,
        chains=scanner.chains,
        target=target,
        use_llm=not no_llm,
        target_url=target_url if not no_llm else None,
    )


@cli.command()
@click.argument("packages", nargs=-1, required=True)
@click.option("--no-llm",  is_flag=True, help="AST rules only, skip Claude enrichment.")
@click.option("--keep-fp", is_flag=True, help="Keep findings marked as false positives.")
@click.option("--output-dir", "-o", type=click.Path(), default="./pyhunter_results",
              show_default=True, help="Directory to write per-package markdown reports.")
@click.option("--keep-sources", is_flag=True, help="Preserve downloaded source trees.")
def pypi(packages, no_llm, keep_fp, output_dir, keep_sources):
    """Download PACKAGES from PyPI and scan each one.

    Example: pyhunter pypi celery requests fabric
    """
    _banner()
    _kv("Packages", ", ".join(packages))
    _kv("Mode",     "AST only" if no_llm else "AST + Claude enrichment")
    _kv("Output",   output_dir)
    _rule()

    use_llm     = not no_llm
    all_results = {}

    def on_package_start(name: str, version: str, scanner: Scanner) -> None:
        click.echo()
        _thick_rule()
        click.secho(f"  {name}  v{version}", bold=True)
        _thick_rule()
        t0 = time.time()

        def on_raw(findings: List[Finding]) -> None:
            _print_raw_summary(findings, time.time() - t0)

        def on_progress(done: int, tot: int, result: Optional[Finding]) -> None:
            _print_enriched_line(result, done, tot)

        scanner.raw_findings_callback = on_raw
        if use_llm:
            scanner.progress_callback = on_progress
        else:
            scanner.progress_callback = None

    out     = Path(output_dir)
    scanner = PyPIScanner(
        output_dir=out,
        keep_sources=keep_sources,
        scanner_kwargs=dict(
            use_llm=use_llm,
            skip_false_positives=not keep_fp,
        ),
        on_package_start=on_package_start,
    )
    results = scanner.run(list(packages))

    # ── Full per-finding detail ────────────────────────────────────────────
    for name, info in results.items():
        findings_dicts = info.get("findings", [])
        if findings_dicts:
            click.echo()
            _thick_rule()
            click.secho(f"  {name} — findings", bold=True)
            _thick_rule()
            # Reconstruct Finding objects for printing from the scanner's output
            # The scanner already wrote the markdown files; re-read them isn't clean.
            # Instead we print from the to_dict data we have.
            for fd in findings_dicts:
                _print_finding_dict(fd)

    # ── Summary table ──────────────────────────────────────────────────────
    click.echo()
    _thick_rule()
    click.secho("  SUMMARY", bold=True)
    _thick_rule()
    grand_total = 0
    for name, info in results.items():
        count   = info.get("finding_count", 0)
        version = info.get("version", "?")
        err     = info.get("error")
        grand_total += count
        if err:
            click.secho(f"  {name:<24} v{version:<10} ERROR: {err}", fg="red")
        else:
            color = "yellow" if count else "green"
            click.secho(f"  {name:<24} v{version:<10} {count} finding(s)", fg=color)
    _rule()
    click.echo(f"  {grand_total} total confirmed finding(s)  →  {out}/")
    click.echo()


# ── Scan orchestration ────────────────────────────────────────────────────────

def _run_scan(scanner: Scanner, target: str, use_llm: bool) -> List[Finding]:
    t0 = time.time()

    def on_raw(findings: List[Finding]) -> None:
        _print_raw_summary(findings, time.time() - t0)

    def on_progress(done: int, tot: int, result: Optional[Finding]) -> None:
        _print_enriched_line(result, done, tot)

    scanner.raw_findings_callback = on_raw
    if use_llm:
        scanner.progress_callback = on_progress

    findings = scanner.scan(target)

    if use_llm:
        elapsed = time.time() - t0
        click.echo(f"\n  Enrichment complete — {elapsed:.1f}s total")

    return findings


# ── Live output ───────────────────────────────────────────────────────────────

def _print_raw_summary(findings: List[Finding], elapsed: float) -> None:
    by_rule   = Counter(f.rule_id for f in findings)
    max_count = max(by_rule.values()) if by_rule else 1
    bar_width = 28

    click.echo()
    click.secho(f"  AST scan complete — {len(findings)} raw findings  ({elapsed:.1f}s)", bold=True)
    _rule()
    for rule_id, count in sorted(by_rule.items(), key=lambda x: -x[1]):
        bar = ("█" * int(count / max_count * bar_width)).ljust(bar_width)
        click.echo(f"  {rule_id:<22}  {bar}  {count}")
    _rule()
    if findings:
        click.secho("  Enriching with Claude …", bold=True)
        click.echo()


def _print_enriched_line(result: Optional[Finding], done: int, total: int) -> None:
    if result is None:
        return
    pct   = int(done / total * 100) if total else 0
    sev   = result.severity.value
    color = _SEV_COLOR.get(sev, "white")

    if result.exploitable is False:
        mark    = click.style("✗", fg="cyan")
        verdict = click.style("false-positive", fg="cyan")
    elif result.exploitable:
        mark    = click.style("✓", fg="green")
        verdict = click.style("exploitable   ", fg="green")
    else:
        mark    = click.style("?", fg="yellow")
        verdict = click.style("unknown       ", fg="yellow")

    analysis_snip = ""
    if result.analysis:
        analysis_snip = "  " + result.analysis[:60].replace("\n", " ")
    elif result.false_positive_reason:
        analysis_snip = "  " + result.false_positive_reason[:60].replace("\n", " ")

    click.echo(
        f"  {mark} [{click.style(f'{sev:<8}', fg=color, bold=True)}] "
        f"{result.id:<32} {click.style(result.sink or '—', dim=True):<20} "
        f"{verdict}  {done}/{total} ({pct}%)"
        f"{analysis_snip}"
    )


# ── Full finding detail ───────────────────────────────────────────────────────

def _print_results(
    findings: List[Finding],
    output_dir: Optional[str] = None,
    chains: Optional[List[ExploitChain]] = None,
    target: str = "",
    use_llm: bool = True,
    target_url: Optional[str] = None,
) -> None:
    # Write output directory first — always write even when findings list is empty.
    if output_dir:
        _write_output_dir(findings, chains or [], target, output_dir, use_llm, target_url)

    if not findings:
        click.echo()
        click.secho("  No confirmed findings.", fg="green")
        click.echo("  Tip: re-run with --keep-fp to include false positives.")
        click.echo()
        sys.exit(0)

    for f in findings:
        _print_finding(f)

    _print_summary(findings)
    _print_chains(chains or [])

    sys.exit(1)


def _build_markdown_report(
    findings: List[Finding],
    chains: List[ExploitChain],
    target: str = "",
) -> str:
    """Build a single consolidated markdown report for all findings and chains."""
    lines: List[str] = [
        "# PyHunter Vulnerability Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Date:** {date.today()}  ",
        f"**Findings:** {len(findings)} confirmed  ",
        f"**Chains:** {len(chains)} exploit chain(s)",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    by_sev = Counter(f.severity.value for f in findings)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = by_sev.get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count} |")

    lines += ["", "---", "", "## Findings", ""]

    for f in findings:
        # Demote h1 heading to h3 so the report has a clean hierarchy.
        finding_md = f.to_markdown().replace(f"# {f.id}", f"### {f.id}", 1)
        lines.append(finding_md)
        lines.append("---")
        lines.append("")

    # ── Taint Flow Summary ────────────────────────────────────────────────────
    taint_findings = [f for f in findings if f.taint_path]
    if taint_findings:
        lines += ["## Taint Flow Summary", ""]
        lines.append(
            f"{len(taint_findings)} of {len(findings)} finding(s) have a "
            f"recorded source→sink taint path.\n"
        )

        # Group by source type
        from collections import defaultdict as _dd
        by_source: dict = _dd(list)
        for f in taint_findings:
            by_source[f.source or "unknown"].append(f)

        lines += ["| Source | Findings | Sanitized | Chains |", "|--------|----------|-----------|--------|"]
        chain_finding_ids = {step.id for c in chains for step in c.steps}
        for src, flist in sorted(by_source.items()):
            san_count   = sum(1 for f in flist if f.sanitized)
            chain_count = sum(1 for f in flist if f.id in chain_finding_ids)
            san_str     = f"{san_count}/{len(flist)}" if san_count else "None"
            chain_str   = str(chain_count) if chain_count else "—"
            lines.append(f"| `{src}` | {len(flist)} | {san_str} | {chain_str} |")

        lines += [""]

        # Highlight unsanitized high-severity flows with chain membership
        high_unsan = [
            f for f in taint_findings
            if not f.sanitized and f.severity.value in ("CRITICAL", "HIGH")
        ]
        if high_unsan:
            lines += ["### High-Risk Unsanitized Flows", ""]
            for f in high_unsan:
                chain_ref = ""
                for c in chains:
                    if any(s.id == f.id for s in c.steps):
                        chain_ref = f"  → part of **{c.id}**: {c.title}"
                        break
                lines.append(
                    f"- **{f.id}** `{f.source or '?'}` → `{f.sink}`  "
                    f"`{f.file}:{f.line}`{chain_ref}"
                )
            lines.append("")

        lines += ["---", ""]

    if chains:
        lines += ["## Exploit Chains", ""]
        for c in chains:
            chain_md = c.to_markdown().replace(f"# {c.id}", f"### {c.id}", 1)
            lines.append(chain_md)
            lines.append("---")
            lines.append("")

    return "\n".join(lines)


def _write_output_dir(
    findings: List[Finding],
    chains: List[ExploitChain],
    target: str,
    output_dir: str,
    use_llm: bool,
    target_url: Optional[str] = None,
) -> None:
    """Write report.md and exploit.py to output_dir."""
    import asyncio
    from pyhunter.skills.exploit_gen import generate_exploit, no_exploit_placeholder

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    report_path = out / "report.md"
    report_path.write_text(_build_markdown_report(findings, chains, target=target))
    click.echo(f"\n  Report  → {report_path}")

    exploit_path = out / "exploit.py"
    if use_llm and target_url:
        from pyhunter.skills.agent_exploit import agent_exploit

        click.secho(
            f"  Starting agentic exploit loop against {target_url} …",
            bold=True, fg="bright_red",
        )

        def _on_tool(tool_name: str, tool_input: dict) -> None:
            icons = {"read_file": "read", "http_request": "http", "run_script": "exec"}
            icon  = icons.get(tool_name, tool_name)
            detail = (
                tool_input.get("path")
                or tool_input.get("path", tool_input.get("method", "") + " " + tool_input.get("path", ""))
                or str(tool_input)[:60]
            )
            if tool_name == "http_request":
                detail = f"{tool_input.get('method','?')} {tool_input.get('path','')}"
            elif tool_name == "run_script":
                detail = tool_input.get("code", "")[:60].replace("\n", " ")
            click.echo(f"  [{icon}] {detail}")

        exploit_code = asyncio.run(
            agent_exploit(findings, chains, target, target_url, progress_cb=_on_tool)
        )
    elif use_llm:
        click.secho("  Generating exploit PoC …", bold=True)
        exploit_code = asyncio.run(generate_exploit(findings, chains, target))
    else:
        exploit_code = no_exploit_placeholder(target)

    exploit_path.write_text(exploit_code)
    click.echo(f"  Exploit → {exploit_path}\n")


def _write_structured_output(
    findings: List[Finding],
    output: str,
    fmt: str,
    chains: Optional[List[ExploitChain]] = None,
    target: str = "",
) -> None:
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        payload = {
            "findings": [f.to_dict() for f in findings],
            "chains":   [c.to_dict() for c in (chains or [])],
        }
        out.write_text(json.dumps(payload, indent=2))
        click.echo(f"  JSON report written → {output}")
    elif fmt == "text":
        lines: List[str] = []
        for f in findings:
            lines.append(f"[{f.severity.value}] {f.rule_id}  {f.file}:{f.line}")
            lines.append(f"  Sink:    {f.sink or '—'}")
            lines.append(f"  Source:  {f.source or '—'}")
            if f.snippet:
                for ln in f.snippet.splitlines():
                    lines.append(f"  {ln}")
            lines.append("")
        if chains:
            lines.append("EXPLOIT CHAINS")
            lines.append("=" * 60)
            for c in chains:
                lines.append(f"\n[{c.severity.value}] {c.id} — {c.title}")
                lines.append(f"  Narrative: {c.narrative}")
                lines.append(f"  Prerequisites: {c.prerequisites}")
                lines.append(f"  Impact: {c.impact}")
                lines.append("")
        out.write_text("\n".join(lines))
        click.echo(f"  Text report written → {output}")
    elif fmt == "markdown":
        out.write_text(_build_markdown_report(findings, chains or [], target=target))
        click.echo(f"  Markdown report written → {output}")


def _format_taint_path(f: Finding) -> str:
    """Return a human-readable taint path string for terminal display."""
    if not f.taint_path:
        return ""
    san = f"  [sanitized by {f.sanitizer}]" if f.sanitized and f.sanitizer else ""
    steps = "\n".join(
        f"  {i}. L{step.location.line}  {step.variable:<18}  {step.description}"
        for i, step in enumerate(f.taint_path.steps, 1)
    )
    return f"Source: {f.source or '?'}{san}\n{steps}"


def _print_finding(f: Finding) -> None:
    sev   = f.severity.value
    color = _SEV_COLOR.get(sev, "white")

    click.echo()
    _thick_rule()
    click.secho(f"  [{sev}]  {f.id}  —  {f.rule_id}", fg=color, bold=True)
    _thick_rule()

    _kv("File",   f"{f.file}:{f.line}")
    _kv("Sink",   f.sink   or "—")
    _kv("Source", f.source or "—")

    if f.exploitable is not None:
        label = (click.style("Exploitable",  fg="red")   if f.exploitable else
                 click.style("False Positive", fg="cyan"))
        click.echo(f"  {'Verdict':<10}  {label}")
    click.echo()

    _box("Snippet",   f.snippet   or "—", dim=True)
    if f.taint_path:
        _box("Taint Path", _format_taint_path(f), dim=True)
    if f.taint_analysis:
        _box("Taint Analysis", f.taint_analysis.assessment)
    _box("Analysis",  f.analysis  or f.false_positive_reason or "—")
    _box("Explanation", f.explanation or "—")
    _box("PoC",       f.poc       or "—", fg="magenta")
    _box("Demo",      f.demo      or "—", fg="bright_black", code=True)
    _box("Exploitation Context", f.context or "—")


def _print_finding_dict(fd: dict) -> None:
    """Print a finding reconstructed from its to_dict() representation."""
    from pyhunter.models import Finding, Severity
    f = Finding(
        id=fd["id"], rule_id=fd["rule_id"],
        severity=Severity(fd["severity"]),
        file=fd["file"], line=fd["line"], snippet=fd["snippet"],
        sink=fd.get("sink"), source=fd.get("source"),
        exploitable=fd.get("exploitable"),
        false_positive_reason=fd.get("false_positive_reason"),
        analysis=fd.get("analysis"), explanation=fd.get("explanation"),
        poc=fd.get("poc"), demo=fd.get("demo"), context=fd.get("context"),
    )
    _print_finding(f)


def _print_chains(chains: List[ExploitChain]) -> None:
    if not chains:
        return
    click.echo()
    _thick_rule()
    click.secho(
        f"  EXPLOIT CHAINS — {len(chains)} chain(s) identified",
        bold=True, fg="bright_red",
    )
    _thick_rule()
    for chain in chains:
        _print_chain(chain)


def _print_chain(chain: ExploitChain) -> None:
    sev   = chain.severity.value
    color = _SEV_COLOR.get(sev, "white")

    click.echo()
    click.secho(
        f"  [{sev}]  {chain.id}  —  {chain.title}",
        fg=color, bold=True,
    )
    click.echo()

    # Step list
    click.secho("  ┌─ Attack Steps " + "─" * max(0, _W - 17), dim=True)
    for i, step in enumerate(chain.steps, 1):
        scol = _SEV_COLOR.get(step.severity.value, "white")
        click.echo(
            f"  │  {i}. "
            + click.style(f"[{step.severity.value}]", fg=scol)
            + f"  {step.rule_id:<20}"
            + click.style(f"  {step.file}:{step.line}", dim=True)
        )
    click.secho(f"  └{'─' * _W}", dim=True)
    click.echo()

    _box("Attack Narrative",  chain.narrative,     fg="bright_white")
    _box("Prerequisites",     chain.prerequisites)
    _box("Impact",            chain.impact,        fg="red")


def _print_summary(findings: List[Finding]) -> None:
    click.echo()
    _thick_rule()
    click.secho(f"  SUMMARY — {len(findings)} confirmed finding(s)", bold=True)
    _thick_rule()

    by_sev  = Counter(f.severity.value for f in findings)
    max_sev = max(by_sev.values()) if by_sev else 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = by_sev.get(sev, 0)
        if count:
            bar   = ("█" * int(count / max_sev * 24)).ljust(24)
            color = _SEV_COLOR.get(sev, "white")
            click.secho(f"  {sev:<12} {count:>4}  {bar}", fg=color)

    click.echo()
    by_rule = Counter(f.rule_id for f in findings)
    for rule_id, count in sorted(by_rule.items(), key=lambda x: -x[1]):
        click.echo(f"  {rule_id:<26} {count}")
    _rule()


# ── Visual helpers ────────────────────────────────────────────────────────────

def _banner() -> None:
    click.echo()
    click.secho("  ██████╗ ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ", fg="bright_red")
    click.secho("  ██╔══██╗╚██╗ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗", fg="bright_red")
    click.secho("  ██████╔╝ ╚████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝", fg="red")
    click.secho("  ██╔═══╝   ╚██╔╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗", fg="red")
    click.secho("  ██║        ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║", fg="bright_red")
    click.secho("  ╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝", fg="bright_red")
    click.echo()
    click.secho("  AI-powered Python vulnerability scanner", dim=True)
    _thick_rule()


def _box(label: str, content: str, dim: bool = False, fg: str = None, code: bool = False) -> None:
    if not content or content == "—":
        return
    border = "─" * _W
    click.secho(f"  ┌─ {label} {'─' * max(0, _W - len(label) - 4)}", dim=True)
    for line in content.splitlines():
        styled = click.style(f"  │  {line}", fg=fg, dim=dim)
        click.echo(styled)
    click.secho(f"  └{border}", dim=True)
    click.echo()


def _kv(key: str, value: str) -> None:
    click.echo(f"  {key:<10}  {value}")


def _rule() -> None:
    click.echo("  " + "─" * _W)


def _thick_rule() -> None:
    click.secho("  " + "═" * _W, bold=True)


def main():
    cli()


if __name__ == "__main__":
    main()
