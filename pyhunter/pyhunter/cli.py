"""PyHunter CLI."""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import List, Optional

import click

from pyhunter.engine import Scanner
from pyhunter.engine.pypi import PyPIScanner
from pyhunter.models import Finding

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
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write output here (file for --format json/text, dir for markdown).")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default=None,
              help="Output format: json (machine-readable) or text (plain).")
@click.option("--verbose", is_flag=True, help="Show snippet in enrichment progress.")
def scan(target, no_llm, keep_fp, output, fmt, verbose):
    """Scan TARGET (file or directory) for vulnerabilities."""
    _banner()
    _kv("Target", target)
    _kv("Mode",   "AST only" if no_llm else "AST + Claude enrichment")
    _rule()

    scanner  = Scanner(use_llm=not no_llm, skip_false_positives=not keep_fp)
    findings = _run_scan(scanner, target, use_llm=not no_llm)
    _print_results(findings, output, fmt=fmt)


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

def _print_results(findings: List[Finding], output: Optional[str], fmt: Optional[str] = None) -> None:
    # Write structured output first — always write even when findings list is empty.
    if output and fmt:
        _write_structured_output(findings, output, fmt)

    if not findings:
        click.echo()
        click.secho("  No confirmed findings.", fg="green")
        click.echo("  Tip: re-run with --keep-fp to include false positives.")
        click.echo()
        sys.exit(0)

    for f in findings:
        _print_finding(f)

    _print_summary(findings)

    if output and not fmt:
        out = Path(output)
        out.mkdir(parents=True, exist_ok=True)
        for f in findings:
            (out / f"{f.id}.md").write_text(f.to_markdown())
        click.echo(f"  Reports written → {output}/")
        click.echo()

    sys.exit(1)


def _write_structured_output(findings: List[Finding], output: str, fmt: str) -> None:
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        out.write_text(json.dumps([f.to_dict() for f in findings], indent=2))
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
        out.write_text("\n".join(lines))
        click.echo(f"  Text report written → {output}")


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
