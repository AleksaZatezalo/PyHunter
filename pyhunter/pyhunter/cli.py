"""PyHunter CLI."""

from __future__ import annotations
import json
import sys
from pathlib import Path

import click

from pyhunter.engine import Scanner
from pyhunter.engine.pypi import PyPIScanner


@click.group()
@click.version_option("0.1.0", prog_name="pyhunter")
def cli():
    """PyHunter - AI-powered Python vulnerability scanner."""
    pass


# ── pyhunter scan ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--no-llm", is_flag=True, help="Run AST rules only, skip Claude enrichment.")
@click.option("--keep-fp", is_flag=True, help="Include findings Claude marked as false positives.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write report to file.")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="text",
              show_default=True, help="Output format for --output.")
@click.option("--demo-dir", "-d", type=click.Path(), default=None,
              help="Write runnable demo scripts to this directory.")
@click.option("--verbose", "-v", is_flag=True, help="Print enriched details to stdout.")
def scan(target, no_llm, keep_fp, output, fmt, demo_dir, verbose):
    """Scan TARGET (file or directory) for vulnerabilities."""
    click.echo(f"[*] Scanning {target} ...")

    scanner = Scanner(use_llm=not no_llm, skip_false_positives=not keep_fp)
    findings = scanner.scan(target)

    if not findings:
        click.secho("[v] No findings.", fg="green")
        if output and fmt == "json":
            Path(output).write_text("[]")
        sys.exit(0)

    click.secho(f"[!] {len(findings)} finding(s).", fg="yellow")

    for f in findings:
        _print_finding(f, verbose)

    if output:
        _write_report(findings, Path(output), fmt)
        click.echo(f"[*] Report written to {output}")

    if demo_dir:
        demo_path = Path(demo_dir)
        demo_path.mkdir(parents=True, exist_ok=True)
        for f in findings:
            if f.demo:
                (demo_path / f"{f.id}.py").write_text(f.demo)
        click.echo(f"[*] Demo scripts written to {demo_dir}/")

    sys.exit(1)


# ── pyhunter pypi ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("packages", nargs=-1, required=True)
@click.option("--no-llm", is_flag=True, help="Run AST rules only, skip Claude enrichment.")
@click.option("--keep-fp", is_flag=True, help="Include findings Claude marked as false positives.")
@click.option("--output-dir", "-o", type=click.Path(), default="./pyhunter_results",
              show_default=True, help="Directory to write per-package JSON reports.")
@click.option("--keep-sources", is_flag=True, help="Preserve downloaded source trees.")
@click.option("--verbose", "-v", is_flag=True, help="Print enriched details to stdout.")
def pypi(packages, no_llm, keep_fp, output_dir, keep_sources, verbose):
    """Download PACKAGES from PyPI and scan each one.

    Example: pyhunter pypi gradio streamlit fabric
    """
    out = Path(output_dir)
    scanner_kwargs = dict(use_llm=not no_llm, skip_false_positives=not keep_fp)

    pypi_scanner = PyPIScanner(
        output_dir=out,
        keep_sources=keep_sources,
        scanner_kwargs=scanner_kwargs,
    )

    results = pypi_scanner.run(list(packages))

    click.echo("\n" + "=" * 60)
    click.secho("PYPI SCAN SUMMARY", bold=True)
    click.echo("=" * 60)
    for pkg_name, info in results.items():
        count = info.get("finding_count", "?")
        version = info.get("version", "?")
        err = info.get("error")
        if err:
            click.secho(f"  {pkg_name:<22} v{version:<12} ERROR: {err}", fg="red")
        else:
            color = "yellow" if count else "green"
            click.secho(f"  {pkg_name:<22} v{version:<12} {count} finding(s)", fg=color)
    click.echo("=" * 60)
    click.echo(f"Reports: {out}/\n")


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_report(findings, path: Path, fmt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        lines = []
        for f in findings:
            lines.append(f"[{f.severity.value}] {f.id} {f.file}:{f.line} sink={f.sink}")
            if f.explanation:
                lines.append(f"  {f.explanation}")
        path.write_text("\n".join(lines))


def _print_finding(finding, verbose: bool) -> None:
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "bright_red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "white",
    }
    color = severity_colors.get(finding.severity.value, "white")

    click.echo("")
    click.secho(f"  [{finding.severity.value}] {finding.id} -- {finding.rule_id}", fg=color, bold=True)
    click.echo(f"  File : {finding.file}:{finding.line}")
    click.echo(f"  Sink : {finding.sink}")
    if finding.snippet:
        click.secho(f"  Code : {finding.snippet[:120]}", dim=True)

    if verbose:
        if finding.explanation:
            click.echo(f"\n  Explanation:\n  {finding.explanation}")
        if finding.poc:
            click.secho(f"\n  PoC payload: {finding.poc}", fg="magenta")
        if finding.false_positive_reason:
            click.secho(f"  [FP] {finding.false_positive_reason}", fg="cyan")


def main():
    cli()


if __name__ == "__main__":
    main()
