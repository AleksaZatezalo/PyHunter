"""CLI integration tests — exercises the Click commands without LLM calls."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyhunter.cli import cli


VULN_SRC = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""

SAFE_SRC = "x = 1 + 1\n"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vuln_file(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text(VULN_SRC)
    return f


@pytest.fixture
def safe_file(tmp_path):
    f = tmp_path / "safe.py"
    f.write_text(SAFE_SRC)
    return f


# ── pyhunter scan ─────────────────────────────────────────────────────────────

class TestScanCommand:
    def test_scan_vulnerable_exits_1(self, runner, vuln_file):
        result = runner.invoke(cli, ["scan", str(vuln_file), "--no-llm"])
        assert result.exit_code == 1

    def test_scan_clean_exits_0(self, runner, safe_file):
        result = runner.invoke(cli, ["scan", str(safe_file), "--no-llm"])
        assert result.exit_code == 0

    def test_scan_writes_json_output(self, runner, vuln_file, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        assert out.exists(), f"report not written; output:\n{result.output}"
        data = json.loads(out.read_text())
        assert "findings" in data and "chains" in data
        assert len(data["findings"]) >= 1
        assert data["findings"][0]["sink"] == "os.system"

    def test_scan_json_output_is_list_on_no_findings(self, runner, safe_file, tmp_path):
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(safe_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        assert out.exists()
        data = json.loads(out.read_text())
        assert data == {"findings": [], "chains": []}

    def test_scan_writes_text_output(self, runner, vuln_file, tmp_path):
        out = tmp_path / "report.txt"
        runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--output", str(out), "--format", "text",
        ])
        assert out.exists()
        assert "os.system" in out.read_text()

    def test_scan_verbose_shows_snippet(self, runner, vuln_file):
        result = runner.invoke(cli, ["scan", str(vuln_file), "--no-llm", "--verbose"])
        assert "os.system" in result.output

    def test_scan_directory(self, runner, tmp_path):
        (tmp_path / "a.py").write_text(VULN_SRC)
        (tmp_path / "b.py").write_text(SAFE_SRC)
        result = runner.invoke(cli, ["scan", str(tmp_path), "--no-llm"])
        assert result.exit_code == 1
        assert "finding" in result.output

    def test_scan_format_flag_required_value(self, runner, vuln_file):
        """--format only accepts 'json' or 'text'."""
        result = runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm", "--format", "xml"
        ])
        assert result.exit_code != 0

    def test_scan_compatible_with_scan_targets_invocation(self, runner, vuln_file, tmp_path):
        """
        Reproduce the exact subprocess.run() call from scan_targets.py:
            pyhunter scan <source_dir> --output <out_file> --format json
        Exit codes 0 and 1 are both acceptable (0=no findings, 1=findings).
        The output file must be a parseable JSON list.
        """
        out_file = tmp_path / "testpkg.json"
        result = runner.invoke(cli, [
            "scan", str(vuln_file),
            "--output", str(out_file),
            "--format", "json",
            "--no-llm",
        ])
        assert result.exit_code in (0, 1), (
            f"Unexpected exit code {result.exit_code}:\n{result.output}"
        )
        assert out_file.exists(), "Output file was not written"
        parsed = json.loads(out_file.read_text())
        assert "findings" in parsed and "chains" in parsed, (
            "Output must be a JSON object with 'findings' and 'chains' keys"
        )


# ── Taint fields in structured output ────────────────────────────────────────

# A snippet where the taint engine can record a source→sink path:
# request.args → cmd → os.system
_TAINT_SRC = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""

# A snippet where shlex.quote is applied before the sink so sanitized=True
_SANITIZED_SRC = """\
import os, shlex
from flask import request
def run():
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    os.system(safe)
"""


@pytest.fixture
def taint_file(tmp_path):
    f = tmp_path / "taint_app.py"
    f.write_text(_TAINT_SRC)
    return f


@pytest.fixture
def sanitized_file(tmp_path):
    f = tmp_path / "sanitized_app.py"
    f.write_text(_SANITIZED_SRC)
    return f


class TestTaintFieldsInOutput:
    def test_json_output_contains_taint_path_key(self, runner, taint_file, tmp_path):
        """Every finding in JSON output must have a taint_path key."""
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        data = json.loads(out.read_text())
        assert data["findings"], "expected at least one finding"
        for finding in data["findings"]:
            assert "taint_path" in finding, (
                f"finding {finding['id']} is missing taint_path key"
            )

    def test_json_taint_path_is_list_of_steps_for_taint_flow(self, runner, taint_file, tmp_path):
        """When a taint path exists it must be a non-empty list of step dicts."""
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        data = json.loads(out.read_text())
        taint_findings = [f for f in data["findings"] if f.get("taint_path")]
        assert taint_findings, "expected at least one finding with a non-null taint_path"
        path = taint_findings[0]["taint_path"]
        assert isinstance(path, list)
        assert len(path) >= 2
        for step in path:
            assert "line" in step
            assert "variable" in step
            assert "description" in step

    def test_json_taint_path_step_line_numbers_are_integers(self, runner, taint_file, tmp_path):
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        data = json.loads(out.read_text())
        taint_findings = [f for f in data["findings"] if f.get("taint_path")]
        assert taint_findings
        for step in taint_findings[0]["taint_path"]:
            assert isinstance(step["line"], int), "step line must be an integer"

    def test_json_unsanitized_flow_has_sanitized_false(self, runner, taint_file, tmp_path):
        """An unguarded flow must be serialised with sanitized=False (or null, not True)."""
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        data = json.loads(out.read_text())
        taint_findings = [f for f in data["findings"] if f.get("taint_path")]
        assert taint_findings
        for f in taint_findings:
            assert f.get("sanitized") is not True, (
                "unguarded flow must not be marked sanitized"
            )

    def test_json_sanitized_flow_has_sanitized_true(self, runner, sanitized_file, tmp_path):
        """A flow through shlex.quote must be serialised with sanitized=True."""
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(sanitized_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        data = json.loads(out.read_text())
        taint_findings = [f for f in data["findings"] if f.get("taint_path")]
        assert taint_findings, "expected a taint-tracked finding for the sanitized source"
        sanitized = [f for f in taint_findings if f.get("sanitized") is True]
        assert sanitized, "expected at least one finding with sanitized=True"

    def test_json_sanitized_flow_records_sanitizer_name(self, runner, sanitized_file, tmp_path):
        """sanitizer field must be the function name used (shlex.quote)."""
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(sanitized_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        data = json.loads(out.read_text())
        sanitized = [
            f for f in data["findings"]
            if f.get("sanitized") is True
        ]
        assert sanitized
        assert sanitized[0]["sanitizer"] == "shlex.quote"

    def test_markdown_report_contains_taint_flow_section(self, runner, taint_file, tmp_path):
        """The markdown report must contain a Taint Flow section for tainted findings."""
        out = tmp_path / "report.md"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "markdown",
        ])
        assert out.exists()
        content = out.read_text()
        assert "Taint Flow" in content, "markdown report must include a Taint Flow section"

    def test_markdown_report_contains_taint_flow_summary(self, runner, taint_file, tmp_path):
        """The consolidated report must include the Taint Flow Summary table."""
        out = tmp_path / "report.md"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "markdown",
        ])
        content = out.read_text()
        assert "Taint Flow Summary" in content

    def test_markdown_taint_path_lists_source(self, runner, taint_file, tmp_path):
        """The Taint Flow section must name the taint source."""
        out = tmp_path / "report.md"
        runner.invoke(cli, [
            "scan", str(taint_file), "--no-llm",
            "--output", str(out), "--format", "markdown",
        ])
        content = out.read_text()
        # The source (request.args) should appear somewhere in the taint sections
        assert "request.args" in content or "user input" in content
