"""CLI integration tests — exercises the Click commands without LLM calls."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyhunter.cli import cli


VULN_SRC = """\
import os
def run(cmd):
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
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["sink"] == "os.system"

    def test_scan_json_output_is_list_on_no_findings(self, runner, safe_file, tmp_path):
        out = tmp_path / "report.json"
        runner.invoke(cli, [
            "scan", str(safe_file), "--no-llm",
            "--output", str(out), "--format", "json",
        ])
        assert out.exists()
        data = json.loads(out.read_text())
        assert data == []

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
        assert isinstance(parsed, list), "Output must be a JSON list"
