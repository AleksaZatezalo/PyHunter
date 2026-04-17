"""CLI integration tests — exercises the Click commands without LLM calls."""

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

    def test_scan_writes_output_dir(self, runner, vuln_file, tmp_path):
        out_dir = tmp_path / "results"
        result = runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--output-dir", str(out_dir),
        ])
        assert out_dir.exists(), f"output dir not created; output:\n{result.output}"
        assert (out_dir / "report.md").exists(), "report.md not written"
        assert (out_dir / "exploit.py").exists(), "exploit.py not written"

    def test_scan_output_dir_report_contains_findings(self, runner, vuln_file, tmp_path):
        out_dir = tmp_path / "results"
        runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--output-dir", str(out_dir),
        ])
        content = (out_dir / "report.md").read_text()
        assert "os.system" in content

    def test_scan_output_dir_no_findings(self, runner, safe_file, tmp_path):
        out_dir = tmp_path / "results"
        runner.invoke(cli, [
            "scan", str(safe_file), "--no-llm",
            "--output-dir", str(out_dir),
        ])
        assert (out_dir / "report.md").exists(), "report.md must be written even with no findings"
        assert (out_dir / "exploit.py").exists(), "exploit.py must be written even with no findings"

    def test_scan_verbose_shows_snippet(self, runner, vuln_file):
        result = runner.invoke(cli, ["scan", str(vuln_file), "--no-llm", "--verbose"])
        assert "os.system" in result.output

    def test_scan_directory(self, runner, tmp_path):
        (tmp_path / "a.py").write_text(VULN_SRC)
        (tmp_path / "b.py").write_text(SAFE_SRC)
        result = runner.invoke(cli, ["scan", str(tmp_path), "--no-llm"])
        assert result.exit_code == 1
        assert "finding" in result.output

    def test_scan_no_format_option(self, runner, vuln_file):
        """--format is no longer a valid option for scan."""
        result = runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm", "--format", "json"
        ])
        assert result.exit_code != 0

    def test_scan_output_dir_short_flag(self, runner, vuln_file, tmp_path):
        """Short flag -o must also work for --output-dir."""
        out_dir = tmp_path / "results"
        runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "-o", str(out_dir),
        ])
        assert (out_dir / "report.md").exists()
        assert (out_dir / "exploit.py").exists()

    def test_target_url_accepted_as_flag(self, runner, vuln_file):
        """--target-url must be accepted without error (no LLM called with --no-llm)."""
        result = runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--target-url", "http://localhost:5000",
        ])
        # Flag accepted; --no-llm suppresses the agent loop, so a warning is shown
        assert result.exit_code in (0, 1)
        assert "Error:" not in result.output or "target-url" not in result.output

    def test_target_url_with_no_llm_shows_warning(self, runner, vuln_file):
        """--target-url with --no-llm must print a human-readable warning."""
        result = runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--target-url", "http://localhost:5000",
        ])
        assert "no effect" in result.output.lower() or "no-llm" in result.output.lower()

    def test_target_url_with_output_dir_and_no_llm(self, runner, vuln_file, tmp_path):
        """With --no-llm the output dir must still be written (placeholder exploit)."""
        out_dir = tmp_path / "results"
        runner.invoke(cli, [
            "scan", str(vuln_file), "--no-llm",
            "--output-dir", str(out_dir),
            "--target-url", "http://localhost:5000",
        ])
        assert (out_dir / "report.md").exists()
        assert (out_dir / "exploit.py").exists()
        # Placeholder script must mention re-running without --no-llm
        content = (out_dir / "exploit.py").read_text()
        assert "No confirmed" in content or "no-llm" in content.lower() or "LLM" in content


# ── Taint fields in report output ────────────────────────────────────────────

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
    def _scan_to_dir(self, runner, source_file, tmp_path) -> str:
        out_dir = tmp_path / "results"
        runner.invoke(cli, [
            "scan", str(source_file), "--no-llm",
            "--output-dir", str(out_dir),
        ])
        return (out_dir / "report.md").read_text()

    def test_report_contains_taint_flow_section(self, runner, taint_file, tmp_path):
        """The markdown report must contain a Taint Flow section for tainted findings."""
        content = self._scan_to_dir(runner, taint_file, tmp_path)
        assert "Taint Flow" in content, "report.md must include a Taint Flow section"

    def test_report_contains_taint_flow_summary(self, runner, taint_file, tmp_path):
        """The consolidated report must include the Taint Flow Summary table."""
        content = self._scan_to_dir(runner, taint_file, tmp_path)
        assert "Taint Flow Summary" in content

    def test_report_taint_path_lists_source(self, runner, taint_file, tmp_path):
        """The Taint Flow section must name the taint source."""
        content = self._scan_to_dir(runner, taint_file, tmp_path)
        assert "request.args" in content or "user input" in content

    def test_report_unsanitized_flow_marked(self, runner, taint_file, tmp_path):
        """An unguarded flow must be marked as unsanitized in the report."""
        content = self._scan_to_dir(runner, taint_file, tmp_path)
        assert "**Sanitized**: No" in content or "unguarded" in content

    def test_report_sanitized_flow_marked(self, runner, sanitized_file, tmp_path):
        """A flow through shlex.quote must be marked as sanitized in the report."""
        content = self._scan_to_dir(runner, sanitized_file, tmp_path)
        # Markdown bold: **Sanitized**: Yes — OR summary table shows 1/1 sanitized
        assert "**Sanitized**: Yes" in content or "1/1" in content

    def test_report_sanitized_flow_records_sanitizer_name(self, runner, sanitized_file, tmp_path):
        """sanitizer function name (shlex.quote) must appear in the report."""
        content = self._scan_to_dir(runner, sanitized_file, tmp_path)
        assert "shlex.quote" in content
