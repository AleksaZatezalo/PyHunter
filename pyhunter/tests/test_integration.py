"""Integration tests: scanner pipeline (no LLM) including taint-merge behaviour."""

from pathlib import Path
import pytest

from pyhunter.engine import Scanner
from pyhunter.taint.types import TaintPath


EXAMPLE = Path(__file__).parent.parent / "examples" / "vulnerable_app.py"


@pytest.mark.skipif(not EXAMPLE.exists(), reason="example file not present")
def test_scanner_finds_known_vulns():
    scanner = Scanner(use_llm=False)
    findings = scanner.scan(str(EXAMPLE))

    sinks_found = {f.sink for f in findings}

    # Must catch the obvious sinks in vulnerable_app.py
    assert "eval" in sinks_found, "eval not detected"
    assert "os.system" in sinks_found, "os.system not detected"
    assert "pickle.loads" in sinks_found, "pickle.loads not detected"

    # Every finding must have a non-empty snippet
    for f in findings:
        assert f.snippet, f"Empty snippet on finding {f.id}"


def test_scanner_clean_file(tmp_path):
    """A file with no dangerous patterns should produce zero findings."""
    safe = tmp_path / "safe.py"
    safe.write_text("x = int(input())\nprint(x + 1)\n")

    scanner = Scanner(use_llm=False)
    findings = scanner.scan(str(safe))
    assert findings == []


# ── Taint-merge integration ───────────────────────────────────────────────────

# A file where the taint engine can produce a concrete source→variable→sink path.
_TAINT_SRC = """\
import os
from flask import request
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""

# Same pattern but with shlex.quote applied before the sink.
_SANITIZED_SRC = """\
import os, shlex
from flask import request
def run():
    raw = request.args.get("cmd")
    safe = shlex.quote(raw)
    os.system(safe)
"""


class TestScannerTaintMerge:
    """Verify that _merge_taint() propagates TaintFlow data into Finding fields."""

    def test_taint_path_populated_on_finding(self, tmp_path):
        """Findings whose sink matches a TaintFlow must have taint_path set."""
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        scanner = Scanner(use_llm=False)
        findings = scanner.scan(str(f))

        taint_findings = [x for x in findings if x.taint_path is not None]
        assert taint_findings, "expected at least one finding with taint_path populated"

    def test_taint_path_is_taint_path_object(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        path = tainted[0].taint_path
        assert isinstance(path, TaintPath)
        assert len(path.steps) >= 2

    def test_taint_path_steps_have_required_fields(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        for step in tainted[0].taint_path.steps:
            assert step.location.line > 0, "step missing valid line"
            assert step.variable,          "step missing variable"
            assert step.description,       "step missing description"
            assert step.kind is not None,  "step missing kind"

    def test_taint_path_step_lines_are_positive_integers(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        for step in tainted[0].taint_path.steps:
            assert isinstance(step.location.line, int) and step.location.line > 0

    def test_source_populated_alongside_taint_path(self, tmp_path):
        """_merge_taint populates both Finding.source and Finding.taint_path."""
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        assert tainted[0].source is not None, "source must be set when taint_path is set"

    def test_unsanitized_finding_has_sanitized_false_or_none(self, tmp_path):
        """For an unguarded flow, sanitized must be False or None — never True."""
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        for finding in tainted:
            assert finding.sanitized is not True, (
                f"{finding.id} is incorrectly marked sanitized"
            )

    def test_sanitized_finding_has_sanitized_true(self, tmp_path):
        """A flow through shlex.quote must result in finding.sanitized == True."""
        f = tmp_path / "app.py"
        f.write_text(_SANITIZED_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted, "expected a taint-path finding for the sanitized source"
        sanitized = [x for x in tainted if x.sanitized is True]
        assert sanitized, "expected at least one finding with sanitized=True"

    def test_sanitizer_name_populated_on_finding(self, tmp_path):
        """finding.sanitizer must be the name of the sanitizer function."""
        f = tmp_path / "app.py"
        f.write_text(_SANITIZED_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        sanitized = [x for x in findings if x.sanitized is True]
        assert sanitized
        assert sanitized[0].sanitizer == "shlex.quote"

    def test_clean_file_has_no_taint_paths(self, tmp_path):
        """A file with no user-input sources must produce findings with taint_path=None."""
        clean = tmp_path / "clean.py"
        clean.write_text("import os\ndef run():\n    os.system('ls')\n")
        findings = Scanner(use_llm=False).scan(str(clean))
        for finding in findings:
            assert finding.taint_path is None, (
                f"{finding.id} has unexpected taint_path on a clean source"
            )

    def test_taint_path_first_step_is_source_assignment(self, tmp_path):
        """The first path step must represent the assignment from the taint source."""
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        first = tainted[0].taint_path.steps[0]
        assert "assigned from" in first.description or "propagated" in first.description

    def test_taint_path_last_step_reaches_sink(self, tmp_path):
        """The last path step must describe reaching the sink function."""
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        tainted = [x for x in findings if x.taint_path]
        assert tainted
        last = tainted[0].taint_path.steps[-1]
        assert "reaches sink" in last.description

    def test_taint_analysis_is_none_without_llm(self, tmp_path):
        """Without LLM enrichment the taint_analysis field must be None."""
        f = tmp_path / "app.py"
        f.write_text(_TAINT_SRC)
        findings = Scanner(use_llm=False).scan(str(f))

        for finding in findings:
            assert finding.taint_analysis is None, (
                "taint_analysis should only be populated by the LLM taint skill"
            )
