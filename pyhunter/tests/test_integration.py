"""Integration test: run scanner (no LLM) against the bundled vulnerable example."""

from pathlib import Path
import pytest

from pyhunter.engine import Scanner


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
