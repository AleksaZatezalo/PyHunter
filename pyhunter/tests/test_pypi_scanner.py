"""Unit tests for the PyPIScanner and PackageAcquirer (no network, no LLM)."""

import json
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyhunter.engine.pypi import PackageAcquirer, PyPIScanner, PackageTarget, ScanSummary


# ── PackageAcquirer ───────────────────────────────────────────────────────────

class TestPackageAcquirer:
    def _make_sdist(self, tmp_path: Path, pkg: str, version: str) -> Path:
        """Create a minimal fake sdist tarball with one vulnerable Python file."""
        inner = tmp_path / f"{pkg}-{version}"
        inner.mkdir()
        (inner / "vuln.py").write_text("eval(user_input)\n")
        archive = tmp_path / f"{pkg}-{version}.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(inner, arcname=inner.name)
        return archive

    def test_extract_descends_into_top_level_dir(self, tmp_path):
        """After extraction the acquirer should resolve the inner versioned dir."""
        archive = self._make_sdist(tmp_path, "mylib", "1.0")
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        acquirer = PackageAcquirer(tmp_path)
        acquirer._extract(archive, extract_dir)

        children = list(extract_dir.iterdir())
        assert len(children) == 1
        assert children[0].is_dir()

    def test_best_artifact_prefers_sdist(self):
        meta = {
            "info": {"name": "mylib", "version": "1.0"},
            "urls": [
                {"packagetype": "bdist_wheel", "filename": "mylib-1.0-py3-none-any.whl",
                 "url": "https://example.com/mylib-1.0.whl"},
                {"packagetype": "sdist", "filename": "mylib-1.0.tar.gz",
                 "url": "https://example.com/mylib-1.0.tar.gz"},
            ],
        }
        acquirer = PackageAcquirer(Path("/tmp"))
        url, filename = acquirer._best_artifact(meta)
        assert filename.endswith(".tar.gz")

    def test_best_artifact_falls_back_to_wheel(self):
        meta = {
            "info": {"name": "mylib", "version": "1.0"},
            "urls": [
                {"packagetype": "bdist_wheel", "filename": "mylib-1.0-py3-none-any.whl",
                 "url": "https://example.com/mylib-1.0.whl"},
            ],
        }
        acquirer = PackageAcquirer(Path("/tmp"))
        url, filename = acquirer._best_artifact(meta)
        assert filename.endswith(".whl")

    def test_no_artifact_raises(self):
        meta = {"info": {"name": "mylib", "version": "1.0"}, "urls": []}
        acquirer = PackageAcquirer(Path("/tmp"))
        with pytest.raises(RuntimeError, match="No downloadable artifact"):
            acquirer._best_artifact(meta)


# ── ScanSummary serialisation ─────────────────────────────────────────────────

class TestScanSummary:
    def test_to_dict_round_trips(self):
        s = ScanSummary(
            package="mylib",
            version="1.0",
            finding_count=2,
            findings=[{"id": "PY-RCE-001"}],
        )
        d = s.to_dict()
        assert d["package"] == "mylib"
        assert d["finding_count"] == 2
        assert d["error"] is None

    def test_error_summary(self):
        s = ScanSummary(package="bad", version=None, finding_count=0, findings=[], error="timeout")
        assert s.to_dict()["error"] == "timeout"


# ── PyPIScanner integration (mocked network + scanner) ───────────────────────

class TestPyPIScannerMocked:
    def _fake_sdist(self, tmp_path: Path, pkg: str) -> Path:
        inner = tmp_path / f"{pkg}-1.0"
        inner.mkdir()
        (inner / "vuln.py").write_text("eval(user_input)\n")
        archive = tmp_path / f"{pkg}-1.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(inner, arcname=inner.name)
        return archive

    def test_run_returns_dict_keyed_by_package(self, tmp_path):
        out_dir = tmp_path / "results"

        with tempfile.TemporaryDirectory() as work:
            work_path = Path(work)
            archive = self._fake_sdist(work_path, "testpkg")

            fake_meta = {
                "info": {"name": "testpkg", "version": "1.0"},
                "urls": [{"packagetype": "sdist", "filename": archive.name,
                           "url": f"file://{archive}"}],
            }

            with patch("pyhunter.engine.pypi.PackageAcquirer._fetch_metadata", return_value=fake_meta), \
                 patch("pyhunter.engine.pypi.urlretrieve", side_effect=lambda url, dest: Path(dest).write_bytes(archive.read_bytes())), \
                 patch("pyhunter.engine.pypi.Scanner.scan", return_value=[]):

                scanner = PyPIScanner(output_dir=out_dir, scanner_kwargs={"use_llm": False})
                results = scanner.run(["testpkg"])

        assert "testpkg" in results
        assert results["testpkg"]["version"] == "1.0"
        assert isinstance(results["testpkg"]["findings"], list)

    def test_run_handles_acquisition_error_gracefully(self, tmp_path):
        out_dir = tmp_path / "results"

        with patch("pyhunter.engine.pypi.PackageAcquirer._fetch_metadata",
                   side_effect=RuntimeError("network error")):
            scanner = PyPIScanner(output_dir=out_dir, scanner_kwargs={"use_llm": False})
            results = scanner.run(["badpkg"])

        assert "badpkg" in results
        assert results["badpkg"]["error"] is not None

    def test_json_report_written_per_package(self, tmp_path):
        out_dir = tmp_path / "results"
        archive = self._fake_sdist(tmp_path, "mypkg")
        fake_meta = {
            "info": {"name": "mypkg", "version": "2.0"},
            "urls": [{"packagetype": "sdist", "filename": archive.name,
                       "url": f"file://{archive}"}],
        }

        with patch("pyhunter.engine.pypi.PackageAcquirer._fetch_metadata", return_value=fake_meta), \
             patch("pyhunter.engine.pypi.urlretrieve", side_effect=lambda url, dest: Path(dest).write_bytes(archive.read_bytes())), \
             patch("pyhunter.engine.pypi.Scanner.scan", return_value=[]):

            scanner = PyPIScanner(output_dir=out_dir, scanner_kwargs={"use_llm": False})
            scanner.run(["mypkg"])

        report = out_dir / "mypkg.json"
        assert report.exists()
        data = json.loads(report.read_text())
        assert data["package"] == "mypkg"
        assert data["version"] == "2.0"
