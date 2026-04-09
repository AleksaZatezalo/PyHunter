"""
pyhunter/engine/pypi.py
~~~~~~~~~~~~~~~~~~~~~~~
PyPI-aware scanner: fetches packages from PyPI, extracts them, and runs
the full PyHunter pipeline against the source tree.

Public surface:
    PyPIScanner.run(package_names) -> dict[name, ScanSummary]

Architecture:
    PyPIScanner
        └── PackageAcquirer   (download + extract from PyPI)
        └── Scanner           (existing AST + skills pipeline)
        └── ResultsWriter     (persist per-package JSON reports)
"""

from __future__ import annotations

import json
import logging
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.request import urlopen, urlretrieve

from pyhunter.engine.scanner import Scanner
from pyhunter.models import Finding

log = logging.getLogger(__name__)

PYPI_API = "https://pypi.org/pypi/{package}/json"


# ── Domain types ──────────────────────────────────────────────────────────────

@dataclass
class PackageTarget:
    """Represents one PyPI package moving through the acquire → scan pipeline."""
    name: str
    version: Optional[str] = None
    source_dir: Optional[Path] = None
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class ScanSummary:
    """Serialisable result for one package."""
    package: str
    version: Optional[str]
    finding_count: int
    findings: list[dict]
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "finding_count": self.finding_count,
            "findings": self.findings,
            "error": self.error,
        }


# ── Package acquisition ───────────────────────────────────────────────────────

class PackageAcquirer:
    """
    Downloads and extracts the latest sdist (or wheel fallback) for a
    package from PyPI into a caller-supplied work directory.
    """

    def __init__(self, work_dir: Path):
        self.work_dir = work_dir

    def acquire(self, target: PackageTarget) -> Path:
        log.info(f"[{target.name}] Fetching PyPI metadata …")
        meta = self._fetch_metadata(target.name)
        target.version = meta["info"]["version"]

        sdist_url, filename = self._best_artifact(meta)
        archive_path = self.work_dir / filename

        log.info(f"[{target.name}] Downloading {filename} …")
        urlretrieve(sdist_url, archive_path)

        extract_dir = self.work_dir / target.name
        extract_dir.mkdir(exist_ok=True)
        self._extract(archive_path, extract_dir)

        # sdists unpack into a single versioned top-level dir; descend into it
        children = [c for c in extract_dir.iterdir()]
        source_root = (
            children[0]
            if len(children) == 1 and children[0].is_dir()
            else extract_dir
        )

        target.source_dir = source_root
        log.info(f"[{target.name}] v{target.version} extracted to {source_root}")
        return source_root

    # ── private ───────────────────────────────────────────────────────────────

    def _fetch_metadata(self, package_name: str) -> dict:
        url = PYPI_API.format(package=package_name)
        with urlopen(url, timeout=30) as resp:
            return json.loads(resp.read())

    def _best_artifact(self, meta: dict) -> tuple[str, str]:
        """Prefer sdist; fall back to first wheel."""
        urls: list[dict] = meta["urls"]
        for entry in urls:
            if entry["packagetype"] == "sdist":
                return entry["url"], entry["filename"]
        for entry in urls:
            if entry["filename"].endswith(".whl"):
                return entry["url"], entry["filename"]
        raise RuntimeError(
            f"No downloadable artifact for {meta['info']['name']} {meta['info']['version']}"
        )

    def _extract(self, archive: Path, dest: Path) -> None:
        name = archive.name
        if name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(dest)
        elif name.endswith((".zip", ".whl")):
            with zipfile.ZipFile(archive, "r") as zf:
                zf.extractall(dest)
        else:
            raise RuntimeError(f"Unsupported archive format: {name}")


# ── Results writer ────────────────────────────────────────────────────────────

class ResultsWriter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, summary: ScanSummary) -> Path:
        out = self.output_dir / f"{summary.package}.json"
        out.write_text(json.dumps(summary.to_dict(), indent=2))
        log.info(f"[{summary.package}] Report → {out}")
        return out

    def write_aggregate(self, summaries: list[ScanSummary]) -> Path:
        out = self.output_dir / "summary.json"
        out.write_text(json.dumps([s.to_dict() for s in summaries], indent=2))
        log.info(f"Aggregate summary → {out}")
        return out


# ── Orchestrator ──────────────────────────────────────────────────────────────

class PyPIScanner:
    """
    Top-level coordinator for scanning PyPI packages.

    Usage:
        scanner = PyPIScanner(output_dir=Path("results"), scanner_kwargs={"use_llm": False})
        results = scanner.run(["gradio", "streamlit", "fabric"])
        # results is dict[package_name, dict] matching ScanSummary.to_dict()
    """

    def __init__(
        self,
        output_dir: Path,
        keep_sources: bool = False,
        scanner_kwargs: Optional[dict[str, Any]] = None,
    ):
        self.output_dir = Path(output_dir)
        self.keep_sources = keep_sources
        self.scanner_kwargs = scanner_kwargs or {}

    def run(self, package_names: list[str]) -> dict[str, dict]:
        """
        Acquire and scan each package. Returns a dict keyed by package name
        whose values are ScanSummary.to_dict() — directly usable by
        scan_targets.py and the CLI.
        """
        summaries: list[ScanSummary] = []
        results: dict[str, dict] = {}

        with tempfile.TemporaryDirectory(prefix="pyhunter_pypi_") as tmp:
            work_dir = Path(tmp)
            acquirer = PackageAcquirer(work_dir)
            writer = ResultsWriter(self.output_dir)
            scanner = Scanner(**self.scanner_kwargs)

            for name in package_names:
                summary = self._process(name, acquirer, scanner, writer, work_dir)
                summaries.append(summary)
                results[name] = summary.to_dict()

            writer.write_aggregate(summaries)

        return results

    # ── private ───────────────────────────────────────────────────────────────

    def _process(
        self,
        name: str,
        acquirer: PackageAcquirer,
        scanner: Scanner,
        writer: ResultsWriter,
        work_dir: Path,
    ) -> ScanSummary:
        target = PackageTarget(name=name)
        try:
            acquirer.acquire(target)
            assert target.source_dir is not None

            log.info(f"[{name}] Scanning …")
            target.findings = scanner.scan(str(target.source_dir))

            if self.keep_sources:
                dest = self.output_dir / "sources" / name
                shutil.copytree(target.source_dir, dest, dirs_exist_ok=True)
                log.info(f"[{name}] Source preserved at {dest}")

            summary = ScanSummary(
                package=name,
                version=target.version,
                finding_count=len(target.findings),
                findings=[f.to_dict() for f in target.findings],
            )
        except Exception as exc:
            log.error(f"[{name}] Failed: {exc}")
            summary = ScanSummary(
                package=name,
                version=target.version,
                finding_count=0,
                findings=[],
                error=str(exc),
            )

        writer.write(summary)
        return summary
