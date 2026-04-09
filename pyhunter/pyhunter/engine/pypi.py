"""PyPI integration: download a package, extract it, scan it, write findings."""
from __future__ import annotations

import json
import logging
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.request import urlopen, urlretrieve

from pyhunter.engine.scanner import Scanner
from pyhunter.models import Finding

log = logging.getLogger(__name__)

_PYPI_API = "https://pypi.org/pypi/{package}/json"

# Simple type alias for package names passed to the scanner.
PackageTarget = str


class PackageAcquirer:
    """Downloads and extracts packages from PyPI."""

    def __init__(self, work_dir: Path):
        self.work_dir = work_dir

    def _fetch_metadata(self, name: str) -> dict:
        with urlopen(_PYPI_API.format(package=name), timeout=30) as r:
            return json.loads(r.read())

    def _best_artifact(self, meta: dict) -> tuple[str, str]:
        for entry in meta["urls"]:
            if entry["packagetype"] == "sdist":
                return entry["url"], entry["filename"]
        for entry in meta["urls"]:
            if entry["filename"].endswith(".whl"):
                return entry["url"], entry["filename"]
        raise RuntimeError(f"No downloadable artifact for {meta['info']['name']}")

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

    def download(self, name: str, meta: dict) -> Path:
        url, filename = self._best_artifact(meta)
        archive = self.work_dir / filename
        urlretrieve(url, archive)
        dest = self.work_dir / name
        dest.mkdir(exist_ok=True)
        self._extract(archive, dest)
        children = list(dest.iterdir())
        return children[0] if len(children) == 1 and children[0].is_dir() else dest


@dataclass
class ScanSummary:
    package:       str
    version:       Optional[str]  = None
    findings:      list           = field(default_factory=list)
    error:         Optional[str]  = None
    # When set explicitly (e.g. in tests), overrides len(findings).
    finding_count: Optional[int]  = None

    def to_dict(self) -> dict:
        count = self.finding_count if self.finding_count is not None else len(self.findings)
        return {
            "package":       self.package,
            "version":       self.version,
            "finding_count": count,
            "findings":      [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "error":         self.error,
        }


# Backward-compatible alias
PackageResult = ScanSummary


class PyPIScanner:
    """Download PyPI packages, scan them, and write per-finding markdown reports."""

    def __init__(
        self,
        output_dir:       Path,
        keep_sources:     bool                                        = False,
        scanner_kwargs:   Optional[dict[str, Any]]                   = None,
        on_package_start: Optional[Callable[[str, str, Scanner], None]] = None,
    ):
        self.output_dir       = Path(output_dir)
        self.keep_sources     = keep_sources
        self.scanner          = Scanner(**(scanner_kwargs or {}))
        self.on_package_start = on_package_start
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, packages: list[str]) -> dict[str, dict]:
        results = {}
        with tempfile.TemporaryDirectory(prefix="pyhunter_") as tmp:
            acquirer = PackageAcquirer(Path(tmp))
            for name in packages:
                result        = self._scan_package(name, acquirer)
                results[name] = result.to_dict()
                self._write_package_json(result)
                self._write_findings(result)
        self._write_summary(list(results.values()))
        return results

    # ── Private ───────────────────────────────────────────────────────────────

    def _scan_package(self, name: str, acquirer: PackageAcquirer) -> ScanSummary:
        result = ScanSummary(package=name)
        try:
            meta           = acquirer._fetch_metadata(name)
            result.version = meta["info"]["version"]

            if self.on_package_start:
                self.on_package_start(name, result.version, self.scanner)

            source_dir      = acquirer.download(name, meta)
            result.findings = self.scanner.scan(str(source_dir))

            if self.keep_sources:
                dest = self.output_dir / "sources" / name
                shutil.copytree(source_dir, dest, dirs_exist_ok=True)
        except Exception as exc:
            log.error(f"[{name}] {exc}")
            result.error = str(exc)
        return result

    def _write_package_json(self, result: ScanSummary) -> None:
        out = self.output_dir / f"{result.package}.json"
        out.write_text(json.dumps(result.to_dict(), indent=2))

    def _write_findings(self, result: ScanSummary) -> None:
        if result.error or not result.findings:
            return
        pkg_dir = self.output_dir / result.package
        pkg_dir.mkdir(parents=True, exist_ok=True)
        for finding in result.findings:
            (pkg_dir / f"{finding.id}.md").write_text(finding.to_markdown())

    def _write_summary(self, results: list[dict]) -> None:
        out = self.output_dir / "summary.json"
        out.write_text(json.dumps(results, indent=2))
