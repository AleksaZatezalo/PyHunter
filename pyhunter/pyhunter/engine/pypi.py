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


@dataclass
class PackageResult:
    name:     str
    version:  Optional[str]  = None
    findings: list[Finding]  = field(default_factory=list)
    error:    Optional[str]  = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "package":       self.name,
            "version":       self.version,
            "finding_count": self.finding_count,
            "findings":      [f.to_dict() for f in self.findings],
            "error":         self.error,
        }


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
            for name in packages:
                result        = self._scan_package(name, Path(tmp))
                results[name] = result.to_dict()
                self._write_findings(result)
        self._write_summary(list(results.values()))
        return results

    # ── Private ───────────────────────────────────────────────────────────────

    def _scan_package(self, name: str, work_dir: Path) -> PackageResult:
        result = PackageResult(name=name)
        try:
            meta           = self._fetch_meta(name)
            result.version = meta["info"]["version"]

            if self.on_package_start:
                self.on_package_start(name, result.version, self.scanner)

            source_dir     = self._download(name, meta, work_dir)
            result.findings = self.scanner.scan(str(source_dir))

            if self.keep_sources:
                dest = self.output_dir / "sources" / name
                shutil.copytree(source_dir, dest, dirs_exist_ok=True)
        except Exception as exc:
            log.error(f"[{name}] {exc}")
            result.error = str(exc)
        return result

    def _fetch_meta(self, name: str) -> dict:
        with urlopen(_PYPI_API.format(package=name), timeout=30) as r:
            return json.loads(r.read())

    def _download(self, name: str, meta: dict, work_dir: Path) -> Path:
        url, filename = self._best_artifact(meta)
        archive = work_dir / filename
        urlretrieve(url, archive)

        dest = work_dir / name
        dest.mkdir()
        self._extract(archive, dest)

        children = list(dest.iterdir())
        return children[0] if len(children) == 1 and children[0].is_dir() else dest

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

    def _write_findings(self, result: PackageResult) -> None:
        if result.error or not result.findings:
            return
        pkg_dir = self.output_dir / result.name
        pkg_dir.mkdir(parents=True, exist_ok=True)
        for finding in result.findings:
            (pkg_dir / f"{finding.id}.md").write_text(finding.to_markdown())

    def _write_summary(self, results: list[dict]) -> None:
        out = self.output_dir / "summary.json"
        out.write_text(json.dumps(results, indent=2))
