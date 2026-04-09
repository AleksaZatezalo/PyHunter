#!/usr/bin/env python3
"""
scan_targets.py — Download target packages from PyPI and run PyHunter against them.

Usage:
    python scan_targets.py [--output-dir ./results] [--keep-sources]

Architecture:
    TargetPackage         — represents a package to acquire and scan
    PackageAcquirer       — downloads and extracts packages from PyPI
    PyHunterRunner        — invokes the pyhunter CLI against a source tree
    ScanOrchestrator      — coordinates acquisition + scanning across all targets
    ResultsWriter         — persists scan output to disk
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, urlretrieve

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

PYPI_API = "https://pypi.org/pypi/{package}/json"

TARGETS = [
    "gradio",
    "streamlit",
    "fabric",
]


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass
class TargetPackage:
    name: str
    version: Optional[str] = None          # resolved after PyPI fetch
    source_dir: Optional[Path] = None      # set after extraction
    scan_result: Optional[dict] = None     # set after pyhunter run


@dataclass
class ScanConfig:
    output_dir: Path
    keep_sources: bool = False
    pyhunter_bin: str = "pyhunter"         # override if not on PATH


# ---------------------------------------------------------------------------
# Package acquisition
# ---------------------------------------------------------------------------

class PackageAcquirer:
    """Downloads and extracts the latest sdist for a package from PyPI."""

    def __init__(self, work_dir: Path):
        self.work_dir = work_dir

    def acquire(self, target: TargetPackage) -> Path:
        log.info(f"[{target.name}] Fetching metadata from PyPI...")
        meta = self._fetch_metadata(target.name)

        target.version = meta["info"]["version"]
        log.info(f"[{target.name}] Latest version: {target.version}")

        sdist_url, filename = self._find_sdist(meta)
        archive_path = self.work_dir / filename

        log.info(f"[{target.name}] Downloading {filename}...")
        urlretrieve(sdist_url, archive_path)

        extract_dir = self.work_dir / target.name
        extract_dir.mkdir(exist_ok=True)
        self._extract(archive_path, extract_dir)

        # PyPI sdists unpack into a single top-level directory; descend into it
        children = list(extract_dir.iterdir())
        source_root = children[0] if len(children) == 1 and children[0].is_dir() else extract_dir

        target.source_dir = source_root
        log.info(f"[{target.name}] Extracted to {source_root}")
        return source_root

    # ------------------------------------------------------------------

    def _fetch_metadata(self, package_name: str) -> dict:
        url = PYPI_API.format(package=package_name)
        with urlopen(url) as resp:
            return json.loads(resp.read())

    def _find_sdist(self, meta: dict) -> tuple[str, str]:
        """Return (url, filename) for the sdist, falling back to a wheel."""
        urls = meta["urls"]

        for entry in urls:
            if entry["packagetype"] == "sdist":
                return entry["url"], entry["filename"]

        # Fallback: grab first wheel if no sdist is available
        for entry in urls:
            if entry["filename"].endswith(".whl"):
                return entry["url"], entry["filename"]

        raise RuntimeError(f"No downloadable artifact found for {meta['info']['name']}")

    def _extract(self, archive_path: Path, dest: Path) -> None:
        name = archive_path.name
        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(dest)
        elif name.endswith(".zip") or name.endswith(".whl"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest)
        else:
            raise RuntimeError(f"Unsupported archive format: {name}")


# ---------------------------------------------------------------------------
# PyHunter runner
# ---------------------------------------------------------------------------

class PyHunterRunner:
    """Invokes the pyhunter CLI and captures structured output."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def scan(self, target: TargetPackage) -> dict:
        if target.source_dir is None:
            raise ValueError(f"source_dir not set for {target.name} — acquire first")

        out_file = self.config.output_dir / f"{target.name}.json"

        cmd = [
            self.config.pyhunter_bin,
            "scan",
            str(target.source_dir),
            "--output", str(out_file),
            "--format", "json",
        ]

        log.info(f"[{target.name}] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            log.error(
                f"pyhunter not found at '{self.config.pyhunter_bin}'. "
                "Install it with: pip install -e /path/to/pyhunter"
            )
            sys.exit(1)
        except subprocess.TimeoutExpired:
            log.warning(f"[{target.name}] Scan timed out after 300s")
            return {"error": "timeout", "package": target.name}

        if result.returncode not in (0, 1):  # pyhunter may exit 1 when findings exist
            log.warning(f"[{target.name}] pyhunter exited {result.returncode}")
            log.debug(result.stderr)

        # Read structured output if pyhunter wrote it; else capture stdout
        if out_file.exists():
            with open(out_file) as f:
                scan_result = json.load(f)
        else:
            scan_result = {"raw_output": result.stdout, "stderr": result.stderr}

        target.scan_result = scan_result
        log.info(f"[{target.name}] Scan complete — results at {out_file}")
        return scan_result


# ---------------------------------------------------------------------------
# Results writer
# ---------------------------------------------------------------------------

class ResultsWriter:
    """Writes a consolidated summary across all targets."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def write_summary(self, targets: list[TargetPackage]) -> Path:
        summary = {
            pkg.name: {
                "version": pkg.version,
                "source_dir": str(pkg.source_dir),
                "findings": pkg.scan_result,
            }
            for pkg in targets
        }

        summary_path = self.output_dir / "summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        log.info(f"Summary written to {summary_path}")
        return summary_path


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """Coordinates the full acquire → scan → report pipeline."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, package_names: list[str]) -> list[TargetPackage]:
        targets = [TargetPackage(name=name) for name in package_names]

        with tempfile.TemporaryDirectory(prefix="pyhunter_") as tmp:
            work_dir = Path(tmp)
            acquirer = PackageAcquirer(work_dir)
            runner = PyHunterRunner(self.config)
            writer = ResultsWriter(self.config.output_dir)

            for target in targets:
                try:
                    acquirer.acquire(target)
                    runner.scan(target)
                except Exception as exc:
                    log.error(f"[{target.name}] Failed: {exc}")
                    target.scan_result = {"error": str(exc)}

                if self.config.keep_sources and target.source_dir:
                    dest = self.config.output_dir / "sources" / target.name
                    shutil.copytree(target.source_dir, dest, dirs_exist_ok=True)
                    log.info(f"[{target.name}] Source preserved at {dest}")

            writer.write_summary(targets)

        return targets


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download PyPI packages and run PyHunter against them."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./pyhunter_results"),
        help="Directory for scan results (default: ./pyhunter_results)",
    )
    parser.add_argument(
        "--keep-sources",
        action="store_true",
        help="Preserve extracted source trees alongside results",
    )
    parser.add_argument(
        "--pyhunter-bin",
        default="pyhunter",
        help="Path to the pyhunter executable (default: pyhunter)",
    )
    parser.add_argument(
        "--packages",
        nargs="+",
        default=TARGETS,
        metavar="PKG",
        help=f"Packages to scan (default: {', '.join(TARGETS)})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    config = ScanConfig(
        output_dir=args.output_dir,
        keep_sources=args.keep_sources,
        pyhunter_bin=args.pyhunter_bin,
    )

    log.info(f"Targets: {', '.join(args.packages)}")
    log.info(f"Output:  {config.output_dir}")

    orchestrator = ScanOrchestrator(config)
    targets = orchestrator.run(args.packages)

    # Print a compact terminal summary
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    for t in targets:
        status = "ERROR" if (t.scan_result or {}).get("error") else "OK"
        version = t.version or "unknown"
        finding_count = len(t.scan_result) if isinstance(t.scan_result, list) else "?"
        print(f"  {t.name:<20} v{version:<12} [{status}]  findings: {finding_count}")
    print("=" * 60)
    print(f"Full results: {config.output_dir}/\n")


if __name__ == "__main__":
    main()