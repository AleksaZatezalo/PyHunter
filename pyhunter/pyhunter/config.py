"""Load optional .pyhunterrc configuration (JSON format).

PyHunter searches for a config file starting from the current directory,
walking up to the filesystem root, then falling back to ~/.pyhunterrc.

Example .pyhunterrc:
    {
        "disabled_rules": ["DUNDER-ABUSE", "RCE-BUILD"],
        "min_severity": "MEDIUM",
        "cache_enabled": true
    }
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

_FILENAMES = [".pyhunterrc", ".pyhunter.json"]

_DEFAULTS: dict[str, Any] = {
    "disabled_rules": [],
    "min_severity":   None,
    "cache_enabled":  True,
}


def load_config(start_dir: Optional[Path] = None) -> dict[str, Any]:
    """Return merged config: defaults overridden by the first config file found."""
    cfg   = dict(_DEFAULTS)
    found = _find_config(start_dir or Path.cwd())
    if found:
        try:
            with open(found) as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def _find_config(start: Path) -> Optional[Path]:
    current = start.resolve()
    for _ in range(5):
        for name in _FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    for name in _FILENAMES:
        candidate = Path.home() / name
        if candidate.is_file():
            return candidate
    return None
