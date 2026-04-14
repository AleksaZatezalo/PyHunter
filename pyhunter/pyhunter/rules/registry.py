"""Rule registry — single entry point for all detection rules.

Design pattern: Registry (creational)
  all_rules() is the sole registration point queried by the Scanner at
  startup.  All rule definitions live in rules/definitions/*.yaml — adding
  a new rule requires only a new YAML file, no Python changes.

Attack phases (defined per-rule in YAML):
  1  Initial Access   FLOW-WEB, CMD-INJECT, DESER-RCE, FILE-UPLOAD, PICKLE-NET
  2  Code Execution   RCE-EVAL, EXEC-DECORATOR
  3  Supply Chain     RCE-BUILD, RCE-IMPORT
"""
from __future__ import annotations

from pyhunter.rules.loader import load_all_rules


def all_rules():
    """Return one fresh instance of every YAML-defined detection rule."""
    return load_all_rules()
