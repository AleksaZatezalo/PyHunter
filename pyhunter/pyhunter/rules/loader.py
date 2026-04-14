"""YAML rule loader — reads definitions/*.yaml and produces BaseRule instances.

Design pattern: Factory
  _make_rule() is the single factory function: given a raw YAML definition
  dict it selects the right Matcher strategy, constructs it, and wraps it
  in a YAMLRule.  The caller (registry.py) never needs to know which Matcher
  class implements a given strategy.

Rule authoring
──────────────
  To add a new rule:
    1. Create pyhunter/rules/definitions/<name>.yaml
    2. Set ``strategy:`` to one of the six supported strategies
    3. Provide strategy-specific configuration (see matchers.py docstrings)
    4. The rule is automatically picked up by load_all_rules() — no Python
       changes are needed unless you are implementing a *new* strategy.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List

import yaml

from pyhunter.models import Finding, Severity
from pyhunter.rules import BaseRule
from pyhunter.rules.matchers import (
    AssignTrackMatcher,
    CallMatcher,
    DecoratorMatcher,
    FileScopeMatcher,
    Matcher,
    SaveHeuristicMatcher,
    TaintMatcher,
)

DEFINITIONS_DIR: Path = Path(__file__).parent / "definitions"

_STRATEGY_MAP: Dict[str, type[Matcher]] = {
    "call":           CallMatcher,
    "taint":          TaintMatcher,
    "assign_track":   AssignTrackMatcher,
    "decorator":      DecoratorMatcher,
    "file_scope":     FileScopeMatcher,
    "save_heuristic": SaveHeuristicMatcher,
}

# Strategies that need the sources vocabulary as a second constructor arg
_SOURCES_STRATEGIES: frozenset[str] = frozenset({"taint", "save_heuristic"})


def _load_sources() -> Dict[str, Any]:
    """Load the shared taint-source vocabulary from sources.yaml."""
    path = DEFINITIONS_DIR / "sources.yaml"
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_all_rules() -> List[BaseRule]:
    """Load and instantiate every YAML-defined rule in definitions/.

    Files are sorted by name so rule order is deterministic across runs.
    sources.yaml is excluded — it is vocabulary, not a rule.
    """
    sources = _load_sources()
    rules: List[BaseRule] = []
    for path in sorted(DEFINITIONS_DIR.glob("*.yaml")):
        if path.name == "sources.yaml":
            continue
        with open(path, encoding="utf-8") as fh:
            defn: Dict[str, Any] = yaml.safe_load(fh)
        rules.append(_make_rule(defn, sources))
    return rules


def _make_rule(defn: Dict[str, Any], sources: Dict[str, Any]) -> "YAMLRule":
    strategy = defn.get("strategy")
    if strategy not in _STRATEGY_MAP:
        raise ValueError(
            f"Rule {defn.get('id')!r} has unknown strategy {strategy!r}. "
            f"Known strategies: {sorted(_STRATEGY_MAP)}"
        )

    # The strategy config sits under the strategy name as a YAML mapping
    cfg = defn.get(strategy, {})
    matcher_cls = _STRATEGY_MAP[strategy]

    matcher: Matcher = (
        matcher_cls(cfg, sources)    # type: ignore[call-arg]
        if strategy in _SOURCES_STRATEGIES
        else matcher_cls(cfg)        # type: ignore[call-arg]
    )
    return YAMLRule(defn, matcher)


# ── YAMLRule ──────────────────────────────────────────────────────────────────

class YAMLRule(BaseRule):
    """A detection rule backed by a YAML definition and a strategy Matcher.

    Attributes exposed beyond BaseRule:
      phase      int   — attack phase (1 = Initial Access, 2 = Code Execution,
                         3 = Supply Chain); used by Chainer to group findings
      tags       list  — free-form labels from the YAML definition
      _severity  Severity — default severity for findings emitted by this rule;
                           matchers may override it for individual findings
    """

    def __init__(self, defn: Dict[str, Any], matcher: Matcher) -> None:
        self.rule_id:     str      = defn["id"]
        self.description: str      = defn["description"]
        self.phase:       int      = int(defn.get("phase", 0))
        self.tags:        list     = list(defn.get("tags", []))
        self._severity:   Severity = Severity(defn["severity"])
        self._matcher:    Matcher  = matcher

    def check(
        self,
        tree:         ast.AST,
        source_lines: List[str],
        filepath:     str,
    ) -> List[Finding]:
        return self._matcher.match(tree, source_lines, filepath, self)
