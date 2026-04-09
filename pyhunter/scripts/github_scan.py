"""
scripts/github_scan.py
~~~~~~~~~~~~~~~~~~~~~~
Mass-scan GitHub repositories for vulnerable Python code.

Usage:
    export GITHUB_TOKEN=ghp_...
    export ANTHROPIC_API_KEY=sk-ant-...

    python scripts/github_scan.py --query "eval request.args language:Python" --limit 20

Requires: pip install PyGithub
"""

from __future__ import annotations
import argparse
import json
import os
import tempfile
import subprocess
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(description="Scan GitHub repos with PyHunter.")
    p.add_argument("--query", required=True, help="GitHub code search query.")
    p.add_argument("--limit", type=int, default=10, help="Max repos to scan.")
    p.add_argument("--output", default="github_report.json", help="Output JSON path.")
    p.add_argument("--no-llm", action="store_true", help="Skip Claude enrichment.")
    return p.parse_args()


def fetch_repos(query: str, limit: int) -> list[dict]:
    """Return a list of {repo, clone_url} dicts matching the query."""
    try:
        from github import Github
    except ImportError:
        raise SystemExit("PyGithub not installed. Run: pip install PyGithub")

    token = os.environ.get("GITHUB_TOKEN")
    g = Github(token)
    results = []
    seen = set()

    for code_result in g.search_code(query):
        repo = code_result.repository
        if repo.full_name in seen:
            continue
        seen.add(repo.full_name)
        results.append({"repo": repo.full_name, "clone_url": repo.clone_url})
        if len(results) >= limit:
            break

    return results


def clone_and_scan(repo_info: dict, use_llm: bool) -> list[dict]:
    """Clone a repo to a temp dir and run PyHunter on it."""
    from pyhunter.engine import Scanner

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"  Cloning {repo_info['repo']} …")
        subprocess.run(
            ["git", "clone", "--depth=1", repo_info["clone_url"], tmpdir],
            check=True, capture_output=True,
        )
        scanner = Scanner(use_llm=use_llm)
        findings = scanner.scan(tmpdir)
        return [
            {**f.to_dict(), "github_repo": repo_info["repo"]}
            for f in findings
        ]


def main():
    args = parse_args()
    print(f"[*] Searching GitHub: {args.query}")
    repos = fetch_repos(args.query, args.limit)
    print(f"[*] Found {len(repos)} repos to scan.")

    all_findings = []
    for repo_info in repos:
        try:
            findings = clone_and_scan(repo_info, use_llm=not args.no_llm)
            all_findings.extend(findings)
            print(f"  ✓ {repo_info['repo']}: {len(findings)} finding(s)")
        except Exception as e:
            print(f"  ✗ {repo_info['repo']}: {e}")

    Path(args.output).write_text(json.dumps(all_findings, indent=2))
    print(f"\n[*] Report written to {args.output}  ({len(all_findings)} total findings)")


if __name__ == "__main__":
    main()
