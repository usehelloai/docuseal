#!/usr/bin/env python3
"""Stage-4 PR reviewer: run the active family's two PR-reviewer models on a PR diff and post a review.

Self-contained: reads ONLY config/pr_reviewers.yml (not the EOS lanes). Each reviewer calls its
OpenAI-compatible endpoint; findings from both are posted as one PR comment. Switch the family with
the `active:` line in config/pr_reviewers.yml.

Usage:
  pr_review.py --repo owner/name --pr 123            # review + post
  pr_review.py --repo owner/name --pr 123 --dry-run  # print, do not post
  pr_review.py --diff-file d.patch --dry-run         # review a local patch, no GitHub
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

CONFIG = pathlib.Path(__file__).resolve().parent.parent / "config" / "pr_reviewers.yml"
MAX_DIFF_CHARS = 60000
# Local fallback so the script is testable off-CI: env var wins; else the opencode auth store.
STORE_FALLBACK = {"NVIDIA_API_KEY": "nvidia", "TOGETHER_API_KEY": "togetherai", "OPENROUTER_API_KEY": "openrouterai"}

PROMPT = (
    "You are an adversarial pull-request reviewer. Review ONLY the diff below for real defects: "
    "correctness, security, data handling, missing tests, and repo-boundary issues. List concrete "
    "findings, each as `P0|P1|P2 file:line - issue (one-line fix)`. Do not invent issues; if there "
    "are none, reply exactly `No P0/P1/P2 findings.` Be concise.\n\nDiff:\n```diff\n{diff}\n```"
)


def load_yaml(path: pathlib.Path) -> dict:
    try:
        import yaml
    except ImportError:
        sys.exit("pr_review: PyYAML required (pip install pyyaml)")
    return yaml.safe_load(path.read_text())


def api_key(key_env: str) -> str | None:
    if os.environ.get(key_env):
        return os.environ[key_env]
    # Local convenience ONLY. In CI, secrets must come from the GitHub Secrets env vars (for
    # provenance/governance); never read the ambient opencode auth store on a runner.
    if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI"):
        return None
    store = pathlib.Path.home() / ".local/share/opencode/auth.json"
    name = STORE_FALLBACK.get(key_env)
    if name and store.is_file():
        try:
            entry = json.loads(store.read_text()).get(name) or {}
            return entry.get("key") or entry.get("api_key") or entry.get("token")
        except Exception:
            return None
    return None


def get_diff(args: argparse.Namespace) -> str:
    if args.diff_file:
        return pathlib.Path(args.diff_file).read_text()
    proc = subprocess.run(
        ["gh", "pr", "diff", str(args.pr), "--repo", args.repo],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"pr_review: gh pr diff failed: {proc.stderr.strip()}")
    return proc.stdout


def review_one(label: str, spec: dict, diff: str) -> str:
    key = api_key(spec["key_env"])
    if not key:
        return f"### {label}\n_skipped: no {spec['key_env']} available._"
    body = json.dumps({
        "model": spec["model"],
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": PROMPT.format(diff=diff[:MAX_DIFF_CHARS])}],
    }).encode()
    req = urllib.request.Request(
        spec["base_url"].rstrip("/") + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}",
                 "User-Agent": "eos-pr-review/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read())
        text = (payload.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
        return f"### {label} (`{spec['model']}`)\n{text or '_empty response_'}"
    except Exception as exc:  # noqa: BLE001 - report, never crash the whole review
        return f"### {label} (`{spec['model']}`)\n_review call failed: {type(exc).__name__}: {exc}_"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", help="owner/name (required to post)")
    ap.add_argument("--pr", type=int, help="PR number (required to post)")
    ap.add_argument("--diff-file", help="review a local patch instead of a PR")
    ap.add_argument("--dry-run", action="store_true", help="print the review, do not post")
    ap.add_argument("--family", help="override the active family from config")
    args = ap.parse_args(argv)

    cfg = load_yaml(CONFIG)
    family = args.family or cfg.get("active")
    reviewers = (cfg.get("families") or {}).get(family)
    if not reviewers:
        sys.exit(f"pr_review: family {family!r} not in config/pr_reviewers.yml")
    models = cfg.get("models") or {}

    if args.diff_file:
        diff = get_diff(args)
    else:
        if not (args.repo and args.pr):
            sys.exit("pr_review: --repo and --pr are required (or use --diff-file)")
        diff = get_diff(args)
    if not diff.strip():
        print("pr_review: empty diff, nothing to review")
        return 0

    missing = [r for r in reviewers if r not in models]
    if missing:
        sys.exit(f"pr_review: family {family!r} names reviewers not in `models`: {missing}")
    sections = [review_one(r, models[r], diff) for r in reviewers]
    header = f"## Stage-4 PR review ({family} family: {', '.join(reviewers)})\n"
    if len(diff) > MAX_DIFF_CHARS:
        header += (
            f"\n> Note: the diff is {len(diff)} chars; reviewers saw the first {MAX_DIFF_CHARS}. "
            "Split large PRs for full coverage.\n"
        )
    review = header + "\n\n".join(sections)

    if args.dry_run or not (args.repo and args.pr):
        print(review)
        return 0
    proc = subprocess.run(
        ["gh", "pr", "comment", str(args.pr), "--repo", args.repo, "--body", review],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"pr_review: gh pr comment failed: {proc.stderr.strip()}")
    print(f"pr_review: posted to {args.repo}#{args.pr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
