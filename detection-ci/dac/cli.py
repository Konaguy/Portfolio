"""
Detection-as-Code gate.

    # Validate this repo's detections (from anywhere):
    python -m dac.cli --repo

    # Validate specific paths, emit GitHub annotations, write a JSON report:
    python -m dac.cli --path some/rules --format github --json-out dac-report.json

Exit code is non-zero when there are error-level findings, so it fails a CI job.
Warnings alone do not fail the build unless --strict is passed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .discover import default_scan, scan
from .report import Report

# repo root = two levels up from this file (detection-ci/dac/cli.py -> repo root)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _emit(report: Report, fmt: str) -> None:
    if fmt == "json":
        print(report.to_json())
    elif fmt == "github":
        gh = report.to_github()
        if gh:
            print(gh)
        print(report.to_text(), file=sys.stderr)
    else:
        print(report.to_text())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detection-as-Code validation gate.")
    parser.add_argument("--path", action="append", default=[], help="File/dir to validate (repeatable)")
    parser.add_argument("--repo", action="store_true", help="Validate this repo's detection directories")
    parser.add_argument("--root", default=str(_REPO_ROOT), help="Repo root for --repo (default: inferred)")
    parser.add_argument("--format", choices=["text", "json", "github"], default="text")
    parser.add_argument("--json-out", help="Also write the JSON report to this path")
    parser.add_argument("--strict", action="store_true", help="Fail on warnings too")
    args = parser.parse_args(argv)

    if not args.path and not args.repo:
        parser.error("provide --path or --repo")

    report = default_scan(args.root) if args.repo else Report()
    if args.path:
        extra = scan(args.path)
        report.files_checked += extra.files_checked
        report.extend(extra.findings)

    _emit(report, args.format)
    if args.json_out:
        Path(args.json_out).write_text(report.to_json(), encoding="utf-8")

    failed = bool(report.errors) or (args.strict and bool(report.warnings))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
