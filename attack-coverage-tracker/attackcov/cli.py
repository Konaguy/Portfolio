"""
Scan detection sources, build the coverage model, and write the dashboard data
and the ATT&CK Navigator layer.

    # Scan this portfolio's real detections (run from the repo root):
    python -m attackcov.cli \
        --path ../security-automation-soar/detection-rules \
        --path ../sigma-rule-translator/rules

    # Or scan the bundled sample rule set (standalone):
    python -m attackcov.cli --sample

Writes dashboard/coverage.json and navigator-layer.json by default, and prints a
short coverage summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .coverage import build_coverage
from .navigator import build_layer
from .parsers import parse_paths

_HERE = Path(__file__).resolve().parent.parent
_SAMPLE = _HERE / "data" / "sample_rules"
_DEFAULT_COVERAGE = _HERE / "dashboard" / "coverage.json"
_DEFAULT_LAYER = _HERE / "navigator-layer.json"

# Where this portfolio keeps its detections. Resolved against the repo root
# (this project's parent) so --repo works regardless of the current directory.
_REPO_ROOT = _HERE.parent
_REPO_DEFAULTS = [
    str(_REPO_ROOT / "security-automation-soar" / "detection-rules"),
    str(_REPO_ROOT / "sigma-rule-translator" / "rules"),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Map detections to ATT&CK and report coverage.")
    parser.add_argument("--path", action="append", default=[], help="File or directory of detections (repeatable)")
    parser.add_argument("--sample", action="store_true", help="Use the bundled sample rule set")
    parser.add_argument("--repo", action="store_true", help="Scan this portfolio's detection dirs (from repo root)")
    parser.add_argument("--name", default="Portfolio detection coverage", help="Layer name")
    parser.add_argument("--coverage-out", default=str(_DEFAULT_COVERAGE))
    parser.add_argument("--layer-out", default=str(_DEFAULT_LAYER))
    args = parser.parse_args(argv)

    paths: list[str] = list(args.path)
    if args.sample:
        paths.append(str(_SAMPLE))
    if args.repo:
        paths.extend(_REPO_DEFAULTS)
    if not paths:
        parser.error("provide --path, --sample, or --repo")

    detections = parse_paths(paths)
    if not detections:
        print(f"No detections found in: {', '.join(paths)}", file=sys.stderr)
        return 2

    coverage = build_coverage(detections, layer_name=args.name)
    layer = build_layer(coverage)

    # Drop the internal helper key before writing the public document.
    public = {k: v for k, v in coverage.items() if not k.startswith("_")}

    cov_path = Path(args.coverage_out)
    cov_path.parent.mkdir(parents=True, exist_ok=True)
    cov_path.write_text(json.dumps(public, indent=2), encoding="utf-8")

    layer_path = Path(args.layer_out)
    layer_path.parent.mkdir(parents=True, exist_ok=True)
    layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")

    s = coverage["summary"]
    print(f"Parsed {s['detections_parsed']} detections "
          f"({', '.join(f'{k}: {v}' for k, v in s['sources'].items())}).")
    print(f"Covered {s['techniques_covered']} techniques across "
          f"{s['tactics_with_coverage']}/{s['tactics_total']} tactics "
          f"({s['coverage_pct']}% of the catalog).")
    if s["unknown_technique_ids"]:
        print(f"Note: {len(s['unknown_technique_ids'])} technique id(s) not in the bundled "
              f"catalog: {', '.join(s['unknown_technique_ids'])}")
    print(f"Wrote {cov_path} and {layer_path}.")
    print("Open dashboard/index.html to view; import navigator-layer.json into the ATT&CK Navigator.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
