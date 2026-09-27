"""
Find and classify detection files in a repository, then run the right validator
for each and aggregate a `Report`.

Classification is by content, not just extension: a `.json` with detection rules
is Defender; a `.yml`/`.yaml` with a Sigma `detection:`/`logsource:` block is
Sigma; a YAML list of analytics rules is Sentinel.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .report import Finding, Report, Severity
from .rules import validate_defender_text, validate_sentinel_text
from .sigma import lint_sigma_text

# Directories this portfolio keeps detections in, relative to the repo root.
DEFAULT_DIRS = [
    "security-automation-soar/detection-rules",
    "sigma-rule-translator/rules",
]


def classify(path: Path, text: str) -> str | None:
    """Return 'defender' | 'sentinel' | 'sigma' | None."""
    suffix = path.suffix.lower()
    head = text[:4000]
    if suffix == ".json":
        if "detectionRules" in head or '"mitreTechniques"' in head or head.lstrip().startswith("["):
            return "defender"
        return None
    if suffix in (".yml", ".yaml"):
        if "detectionRules" in head or '"mitreTechniques"' in head:
            return "defender"
        # Sigma: single rule with logsource/detection blocks
        if "logsource:" in head or "\ndetection:" in head or head.startswith("detection:"):
            return "sigma"
        # Sentinel: analytics rules carry relevantTechniques / queryFrequency / kind
        if "relevantTechniques" in head or "queryFrequency" in head or "kind:" in head:
            return "sentinel"
    return None


_VALIDATORS = {
    "defender": validate_defender_text,
    "sentinel": validate_sentinel_text,
    "sigma": lint_sigma_text,
}


def _count_rules(text: str, kind: str) -> int:
    try:
        if kind == "defender":
            data = json.loads(text)
            rules = data if isinstance(data, list) else data.get("detectionRules", [])
            return len(rules)
        if kind == "sentinel":
            data = yaml.safe_load(text)
            return len(data) if isinstance(data, list) else 1
        if kind == "sigma":
            return sum(1 for d in yaml.safe_load_all(text) if isinstance(d, dict))
    except Exception:
        return 0
    return 0


def validate_file(path: Path) -> tuple[list[Finding], str | None, int]:
    text = path.read_text(encoding="utf-8")
    kind = classify(path, text)
    if kind is None:
        return [], None, 0
    return _VALIDATORS[kind](text, str(path)), kind, _count_rules(text, kind)


def scan(paths: list[str | Path]) -> Report:
    report = Report()
    files: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_file():
            files.append(pp)
        elif pp.is_dir():
            files.extend(sorted(f for f in pp.rglob("*") if f.suffix.lower() in (".json", ".yml", ".yaml")))
    for f in files:
        try:
            findings, kind, count = validate_file(f)
        except Exception as exc:  # a malformed file is a finding, not a crash
            report.files_checked += 1
            report.add(Finding(file=str(f), code="dac-validator-error",
                               message=f"validator raised: {exc}", severity=Severity.ERROR))
            continue
        if kind is None:
            continue
        report.files_checked += 1
        report.rules_checked += count
        report.extend(findings)
    return report


def default_scan(repo_root: str | Path) -> Report:
    root = Path(repo_root)
    dirs = [root / d for d in DEFAULT_DIRS if (root / d).exists()]
    return scan(dirs)
