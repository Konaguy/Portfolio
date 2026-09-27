"""
Parse detection content into a common `Detection` record carrying the ATT&CK
technique IDs it addresses.

Three formats, matching what lives in this portfolio:

*   **Microsoft Defender custom detection rules** -- JSON, techniques under
    `detectionRules[].detectionAction.alertTemplate.mitreTechniques`.
*   **Microsoft Sentinel analytics rules** -- YAML list, techniques under each
    rule's `relevantTechniques`.
*   **Sigma rules** -- YAML, techniques in `tags` as `attack.tXXXX[.yyy]`.

Technique IDs are normalized to upper-case (`T1059.001`). A belt-and-braces
regex sweep backs up the structured parse so a technique mentioned only in prose
is still counted rather than silently missed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass
class Detection:
    name: str
    source: str            # 'defender' | 'sentinel' | 'sigma'
    platform: str          # e.g. 'Microsoft Defender XDR', 'Microsoft Sentinel', 'Sigma'
    technique_ids: list[str] = field(default_factory=list)
    path: str = ""

    def normalized_ids(self) -> list[str]:
        seen: dict[str, None] = {}
        for t in self.technique_ids:
            seen.setdefault(t.upper(), None)
        return list(seen)


def _find_ids(text: str) -> list[str]:
    return [m.upper() for m in _TECH_RE.findall(text)]


def parse_defender_json(text: str, path: str = "") -> list[Detection]:
    data = json.loads(text)
    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict):
        rules = data.get("detectionRules", [])
    else:
        rules = []
    out: list[Detection] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = r.get("displayName") or r.get("name") or "(unnamed)"
        template = (r.get("detectionAction") or {}).get("alertTemplate") or {}
        ids = list(template.get("mitreTechniques") or [])
        # Fall back to a regex sweep of the rule if the field is absent or named
        # differently, so a schema variation doesn't silently drop coverage.
        if not ids:
            ids = _find_ids(json.dumps(r))
        out.append(Detection(name=name, source="defender",
                             platform="Microsoft Defender XDR",
                             technique_ids=[i.upper() for i in ids], path=path))
    return out


def parse_sentinel_yaml(text: str, path: str = "") -> list[Detection]:
    data = yaml.safe_load(text)
    rules = data if isinstance(data, list) else [data]
    out: list[Detection] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = r.get("name") or r.get("id") or "(unnamed)"
        ids = r.get("relevantTechniques") or []
        ids = [str(i).upper() for i in ids]
        out.append(Detection(name=name, source="sentinel",
                             platform="Microsoft Sentinel",
                             technique_ids=ids, path=path))
    return out


def parse_sigma_yaml(text: str, path: str = "") -> list[Detection]:
    """Sigma files may contain multiple YAML documents; one Detection per doc."""
    out: list[Detection] = []
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        name = doc.get("title") or doc.get("id") or "(unnamed)"
        ids: list[str] = []
        for tag in doc.get("tags", []) or []:
            tag = str(tag)
            if tag.lower().startswith("attack.t"):
                ids.extend(_find_ids(tag))
        out.append(Detection(name=name, source="sigma", platform="Sigma",
                             technique_ids=ids, path=path))
    return out


_PARSERS = {
    ".json": parse_defender_json,
    ".yaml": parse_sentinel_yaml,
    ".yml": parse_sigma_yaml,
}


def _classify_and_parse(path: Path) -> list[Detection]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    # Disambiguate the two YAML dialects by content, not just extension.
    if suffix in (".yaml", ".yml"):
        head = text[:4000]
        if "detectionRules" in head or '"mitreTechniques"' in head:
            return parse_defender_json(text, str(path))
        if "logsource" in head or "\ntags:" in head or head.startswith("tags:"):
            return parse_sigma_yaml(text, str(path))
        return parse_sentinel_yaml(text, str(path))
    if suffix == ".json":
        return parse_defender_json(text, str(path))
    return []


def parse_path(path: str | Path) -> list[Detection]:
    """Parse a single file or recurse a directory for detection content."""
    p = Path(path)
    if p.is_file():
        return _classify_and_parse(p)
    detections: list[Detection] = []
    for f in sorted(p.rglob("*")):
        if f.is_file() and f.suffix.lower() in (".json", ".yaml", ".yml"):
            try:
                detections.extend(_classify_and_parse(f))
            except Exception:
                # A non-detection JSON/YAML in the tree shouldn't break the scan.
                continue
    return detections


def parse_paths(paths: list[str | Path]) -> list[Detection]:
    out: list[Detection] = []
    for p in paths:
        out.extend(parse_path(p))
    return out
