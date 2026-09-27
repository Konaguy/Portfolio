"""
Feed loaders: turn various threat-intel source formats into a `ThreatIntel`
(raw text + extracted IOCs).

Supported:
- plain text / CVE descriptions / prose reports  -> extract IOCs from the text
- CSV IOC lists (a column of indicators, optionally typed)
- STIX 2.x bundles (pull `pattern` values out of `indicator` objects)
- MISP event JSON (pull `Attribute.value` fields)

Everything funnels through `iocs.extract_iocs` for the actual indicator
recognition, so defanged indicators are handled uniformly.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .iocs import extract_iocs
from .schema import ThreatIntel


def from_text(text: str, source: str = "text") -> ThreatIntel:
    return ThreatIntel(source=source, raw_text=text, iocs=extract_iocs(text))


def from_csv(text: str, source: str = "csv") -> ThreatIntel:
    """Flatten a CSV into text, then extract. Works whether or not the file has
    a header or a dedicated indicator column."""
    reader = csv.reader(io.StringIO(text))
    cells = [cell for row in reader for cell in row]
    joined = "\n".join(cells)
    return ThreatIntel(source=source, raw_text=joined, iocs=extract_iocs(joined))


def from_stix(text: str, source: str = "stix") -> ThreatIntel:
    """Pull indicator patterns out of a STIX 2.x bundle."""
    data = json.loads(text)
    objects = data.get("objects", []) if isinstance(data, dict) else []
    patterns = [
        obj.get("pattern", "")
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "indicator"
    ]
    blob = "\n".join(patterns)
    return ThreatIntel(source=source, raw_text=blob, iocs=extract_iocs(blob))


def from_misp(text: str, source: str = "misp") -> ThreatIntel:
    """Pull attribute values out of a MISP event JSON."""
    data = json.loads(text)
    event = data.get("Event", data) if isinstance(data, dict) else {}
    values: list[str] = []
    for attr in event.get("Attribute", []) or []:
        if isinstance(attr, dict) and attr.get("value"):
            values.append(str(attr["value"]))
    for obj in event.get("Object", []) or []:
        for attr in obj.get("Attribute", []) or []:
            if isinstance(attr, dict) and attr.get("value"):
                values.append(str(attr["value"]))
    blob = "\n".join(values)
    return ThreatIntel(source=source, raw_text=blob, iocs=extract_iocs(blob))


def load_file(path: str | Path, fmt: str = "auto") -> ThreatIntel:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if fmt == "auto":
        fmt = _sniff_format(p, text)
    loaders = {
        "text": from_text,
        "csv": from_csv,
        "stix": from_stix,
        "misp": from_misp,
    }
    if fmt not in loaders:
        raise ValueError(f"Unknown format: {fmt!r}")
    return loaders[fmt](text, source=p.name)


def _sniff_format(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix == ".json":
        stripped = text.lstrip()
        if '"spec_version"' in text or '"type": "bundle"' in text:
            return "stix"
        if '"Event"' in text or '"Attribute"' in text:
            return "misp"
        return "text"
    return "text"
