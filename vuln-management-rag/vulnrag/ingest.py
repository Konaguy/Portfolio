"""
Ingestion: turn raw inputs into corpus models ready for the vector store.

Two sources:

*   **Tenable/Nessus CSV exports** -> `Vulnerability` records. Tenable's
    column names vary a little between the Nessus UI export and the
    Tenable.io/Tenable.sc exports, so `_pick` tolerates the common aliases.
*   **Policy documents** (Markdown / plain text) -> `PolicyChunk` records,
    split on headings then packed to a target size so each chunk is a
    coherent, retrievable unit.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from pathlib import Path

from .schema import PolicyChunk, Severity, Vulnerability

# Map of our field -> list of accepted CSV header aliases (case-insensitive).
_COLUMN_ALIASES: dict[str, list[str]] = {
    "plugin_id": ["Plugin ID", "Plugin", "pluginID"],
    "cve": ["CVE", "CVEs"],
    "name": ["Name", "Plugin Name", "Vulnerability"],
    "severity": ["Severity", "Risk"],
    "cvss": ["CVSS v3.0 Base Score", "CVSS V3 Base Score", "CVSS Base Score", "CVSS"],
    "vpr": ["VPR Score", "Vulnerability Priority Rating", "VPR"],
    "host": ["Host", "IP Address", "DNS Name", "Asset"],
    "port": ["Port"],
    "description": ["Description", "Synopsis"],
    "solution": ["Solution", "Steps to Remediate"],
    "see_also": ["See Also", "References"],
}

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _normalize_headers(fieldnames: list[str]) -> dict[str, str]:
    """Return {our_field: actual_header} for headers present in this CSV."""
    lower = {h.lower().strip(): h for h in fieldnames}
    resolved: dict[str, str] = {}
    for field, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias.lower() in lower:
                resolved[field] = lower[alias.lower()]
                break
    return resolved


def _pick(row: dict, resolved: dict[str, str], field: str, default: str = "") -> str:
    header = resolved.get(field)
    if header is None:
        return default
    value = row.get(header)
    return (value or default).strip()


def _to_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.lower().strip(), Severity.INFO)


def _float_or_none(raw: str) -> float | None:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _vuln_chunk_id(plugin_id: str, host: str, port: str) -> str:
    basis = f"{plugin_id}|{host}|{port}".encode("utf-8")
    return "vuln-" + hashlib.sha1(basis).hexdigest()[:12]


def parse_tenable_csv(text: str) -> list[Vulnerability]:
    """Parse a Tenable/Nessus CSV export into Vulnerability records."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return []
    resolved = _normalize_headers(list(reader.fieldnames))
    if "plugin_id" not in resolved or "name" not in resolved:
        raise ValueError(
            "CSV does not look like a Tenable export: no Plugin ID / Name column found. "
            f"Headers seen: {reader.fieldnames}"
        )

    vulns: list[Vulnerability] = []
    for row in reader:
        plugin_id = _pick(row, resolved, "plugin_id")
        host = _pick(row, resolved, "host")
        port = _pick(row, resolved, "port")
        if not plugin_id or not host:
            continue
        severity = _to_severity(_pick(row, resolved, "severity"))
        # Tenable marks a lot of informational plugins; a SOC triage corpus
        # is more useful without them.
        if severity == Severity.INFO:
            continue
        see_also_raw = _pick(row, resolved, "see_also")
        vulns.append(
            Vulnerability(
                chunk_id=_vuln_chunk_id(plugin_id, host, port),
                plugin_id=plugin_id,
                cve=_pick(row, resolved, "cve"),
                name=_pick(row, resolved, "name"),
                severity=severity,
                cvss_base_score=_float_or_none(_pick(row, resolved, "cvss")),
                vpr_score=_float_or_none(_pick(row, resolved, "vpr")),
                host=host,
                port=port or None,
                description=_pick(row, resolved, "description"),
                solution=_pick(row, resolved, "solution"),
                see_also=[s.strip() for s in re.split(r"[\n,]", see_also_raw) if s.strip()],
            )
        )
    return vulns


def parse_tenable_file(path: str | Path) -> list[Vulnerability]:
    return parse_tenable_csv(Path(path).read_text(encoding="utf-8"))


def _policy_chunk_id(source: str, index: int) -> str:
    basis = f"{source}|{index}".encode("utf-8")
    return "pol-" + hashlib.sha1(basis).hexdigest()[:12]


def chunk_policy_text(
    text: str, source: str, target_chars: int = 900
) -> list[PolicyChunk]:
    """Split a policy doc on Markdown headings, then pack paragraphs up to a
    target size so each chunk stays under the target while keeping a whole
    section's context together where it fits."""
    # Split into (heading, body) sections on ATX headings.
    sections: list[tuple[str, str]] = []
    current_heading = ""
    current_lines: list[str] = []
    for line in text.splitlines():
        if re.match(r"^#{1,6}\s+", line):
            if current_lines:
                sections.append((current_heading, "\n".join(current_lines).strip()))
                current_lines = []
            current_heading = re.sub(r"^#{1,6}\s+", "", line).strip()
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_heading, "\n".join(current_lines).strip()))

    chunks: list[PolicyChunk] = []
    index = 0
    for heading, body in sections:
        if not body:
            continue
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
        buffer = ""
        for para in paragraphs:
            if buffer and len(buffer) + len(para) + 2 > target_chars:
                chunks.append(
                    PolicyChunk(
                        chunk_id=_policy_chunk_id(source, index),
                        source=source,
                        section=heading,
                        text=buffer.strip(),
                    )
                )
                index += 1
                buffer = para
            else:
                buffer = f"{buffer}\n\n{para}" if buffer else para
        if buffer:
            chunks.append(
                PolicyChunk(
                    chunk_id=_policy_chunk_id(source, index),
                    source=source,
                    section=heading,
                    text=buffer.strip(),
                )
            )
            index += 1
    return chunks


def parse_policy_file(path: str | Path) -> list[PolicyChunk]:
    p = Path(path)
    return chunk_policy_text(p.read_text(encoding="utf-8"), source=p.name)


def parse_policy_dir(path: str | Path) -> list[PolicyChunk]:
    directory = Path(path)
    chunks: list[PolicyChunk] = []
    for file in sorted(directory.glob("**/*")):
        if file.suffix.lower() in {".md", ".markdown", ".txt"} and file.is_file():
            chunks.extend(parse_policy_file(file))
    return chunks
