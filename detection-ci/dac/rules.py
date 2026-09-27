"""
Validators for Microsoft Defender custom detection rules (JSON) and Microsoft
Sentinel analytics rules (YAML).

Both share the same concerns: a name, a valid severity, a well-formed ATT&CK
technique reference, and a KQL query that passes the sanity checks in `kql.py`.
The field paths differ per platform, so there's one validator each.
"""

from __future__ import annotations

import json
import re

import yaml

from .kql import check_kql
from .report import Finding, Severity

_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DEFENDER_SEV = {"informational", "low", "medium", "high"}
_SENTINEL_SEV = {"informational", "low", "medium", "high"}


def _tech_findings(ids: list, path: str, name: str) -> list[Finding]:
    out = []
    if not ids:
        out.append(Finding(file=path, code="rule-no-technique", rule=name,
                           message="rule declares no MITRE ATT&CK technique", severity=Severity.WARNING))
    for t in ids:
        if not _TECH_RE.match(str(t)):
            out.append(Finding(file=path, code="rule-bad-technique", rule=name,
                               message=f"malformed ATT&CK technique id {t!r}", severity=Severity.ERROR))
    return out


def validate_defender_text(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [Finding(file=path, code="defender-invalid-json",
                        message=f"JSON parse error: {exc}", severity=Severity.ERROR)]

    rules = data if isinstance(data, list) else data.get("detectionRules", []) if isinstance(data, dict) else []
    if not rules:
        out.append(Finding(file=path, code="defender-empty",
                           message="no detection rules found", severity=Severity.WARNING))

    for r in rules:
        if not isinstance(r, dict):
            continue
        name = r.get("displayName") or r.get("name") or "(unnamed)"
        template = (r.get("detectionAction") or {}).get("alertTemplate") or {}

        if not (r.get("displayName") or r.get("name")):
            out.append(Finding(file=path, code="defender-no-name",
                               message="rule has no displayName", severity=Severity.ERROR))

        sev = str(template.get("severity", "")).lower()
        if sev and sev not in _DEFENDER_SEV:
            out.append(Finding(file=path, code="defender-bad-severity", rule=name,
                               message=f"severity {sev!r} not in {sorted(_DEFENDER_SEV)}",
                               severity=Severity.ERROR))

        out.extend(_tech_findings(template.get("mitreTechniques") or [], path, name))

        kql = (r.get("queryCondition") or {}).get("queryText", "")
        if not kql:
            out.append(Finding(file=path, code="defender-no-query", rule=name,
                               message="rule has no queryCondition.queryText", severity=Severity.ERROR))
        else:
            for p in check_kql(kql):
                out.append(Finding(file=path, code="defender-bad-kql", rule=name,
                                   message=p, severity=Severity.ERROR))
    return out


def validate_sentinel_text(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [Finding(file=path, code="sentinel-invalid-yaml",
                        message=f"YAML parse error: {exc}", severity=Severity.ERROR)]

    rules = data if isinstance(data, list) else [data]
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = r.get("name") or r.get("id") or "(unnamed)"

        if not r.get("name"):
            out.append(Finding(file=path, code="sentinel-no-name",
                               message="rule has no name", severity=Severity.ERROR))

        sev = str(r.get("severity", "")).lower()
        if not sev:
            out.append(Finding(file=path, code="sentinel-no-severity", rule=name,
                               message="rule has no severity", severity=Severity.WARNING))
        elif sev not in _SENTINEL_SEV:
            out.append(Finding(file=path, code="sentinel-bad-severity", rule=name,
                               message=f"severity {sev!r} not in {sorted(_SENTINEL_SEV)}",
                               severity=Severity.ERROR))

        out.extend(_tech_findings(r.get("relevantTechniques") or [], path, name))

        kql = r.get("query", "")
        if not kql:
            out.append(Finding(file=path, code="sentinel-no-query", rule=name,
                               message="rule has no 'query'", severity=Severity.ERROR))
        else:
            for p in check_kql(kql):
                out.append(Finding(file=path, code="sentinel-bad-kql", rule=name,
                                   message=p, severity=Severity.ERROR))
    return out
