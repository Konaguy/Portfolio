"""
Build the `findings.json` the dashboard reads.

Takes the `Vulnerability` records (from any source -- the Defender connector or
a Tenable import) and produces a single JSON document with the aggregates the
dashboard needs (severity counts, per-host rollups, SLA status, top CVEs) plus
the full finding list. The SLA fields use the same thresholds as the sample
patch-management policy so the dashboard and the RAG bot tell the same story.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .schema import Severity, Vulnerability

# Remediation SLA (days) by severity -- mirrors data/sample_policies.
_SLA_DAYS = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _risk_score(v: Vulnerability) -> float:
    """A simple blended risk score for ranking: CVSS, nudged by severity so
    ties break sensibly. Kept transparent rather than clever."""
    base = v.cvss_base_score if v.cvss_base_score is not None else _severity_default(v.severity)
    weight = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.9,
        Severity.MEDIUM: 0.7,
        Severity.LOW: 0.5,
        Severity.INFO: 0.2,
    }[v.severity]
    return round(base * weight, 2)


def _severity_default(sev: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.0,
    }[sev]


def build_findings_document(
    vulns: list[Vulnerability], generated_at: datetime | None = None
) -> dict:
    generated_at = generated_at or datetime.now(timezone.utc)

    severity_counts = {s.value: 0 for s in _SEVERITY_ORDER}
    for v in vulns:
        severity_counts[v.severity.value] += 1

    hosts: dict[str, dict] = {}
    for v in vulns:
        h = hosts.setdefault(
            v.host,
            {"host": v.host, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "max_cvss": 0.0},
        )
        h["total"] += 1
        h[v.severity.value] += 1
        if v.cvss_base_score:
            h["max_cvss"] = max(h["max_cvss"], v.cvss_base_score)

    findings = []
    for v in sorted(vulns, key=_risk_score, reverse=True):
        findings.append(
            {
                "chunk_id": v.chunk_id,
                "cve": v.cve[0] if v.cve else "",
                "name": v.name,
                "severity": v.severity.value,
                "cvss": v.cvss_base_score,
                "host": v.host,
                "solution": v.solution,
                "risk_score": _risk_score(v),
                "sla_days": _SLA_DAYS[v.severity],
                "references": v.see_also,
            }
        )

    top_cves: dict[str, int] = {}
    for v in vulns:
        if v.cve:
            top_cves[v.cve[0]] = top_cves.get(v.cve[0], 0) + 1

    return {
        "generated_at": generated_at.isoformat(),
        "summary": {
            "total_findings": len(vulns),
            "hosts_scanned": len(hosts),
            "severity_counts": severity_counts,
            "top_cves": [
                {"cve": c, "count": n}
                for c, n in sorted(top_cves.items(), key=lambda kv: kv[1], reverse=True)[:10]
            ],
        },
        "hosts": sorted(hosts.values(), key=lambda h: (h["critical"], h["high"], h["max_cvss"]), reverse=True),
        "findings": findings,
    }
