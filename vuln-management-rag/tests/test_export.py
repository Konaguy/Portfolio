from __future__ import annotations

from pathlib import Path

from vulnrag.connectors import FakeDefenderConnector
from vulnrag.connectors.defender import findings_to_vulnerabilities
from vulnrag.export import build_findings_document

_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_defender_findings.json"


def _doc():
    conn = FakeDefenderConnector.from_json_file(str(_SAMPLE))
    vulns = findings_to_vulnerabilities(conn.get_findings())
    return build_findings_document(vulns), vulns


def test_summary_totals():
    doc, vulns = _doc()
    assert doc["summary"]["total_findings"] == len(vulns)
    assert doc["summary"]["hosts_scanned"] == 4
    counts = doc["summary"]["severity_counts"]
    assert sum(counts.values()) == len(vulns)
    assert counts["critical"] >= 1


def test_findings_sorted_by_risk_desc():
    doc, _ = _doc()
    scores = [f["risk_score"] for f in doc["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_each_finding_has_sla_and_host():
    doc, _ = _doc()
    for f in doc["findings"]:
        assert f["host"]
        assert f["sla_days"] > 0
        assert f["severity"] in {"critical", "high", "medium", "low", "info"}


def test_hosts_rollup_matches_findings():
    doc, _ = _doc()
    total_from_hosts = sum(h["total"] for h in doc["hosts"])
    assert total_from_hosts == doc["summary"]["total_findings"]


def test_top_cves_present():
    doc, _ = _doc()
    assert doc["summary"]["top_cves"]
    assert all("cve" in c and "count" in c for c in doc["summary"]["top_cves"])
