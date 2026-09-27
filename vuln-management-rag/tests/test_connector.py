from __future__ import annotations

from pathlib import Path

import pytest

from vulnrag.connectors import FakeDefenderConnector, finding_to_vulnerability
from vulnrag.connectors.defender import AuthConfig, findings_to_vulnerabilities
from vulnrag.schema import Severity, Vulnerability

_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_defender_findings.json"


def test_map_finding_to_vulnerability():
    finding = {
        "deviceName": "srv-web-01.corp.contoso.com",
        "osPlatform": "WindowsServer2019",
        "cveId": "CVE-2021-44228",
        "vulnerabilitySeverityLevel": "Critical",
        "cvssScore": 10.0,
        "softwareVendor": "apache",
        "softwareName": "log4j",
        "softwareVersion": "2.14.0",
        "recommendedSecurityUpdate": "Upgrade Apache Log4j to 2.17.1",
        "exploitabilityLevel": "ExploitIsPublic",
    }
    v = finding_to_vulnerability(finding)
    assert isinstance(v, Vulnerability)
    assert v.host == "srv-web-01.corp.contoso.com"
    assert v.cve == ["CVE-2021-44228"]
    assert v.severity == Severity.CRITICAL
    assert v.cvss_base_score == 10.0
    assert "log4j" in v.name.lower()
    assert "2.17.1" in v.solution
    assert v.see_also == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]


def test_chunk_ids_stable_and_unique():
    conn = FakeDefenderConnector.from_json_file(str(_SAMPLE))
    vulns = findings_to_vulnerabilities(conn.get_findings())
    ids = [v.chunk_id for v in vulns]
    assert len(ids) == len(set(ids))
    again = findings_to_vulnerabilities(conn.get_findings())
    assert [v.chunk_id for v in again] == ids


def test_fake_connector_device_filter():
    conn = FakeDefenderConnector.from_json_file(str(_SAMPLE))
    only_hr = conn.get_findings(["pc-hr-07"])
    assert only_hr
    assert all(f["deviceName"].startswith("pc-hr-07") for f in only_hr)


def test_sample_covers_four_devices():
    conn = FakeDefenderConnector.from_json_file(str(_SAMPLE))
    vulns = findings_to_vulnerabilities(conn.get_findings())
    hosts = {v.host.split(".")[0] for v in vulns}
    assert hosts == {"srv-web-01", "srv-sql-01", "pc-hr-07", "pc-eng-12"}


def test_auth_config_missing_env(monkeypatch):
    for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ValueError):
        AuthConfig.from_env()


def test_findings_ingest_into_store(seeded_store):
    # seeded_store already has Tenable data; add Defender findings and confirm
    # they are queryable through the same store.
    conn = FakeDefenderConnector.from_json_file(str(_SAMPLE))
    vulns = findings_to_vulnerabilities(conn.get_findings())
    before = seeded_store.count()
    seeded_store.upsert_vulnerabilities(vulns)
    assert seeded_store.count() > before
    hits = seeded_store.search("log4j on srv-web-01", top_k=3, kind="vulnerability")
    assert hits
