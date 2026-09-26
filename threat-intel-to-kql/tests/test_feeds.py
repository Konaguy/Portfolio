from __future__ import annotations

from pathlib import Path

from ti2kql.feeds import from_csv, from_misp, from_stix, load_file
from ti2kql.schema import IOCType

_DATA = Path(__file__).resolve().parent.parent / "data"


def _has(intel, t, needle):
    return any(needle in i.value for i in intel.iocs if i.type == t)


def test_load_cve_text_file():
    intel = load_file(_DATA / "sample_cve.txt")
    assert intel.source == "sample_cve.txt"
    assert _has(intel, IOCType.CVE, "CVE-2023-34362")
    assert _has(intel, IOCType.SHA256, "702421bcee1785")
    assert _has(intel, IOCType.IPV4, "148.113.152.144")
    assert _has(intel, IOCType.DOMAIN, "badactor.com")


def test_load_csv_feed():
    intel = load_file(_DATA / "sample_iocs.csv")
    assert _has(intel, IOCType.IPV4, "185.220.101.45")
    assert _has(intel, IOCType.MD5, "44d88612fea8a8f36de82e1278abb02f")
    assert _has(intel, IOCType.CVE, "CVE-2024-21412")
    assert _has(intel, IOCType.DOMAIN, "malicious-update.net")


def test_load_stix_bundle():
    intel = load_file(_DATA / "sample_stix.json")
    assert _has(intel, IOCType.IPV4, "203.0.113.55")
    assert _has(intel, IOCType.SHA256, "aa11bb22cc33")
    assert _has(intel, IOCType.DOMAIN, "example-malware.org")


def test_misp_parsing():
    misp = """
    {"Event": {"Attribute": [
        {"type": "ip-dst", "value": "10.11.12.13"},
        {"type": "sha256", "value": "bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66ee77"}
    ]}}
    """
    intel = from_misp(misp)
    assert _has(intel, IOCType.IPV4, "10.11.12.13")
    assert _has(intel, IOCType.SHA256, "bb22cc33dd44")


def test_format_autodetect():
    intel = load_file(_DATA / "sample_stix.json", fmt="auto")
    assert intel.iocs  # sniffed as stix, IOCs extracted from patterns
