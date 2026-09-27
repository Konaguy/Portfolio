from __future__ import annotations

from ti2kql.iocs import extract_iocs, refang
from ti2kql.schema import IOCType


def _values(iocs, t):
    return [i.value for i in iocs if i.type == t]


def test_refang_common_styles():
    assert refang("hxxps://bad[.]com") == "https://bad.com"
    assert refang("1.2.3[.]4") == "1.2.3.4"
    assert refang("user[at]evil[.]org") == "user@evil.org"


def test_extract_hashes_by_length():
    text = (
        "sha256 702421bcee1785d93271d311f0203da34cc936317e299575b06503945a6ea1e0 "
        "md5 44d88612fea8a8f36de82e1278abb02f "
        "sha1 6f1e6ab7e0f7e2c9d3b4a5c6d7e8f9a0b1c2d3e4"
    )
    iocs = extract_iocs(text)
    assert _values(iocs, IOCType.SHA256) == [
        "702421bcee1785d93271d311f0203da34cc936317e299575b06503945a6ea1e0"
    ]
    assert _values(iocs, IOCType.MD5) == ["44d88612fea8a8f36de82e1278abb02f"]
    assert _values(iocs, IOCType.SHA1) == ["6f1e6ab7e0f7e2c9d3b4a5c6d7e8f9a0b1c2d3e4"]


def test_hash_not_double_counted_as_shorter_hash():
    # A SHA256 contains 32- and 40-char substrings, but must not be reported
    # as MD5/SHA1 too.
    text = "702421bcee1785d93271d311f0203da34cc936317e299575b06503945a6ea1e0"
    iocs = extract_iocs(text)
    assert len(_values(iocs, IOCType.SHA256)) == 1
    assert _values(iocs, IOCType.MD5) == []
    assert _values(iocs, IOCType.SHA1) == []


def test_extract_defanged_ip_and_domain():
    text = "C2 at 148.113.152.144 and exfil hxxps://exfil-node[.]badactor[.]com/upload"
    iocs = extract_iocs(text)
    assert "148.113.152.144" in _values(iocs, IOCType.IPV4)
    assert any("badactor.com" in d for d in _values(iocs, IOCType.DOMAIN))
    assert any("exfil-node.badactor.com" in u for u in _values(iocs, IOCType.URL))


def test_extract_cve_and_registry_and_path():
    text = (
        r"Exploits CVE-2023-34362. Persists via HKLM\Software\Microsoft\Windows\CurrentVersion\Run "
        r"and drops C:\MOVEitTransfer\wwwroot\human2.aspx"
    )
    iocs = extract_iocs(text)
    assert _values(iocs, IOCType.CVE) == ["CVE-2023-34362"]
    assert any("CurrentVersion" in r for r in _values(iocs, IOCType.REGISTRY_KEY))
    assert any("human2.aspx" in p for p in _values(iocs, IOCType.FILE_PATH))


def test_common_infra_domains_filtered():
    iocs = extract_iocs("See https://www.microsoft.com and https://attack.mitre.org for details")
    assert _values(iocs, IOCType.DOMAIN) == []


def test_dedup():
    text = "1.2.3.4 1.2.3.4 1.2.3.4"
    iocs = extract_iocs(text)
    assert _values(iocs, IOCType.IPV4) == ["1.2.3.4"]
