from threatfeed.enrich import categorize, enrich, extract_iocs, html_to_text, refang
from threatfeed.models import RawPost

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def raw(text, handle="someone"):
    return RawPost("demo", "1", "Name", handle, "https://example.com/1", text, 0.0)


def test_defanged_network_indicators_are_extracted_and_refanged():
    i = extract_iocs("C2 evil-update[.]com, cdn.bad[.]net, 203.0.113[.]7, payload hxxps://dl.evil[.]com/a.exe")
    assert i.domains == ["evil-update.com", "cdn.bad.net"]
    assert i.ipv4 == ["203.0.113.7"]
    assert i.urls == ["https://dl.evil.com/a.exe"]


def test_plain_links_are_references_not_iocs():
    i = extract_iocs("writeup at https://github.com/x/y and see example.com")
    assert i.domains == [] and i.urls == []


def test_non_routable_ips_are_dropped():
    i = extract_iocs("lab box 10.0.0.5, 127.0.0.1, 192.168.1.1 vs scanner 8.8.8.8")
    assert i.ipv4 == ["8.8.8.8"]


def test_hash_lengths_are_not_double_counted():
    i = extract_iocs(f"{SHA256} {SHA1} {MD5}")
    assert i.sha256 == [SHA256] and i.sha1 == [SHA1] and i.md5 == [MD5]
    assert i.count() == 3


def test_cves_are_normalised_and_deduped():
    assert extract_iocs("cve-2026-1234 and CVE-2026-1234").cves == ["CVE-2026-1234"]


def test_cve_is_not_counted_as_an_ioc():
    assert extract_iocs("CVE-2026-1234").count() == 0


def test_categories():
    text = "Actively exploited 0day in the wild, ransomware crews dropping a backdoor"
    cats = categorize(text, extract_iocs(text))
    assert {"zero_day", "exploitation", "ransomware", "malware"} <= set(cats)


def test_cve_implies_vulnerability_category():
    assert categorize("look at CVE-2026-1234", extract_iocs("CVE-2026-1234")) == ["vulnerability"]


def test_severity_orders_sensibly():
    noise = enrich(raw("nice conference talk today"), 0).severity
    vuln = enrich(raw("patch CVE-2026-1234 RCE"), 0).severity
    zero = enrich(raw("CVE-2026-1234 0day actively exploited in the wild, CVSS 9.8, C2 203.0.113[.]5"), 0).severity
    assert noise < vuln < zero
    assert enrich(raw("x"), 0).severity == 0


def test_trusted_author_boost():
    t = "new malware loader"
    assert enrich(raw(t, "@Researcher"), 0, {"researcher"}).severity > enrich(raw(t), 0, {"researcher"}).severity


def test_hashtags_lowercased_and_deduped():
    assert enrich(raw("#Ransomware #ransomware #CVE"), 0).hashtags == ["ransomware", "cve"]


def test_html_to_text():
    assert html_to_text("<p>a &amp; b</p><p>c<br>d</p>") == "a & b\nc\nd"


def test_refang():
    assert refang("hxxp://a[.]b(.)c") == "http://a.b.c"
