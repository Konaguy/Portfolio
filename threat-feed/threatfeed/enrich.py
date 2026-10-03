"""
Deterministic enrichment: IOC extraction, categorisation, severity scoring.

Kept regex/keyword based on purpose: it runs on every post at ingest time,
must be explainable to an analyst ("why is this critical?"), and must never
invent an indicator. Two rules keep false positives down:

* A plain URL or domain in a post is treated as a *reference* (a blog link,
  a VirusTotal report). Only *defanged* network indicators (hxxp://,
  evil[.]com, 1.2.3[.]4) are extracted as IOCs -- researchers defang
  exactly the things that are malicious.
* Bare IPv4 addresses are IOCs only when routable; private, loopback and
  reserved ranges are dropped.
"""

from __future__ import annotations

import html
import ipaddress
import re

from .models import IOCs, Post, RawPost

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASHTAG_RE = re.compile(r"(?<![\w&])#([A-Za-z][\w]{1,49})")

_DOT = r"(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
# A defanged domain needs at least one bracketed dot somewhere in it.
DEFANGED_DOMAIN_RE = re.compile(
    rf"\b((?:[a-z0-9-]+(?:\.|{_DOT}))*[a-z0-9-]+{_DOT}(?:[a-z0-9-]+(?:\.|{_DOT}))*[a-z]{{2,24}})\b",
    re.IGNORECASE,
)
DEFANGED_URL_RE = re.compile(r"\b(hxxps?|fxp)\[?:\]?//[^\s<>\"']+", re.IGNORECASE)
IPV4_RE = re.compile(rf"\b(\d{{1,3}}(?:(?:\.|{_DOT})\d{{1,3}}){{3}})\b", re.IGNORECASE)

TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(s: str) -> str:
    """Mastodon delivers HTML; keep line breaks, drop tags, unescape entities."""
    s = re.sub(r"<br\s*/?>|</p>\s*<p>", "\n", s, flags=re.IGNORECASE)
    return html.unescape(TAG_RE.sub("", s)).strip()


def refang(s: str) -> str:
    s = re.sub(_DOT, ".", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp", "http", s, flags=re.IGNORECASE)
    s = re.sub(r"^fxp", "ftp", s, flags=re.IGNORECASE)
    return s.replace("[:]", ":")


def _dedupe(items) -> list[str]:
    return list(dict.fromkeys(items))


def extract_iocs(text: str) -> IOCs:
    cves = _dedupe(f"CVE-{m.group(1)}-{m.group(2)}" for m in CVE_RE.finditer(text))
    sha256 = _dedupe(h.lower() for h in SHA256_RE.findall(text))
    # Strip longer hashes before matching shorter ones so a sha256 is not
    # also reported as a sha1/md5 substring (word boundaries alone allow it
    # when hashes are adjacent to punctuation).
    rest = SHA256_RE.sub(" ", text)
    sha1 = _dedupe(h.lower() for h in SHA1_RE.findall(rest))
    rest = SHA1_RE.sub(" ", rest)
    md5 = _dedupe(h.lower() for h in MD5_RE.findall(rest))

    urls = _dedupe(refang(m.group(0)).rstrip(".,);]") for m in DEFANGED_URL_RE.finditer(text))
    no_urls = DEFANGED_URL_RE.sub(" ", text)

    ipv4: list[str] = []
    for m in IPV4_RE.finditer(no_urls):
        candidate = refang(m.group(1))
        try:
            ip = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if ip.is_global or _is_documentation(ip):
            ipv4.append(str(ip))
    ipv4 = _dedupe(ipv4)

    domains = []
    for m in DEFANGED_DOMAIN_RE.finditer(IPV4_RE.sub(" ", no_urls)):
        domains.append(refang(m.group(1)).lower())
    domains = _dedupe(domains)

    return IOCs(cves=cves, sha256=sha256, sha1=sha1, md5=md5, ipv4=ipv4, domains=domains, urls=urls)


_DOC_NETS = [ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _is_documentation(ip: ipaddress.IPv4Address) -> bool:
    # RFC 5737 ranges are what the demo source (and many write-ups) use;
    # keeping them lets the demo show IOC extraction without real infra.
    return any(ip in n for n in _DOC_NETS)


# category -> (keyword patterns, severity weight)
CATEGORY_RULES: dict[str, tuple[list[str], int]] = {
    "zero_day": ([r"\b0-?day\b", r"\bzero[- ]day\b", r"\bin[- ]the[- ]wild\b", r"\bITW\b", r"\bunpatched\b",
                  r"\bno patch\b"], 40),
    "exploitation": ([r"\bactively exploited\b", r"\bexploitation\b", r"\bexploited\b", r"\bPoC\b",
                      r"\bproof[- ]of[- ]concept\b", r"\bmass[- ]scann", r"\bKEV\b", r"\bexploit\b"], 25),
    "ransomware": ([r"\bransomware\b", r"\bencryptor\b", r"\bleak site\b", r"\bdouble extortion\b"], 25),
    "outbreak": ([r"\boutbreak\b", r"\bworm(?:able)?\b", r"\bbotnet\b", r"\bspreading\b", r"\bwave of\b",
                  r"\bsurge\b", r"\bcampaign\b", r"\bwiper\b"], 20),
    "malware": ([r"\bmalware\b", r"\binfostealer\b", r"\bstealer\b", r"\bloader\b", r"\bRAT\b",
                 r"\bbackdoor\b", r"\btrojan\b", r"\bC2\b", r"\bC&C\b", r"\bdropper\b", r"\bimplant\b"], 15),
    "supply_chain": ([r"\bsupply[- ]chain\b", r"\bmalicious (?:npm|pypi|package|extension)\b",
                      r"\btyposquat", r"\bcompromised (?:package|dependency|update)\b"], 25),
    "phishing": ([r"\bphish(?:ing)?\b", r"\bcredential harvest", r"\bAiTM\b", r"\bsmishing\b"], 10),
    "vulnerability": ([r"\bvulnerabilit(?:y|ies)\b", r"\bRCE\b", r"\bremote code execution\b",
                       r"\bprivilege escalation\b", r"\bauth(?:entication)? bypass\b", r"\bpatch(?:ed|es)?\b"], 10),
}
_COMPILED = {c: ([re.compile(p, re.IGNORECASE) for p in pats], w) for c, (pats, w) in CATEGORY_RULES.items()}
CATEGORIES = list(CATEGORY_RULES)

CRITICAL_HINT_RE = re.compile(r"\bcritical\b|\bCVSS\s*(?:v3(?:\.1)?\s*)?(?:score\s*)?(?:9\.\d|10(?:\.0)?)\b",
                              re.IGNORECASE)


def categorize(text: str, iocs: IOCs) -> list[str]:
    cats = [c for c, (pats, _) in _COMPILED.items() if any(p.search(text) for p in pats)]
    if iocs.cves and "vulnerability" not in cats:
        cats.append("vulnerability")
    return cats


def score(text: str, categories: list[str], iocs: IOCs, trusted_author: bool) -> int:
    s = sum(_COMPILED[c][1] for c in categories)
    if iocs.cves:
        s += 10
    s += min(iocs.count(), 5) * 3   # concrete indicators = actionable
    if CRITICAL_HINT_RE.search(text):
        s += 15
    if trusted_author:
        s += 10                     # on the curated researcher list
    return max(0, min(100, s))


def enrich(raw: RawPost, ingested_at: float, trusted_handles: set[str] | None = None) -> Post:
    text = raw.text
    iocs = extract_iocs(text)
    cats = categorize(text, iocs)
    trusted = bool(trusted_handles) and raw.author_handle.lower().lstrip("@") in trusted_handles
    hashtags = _dedupe(t.lower() for t in HASHTAG_RE.findall(text))
    return Post(
        raw=raw,
        ingested_at=ingested_at,
        categories=cats,
        severity=score(text, cats, iocs, trusted),
        iocs=iocs,
        hashtags=hashtags,
    )
