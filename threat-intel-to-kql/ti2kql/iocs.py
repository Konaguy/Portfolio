"""
Deterministic IOC extraction from raw threat-intel text.

This is the part we do NOT trust an LLM with: pulling the exact indicators out
of the source is a precision job, and getting a hash wrong by one character
makes a hunt useless. The LLM's job is to turn these extracted indicators into
good queries; the indicators themselves come from here.

Handles common defanging (`hxxp`, `[.]`, `(.)`, `[at]`) so indicators copied
from reports are recognized and re-fanged to their real form.
"""

from __future__ import annotations

import re

from .schema import IOC, IOCType

# Refang: undo common defang styles before matching.
_DEFANG_SUBS = [
    (re.compile(r"h(?:xx|XX)p", re.IGNORECASE), "http"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*at\s*\]", re.IGNORECASE), "@"),
    (re.compile(r"\[\s*@\s*\]"), "@"),
]

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>]+", re.IGNORECASE
)
_FILE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+\.[A-Za-z0-9]{1,6}"
)

# Domains that are almost always noise in TI reports.
_DOMAIN_STOPLIST = {
    "microsoft.com", "windows.com", "google.com", "github.com", "virustotal.com",
    "mitre.org", "attack.mitre.org", "cve.mitre.org", "nvd.nist.gov",
}


def refang(text: str) -> str:
    for pattern, repl in _DEFANG_SUBS:
        text = pattern.sub(repl, text)
    return text


def _domain_from_url(url: str) -> str | None:
    m = re.match(r"https?://([^/:\s]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _is_stoplisted_domain(domain: str) -> bool:
    """True if the domain is, or is a subdomain of, a stoplisted domain."""
    return any(domain == s or domain.endswith("." + s) for s in _DOMAIN_STOPLIST)


def extract_iocs(text: str) -> list[IOC]:
    """Extract and de-duplicate IOCs from raw intel text, preserving order of
    first appearance within each type."""
    fanged = refang(text)
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: IOCType, value: str) -> None:
        key = (ioc_type.value, value.lower())
        if key not in seen:
            seen.add(key)
            found.append(IOC(type=ioc_type, value=value))

    # Order matters: match longer/more-specific patterns first and mask them
    # so a SHA256 isn't also picked up as an MD5 substring, etc.
    masked = fanged

    for m in _CVE_RE.findall(masked):
        add(IOCType.CVE, m.upper())

    for m in _REGISTRY_RE.findall(masked):
        add(IOCType.REGISTRY_KEY, m)
    masked = _REGISTRY_RE.sub(" ", masked)

    for m in _FILE_PATH_RE.findall(masked):
        add(IOCType.FILE_PATH, m)
    masked = _FILE_PATH_RE.sub(" ", masked)

    for m in _SHA256_RE.findall(masked):
        add(IOCType.SHA256, m.lower())
    masked = _SHA256_RE.sub(" ", masked)

    for m in _SHA1_RE.findall(masked):
        add(IOCType.SHA1, m.lower())
    masked = _SHA1_RE.sub(" ", masked)

    for m in _MD5_RE.findall(masked):
        add(IOCType.MD5, m.lower())
    masked = _MD5_RE.sub(" ", masked)

    urls = _URL_RE.findall(masked)
    for u in urls:
        add(IOCType.URL, u.rstrip(".,);"))
    # Take domains from URLs before masking them out.
    url_domains = {d for u in urls if (d := _domain_from_url(u))}
    masked = _URL_RE.sub(" ", masked)

    for m in _EMAIL_RE.findall(masked):
        add(IOCType.EMAIL, m.lower())
    masked = _EMAIL_RE.sub(" ", masked)

    for m in _IPV4_RE.findall(masked):
        add(IOCType.IPV4, m)
    masked = _IPV4_RE.sub(" ", masked)

    for m in _IPV6_RE.findall(masked):
        if ":" in m and not re.fullmatch(r"[A-Fa-f0-9:]+", m) is None and m.count(":") >= 2:
            add(IOCType.IPV6, m.lower())

    for d in url_domains:
        if not _is_stoplisted_domain(d):
            add(IOCType.DOMAIN, d)
    for m in _DOMAIN_RE.findall(masked):
        d = m.lower()
        if _is_stoplisted_domain(d):
            continue
        # Skip things that are really file names (e.g. "invoice.exe").
        if d.rsplit(".", 1)[-1] in _COMMON_FILE_EXT:
            continue
        add(IOCType.DOMAIN, d)

    return found


_COMMON_FILE_EXT = {
    "exe", "dll", "js", "vbs", "ps1", "bat", "cmd", "scr", "hta", "docx", "xlsx",
    "pdf", "zip", "rar", "iso", "img", "lnk", "bin", "dat", "tmp", "png", "jpg",
}
