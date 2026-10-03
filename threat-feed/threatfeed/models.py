"""Core data shapes shared by sources, enrichment, storage and the API."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RawPost:
    """What a source connector yields, before enrichment."""

    source: str           # "x", "mastodon", "bluesky", "reddit", "demo"
    native_id: str        # the platform's own id, unique within a source
    author: str           # display name
    author_handle: str    # @handle / acct
    url: str
    text: str
    created_at: float     # epoch seconds, as reported by the platform

    @property
    def id(self) -> str:
        return f"{self.source}:{self.native_id}"


@dataclass
class IOCs:
    cves: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, list[str]]:
        return {k: list(v) for k, v in self.__dict__.items()}

    def count(self) -> int:
        """Indicators excluding CVE ids (a CVE is a vuln reference, not an IOC)."""
        return sum(len(v) for k, v in self.__dict__.items() if k != "cves")


@dataclass
class Post:
    """An enriched post as stored and served."""

    raw: RawPost
    ingested_at: float
    categories: list[str]
    severity: int          # 0-100
    iocs: IOCs
    hashtags: list[str]

    @property
    def severity_label(self) -> str:
        return severity_label(self.severity)


def severity_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
