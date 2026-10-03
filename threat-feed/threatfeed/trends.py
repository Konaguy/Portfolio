"""
Trend / outbreak detection over the recent window.

For each term (CVE id, hashtag, category) compare mentions in the recent
window against the rate expected from the baseline window. A term trends
when it is both *frequent* (>= min_mentions) and *broad* (>= min_authors
distinct accounts) -- the author floor stops one prolific account from
manufacturing a "trend" by posting about the same thing ten times.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .models import Post

GENERIC_HASHTAGS = {"infosec", "cybersecurity", "security", "threatintel", "cti", "malware", "cve",
                    "vulnerability", "dfir", "ransomware", "0day", "zeroday", "threathunting", "blueteam"}


@dataclass
class Trend:
    term: str
    kind: str            # "cve" | "hashtag" | "category"
    recent: int
    baseline_rate: float  # expected mentions per recent window
    authors: int
    score: float
    max_severity: int

    def as_dict(self) -> dict:
        return {**self.__dict__, "baseline_rate": round(self.baseline_rate, 2), "score": round(self.score, 2)}


def _terms(p: Post) -> list[tuple[str, str]]:
    terms = [(c, "cve") for c in p.iocs.cves]
    terms += [(f"#{h}", "hashtag") for h in p.hashtags if h not in GENERIC_HASHTAGS]
    terms += [(c, "category") for c in p.categories]
    return terms


def detect_trends(
    posts: list[Post],
    now: float,
    *,
    window_seconds: float = 6 * 3600,
    baseline_seconds: float = 7 * 24 * 3600,
    min_mentions: int = 3,
    min_authors: int = 2,
) -> list[Trend]:
    recent_start = now - window_seconds
    base_start = recent_start - baseline_seconds
    recent: dict[tuple[str, str], int] = defaultdict(int)
    base: dict[tuple[str, str], int] = defaultdict(int)
    authors: dict[tuple[str, str], set[str]] = defaultdict(set)
    sev: dict[tuple[str, str], int] = defaultdict(int)

    for p in posts:
        t = p.ingested_at
        for key in set(_terms(p)):
            if recent_start <= t <= now:
                recent[key] += 1
                authors[key].add(f"{p.raw.source}:{p.raw.author_handle.lower()}")
                sev[key] = max(sev[key], p.severity)
            elif base_start <= t < recent_start:
                base[key] += 1

    windows_in_baseline = baseline_seconds / window_seconds
    out = []
    for key, n in recent.items():
        if n < min_mentions or len(authors[key]) < min_authors:
            continue
        expected = base[key] / windows_in_baseline
        # +1 smoothing: a brand-new term with 5 mentions scores 6, not infinity.
        s = (n + 1) / (expected + 1)
        out.append(Trend(key[0], key[1], n, expected, len(authors[key]), s, sev[key]))
    # Categories are always "present"; rank specific terms (CVEs, campaign
    # hashtags) ahead of them when scores tie.
    out.sort(key=lambda tr: (tr.score, tr.kind != "category", tr.recent), reverse=True)
    return out
