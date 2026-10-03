"""
Single source of truth for what each plan gets.

Every gate in the app (API, stream, exports, ads, sources) reads from
TierPolicy rather than checking `tier == "pro"` inline, so changing what the
paid plan includes is a one-line edit here, and the pricing page renders from
the same data the gates enforce.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum


class Tier(str, Enum):
    FREE = "free"
    PRO = "pro"


@dataclass(frozen=True)
class TierPolicy:
    tier: Tier
    display_name: str
    # Posts become visible this many seconds after ingestion. Real-time is
    # the core thing Pro pays for, so Free sees the same feed, just later.
    feed_delay_seconds: int
    history_days: int
    page_size_max: int
    # Sources a tier can see. X's API is the expensive one to run, so it is
    # Pro-only; the open fediverse/Bluesky/Reddit sources are Free.
    sources: frozenset[str]
    realtime_stream: bool
    show_iocs: bool
    exports: bool
    max_watchlists: int
    api_keys: bool
    trends_limit: int
    # Insert one sponsored card after every N posts; 0 = no ads.
    ad_every_n_posts: int

    def public_dict(self) -> dict:
        d = asdict(self)
        d["tier"] = self.tier.value
        d["sources"] = sorted(self.sources)
        return d


ALL_SOURCES = frozenset({"x", "mastodon", "bluesky", "reddit", "demo"})

POLICIES: dict[Tier, TierPolicy] = {
    Tier.FREE: TierPolicy(
        tier=Tier.FREE,
        display_name="Free",
        feed_delay_seconds=15 * 60,
        history_days=1,
        page_size_max=50,
        sources=frozenset({"mastodon", "bluesky", "reddit", "demo"}),
        realtime_stream=False,
        show_iocs=False,
        exports=False,
        max_watchlists=0,
        api_keys=False,
        trends_limit=3,
        ad_every_n_posts=6,
    ),
    Tier.PRO: TierPolicy(
        tier=Tier.PRO,
        display_name="Pro",
        feed_delay_seconds=0,
        history_days=90,
        page_size_max=200,
        sources=ALL_SOURCES,
        realtime_stream=True,
        show_iocs=True,
        exports=True,
        max_watchlists=25,
        api_keys=True,
        trends_limit=25,
        ad_every_n_posts=0,
    ),
}


def policy_for(tier: Tier | str | None) -> TierPolicy:
    if tier is None:
        return POLICIES[Tier.FREE]
    try:
        return POLICIES[Tier(tier)]
    except ValueError:
        # Unknown tier string (e.g. a stale DB value) fails closed to Free.
        return POLICIES[Tier.FREE]
