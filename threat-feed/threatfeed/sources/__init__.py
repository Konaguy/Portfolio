"""
Source connectors. Each one turns a platform's API into RawPost objects.

A connector is stateful only in its cursor (e.g. X's since_id) so repeat
polls fetch just what is new; the store's primary key dedupes regardless.
Connectors receive an httpx.AsyncClient so tests can inject a MockTransport.
"""

from __future__ import annotations

from typing import Protocol

import httpx

from ..models import RawPost


class Source(Protocol):
    name: str

    async def fetch(self, client: httpx.AsyncClient) -> list[RawPost]: ...


def build_sources(settings, researchers: dict) -> list[Source]:
    from .bluesky import BlueskySource
    from .demo import DemoSource
    from .mastodon import MastodonSource
    from .reddit import RedditSource
    from .x import XSource

    sources: list[Source] = []
    x_handles = researchers.get("x", {}).get("handles", [])
    if settings.x_bearer_token and x_handles:
        sources.append(XSource(settings.x_bearer_token, x_handles, researchers["x"].get("keywords", [])))
    m = researchers.get("mastodon", {})
    if m.get("instance") and (m.get("hashtags") or m.get("accounts")):
        sources.append(MastodonSource(m["instance"], m.get("hashtags", []), m.get("accounts", [])))
    b = researchers.get("bluesky", {})
    if b.get("queries"):
        sources.append(BlueskySource(b["queries"], settings.bluesky_handle, settings.bluesky_app_password))
    r = researchers.get("reddit", {})
    if r.get("subreddits"):
        sources.append(RedditSource(r["subreddits"], settings.reddit_user_agent))
    if settings.demo_source:
        sources.append(DemoSource())
    return sources


def trusted_handles(researchers: dict) -> set[str]:
    """Curated researcher accounts get a severity boost (see enrich.score)."""
    handles = set()
    handles.update(h.lower().lstrip("@") for h in researchers.get("x", {}).get("handles", []))
    handles.update(a.lower().lstrip("@") for a in researchers.get("mastodon", {}).get("accounts", []))
    handles.update(h.lower().lstrip("@") for h in researchers.get("bluesky", {}).get("trusted", []))
    return handles
