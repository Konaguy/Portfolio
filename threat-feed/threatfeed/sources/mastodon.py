"""
Mastodon (e.g. infosec.exchange): public hashtag timelines plus specific
researcher accounts. No auth needed for public timelines on most instances.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ..enrich import html_to_text
from ..models import RawPost


def _parse(status: dict) -> RawPost:
    s = status.get("reblog") or status
    acct = s["account"]
    text = html_to_text(s.get("content", ""))
    if s.get("spoiler_text"):
        text = f"{s['spoiler_text']}\n{text}"
    return RawPost(
        source="mastodon", native_id=s["uri"], author=acct.get("display_name") or acct["acct"],
        author_handle=acct["acct"], url=s.get("url") or s["uri"], text=text,
        created_at=datetime.fromisoformat(s["created_at"].replace("Z", "+00:00")).timestamp(),
    )


class MastodonSource:
    name = "mastodon"

    def __init__(self, instance: str, hashtags: list[str], accounts: list[str]):
        self._base = instance.rstrip("/")
        if not self._base.startswith("http"):
            self._base = "https://" + self._base
        self._hashtags = [h.lstrip("#") for h in hashtags]
        self._accounts = accounts
        self._account_ids: dict[str, str] = {}

    async def _account_id(self, client: httpx.AsyncClient, acct: str) -> str | None:
        if acct not in self._account_ids:
            r = await client.get(f"{self._base}/api/v1/accounts/lookup", params={"acct": acct.lstrip("@")})
            if r.status_code != 200:
                return None
            self._account_ids[acct] = r.json()["id"]
        return self._account_ids[acct]

    async def fetch(self, client: httpx.AsyncClient) -> list[RawPost]:
        out: list[RawPost] = []
        for tag in self._hashtags:
            r = await client.get(f"{self._base}/api/v1/timelines/tag/{tag}", params={"limit": "40"})
            r.raise_for_status()
            out += [_parse(s) for s in r.json()]
        for acct in self._accounts:
            aid = await self._account_id(client, acct)
            if aid is None:
                continue
            r = await client.get(f"{self._base}/api/v1/accounts/{aid}/statuses",
                                 params={"limit": "40", "exclude_reblogs": "true"})
            r.raise_for_status()
            out += [_parse(s) for s in r.json()]
        return out
