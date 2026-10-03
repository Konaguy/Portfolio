"""
Bluesky search. Unauthenticated search on the public AppView is rate-limited
and sometimes refused, so an app password (BLUESKY_HANDLE /
BLUESKY_APP_PASSWORD) is used when configured.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ..models import RawPost

PUBLIC = "https://public.api.bsky.app/xrpc"
PDS = "https://bsky.social/xrpc"


def _parse(item: dict) -> RawPost:
    author = item["author"]
    rkey = item["uri"].rsplit("/", 1)[-1]
    created = item.get("record", {}).get("createdAt") or item.get("indexedAt")
    return RawPost(
        source="bluesky", native_id=item["uri"], author=author.get("displayName") or author["handle"],
        author_handle=author["handle"], url=f"https://bsky.app/profile/{author['handle']}/post/{rkey}",
        text=item.get("record", {}).get("text", ""),
        created_at=datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp(),
    )


class BlueskySource:
    name = "bluesky"

    def __init__(self, queries: list[str], handle: str = "", app_password: str = ""):
        self._queries = queries
        self._handle = handle
        self._password = app_password
        self._jwt: str | None = None

    async def _auth(self, client: httpx.AsyncClient) -> dict[str, str]:
        if not (self._handle and self._password):
            return {}
        if self._jwt is None:
            r = await client.post(f"{PDS}/com.atproto.server.createSession",
                                  json={"identifier": self._handle, "password": self._password})
            r.raise_for_status()
            self._jwt = r.json()["accessJwt"]
        return {"Authorization": f"Bearer {self._jwt}"}

    async def fetch(self, client: httpx.AsyncClient) -> list[RawPost]:
        headers = await self._auth(client)
        base = PDS if headers else PUBLIC
        out: list[RawPost] = []
        for q in self._queries:
            r = await client.get(f"{base}/app.bsky.feed.searchPosts",
                                 params={"q": q, "limit": "50", "sort": "latest"}, headers=headers)
            if r.status_code == 401 and headers:
                self._jwt = None  # expired session; re-auth next poll
            r.raise_for_status()
            out += [_parse(p) for p in r.json().get("posts", [])]
        return out
