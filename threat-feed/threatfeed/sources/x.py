"""
X (Twitter) API v2 recent search, filtered to curated researcher accounts.

Needs a paid X API tier (Basic or higher) bearer token -- this is the
costliest source to operate, which is why the tier policy makes it Pro-only.
Handles are batched so each query stays under the 512-char query limit.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ..models import RawPost

API = "https://api.x.com/2/tweets/search/recent"
MAX_QUERY_LEN = 512


def build_queries(handles: list[str], keywords: list[str]) -> list[str]:
    suffix = " -is:retweet"
    if keywords:
        suffix = " (" + " OR ".join(f'"{k}"' if " " in k else k for k in keywords) + ")" + suffix
    queries, current = [], []
    for h in handles:
        h = h.lstrip("@")
        candidate = current + [f"from:{h}"]
        q = "(" + " OR ".join(candidate) + ")" + suffix
        if len(q) > MAX_QUERY_LEN and current:
            queries.append("(" + " OR ".join(current) + ")" + suffix)
            current = [f"from:{h}"]
        else:
            current = candidate
    if current:
        queries.append("(" + " OR ".join(current) + ")" + suffix)
    return queries


class XSource:
    name = "x"

    def __init__(self, bearer_token: str, handles: list[str], keywords: list[str] | None = None):
        self._token = bearer_token
        self._queries = build_queries(handles, keywords or [])
        self._since: dict[str, str] = {}

    async def fetch(self, client: httpx.AsyncClient) -> list[RawPost]:
        out: list[RawPost] = []
        for q in self._queries:
            params = {
                "query": q,
                "max_results": "100",
                "tweet.fields": "created_at,author_id,note_tweet",
                "expansions": "author_id",
                "user.fields": "username,name",
            }
            if q in self._since:
                params["since_id"] = self._since[q]
            r = await client.get(API, params=params, headers={"Authorization": f"Bearer {self._token}"})
            r.raise_for_status()
            body = r.json()
            users = {u["id"]: u for u in body.get("includes", {}).get("users", [])}
            for t in body.get("data", []):
                u = users.get(t.get("author_id"), {})
                handle = u.get("username", "unknown")
                # Long posts carry full text in note_tweet; `text` is truncated.
                text = (t.get("note_tweet") or {}).get("text") or t["text"]
                out.append(RawPost(
                    source="x", native_id=t["id"], author=u.get("name", handle), author_handle=handle,
                    url=f"https://x.com/{handle}/status/{t['id']}", text=text,
                    created_at=datetime.fromisoformat(t["created_at"].replace("Z", "+00:00")).timestamp(),
                ))
            newest = body.get("meta", {}).get("newest_id")
            if newest:
                self._since[q] = newest
        return out
