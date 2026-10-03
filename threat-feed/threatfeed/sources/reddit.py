"""Reddit: newest posts from security subreddits (r/netsec, r/blueteamsec, ...)."""

from __future__ import annotations

import httpx

from ..models import RawPost


class RedditSource:
    name = "reddit"

    def __init__(self, subreddits: list[str], user_agent: str):
        self._path = "+".join(s.removeprefix("r/") for s in subreddits)
        self._ua = user_agent

    async def fetch(self, client: httpx.AsyncClient) -> list[RawPost]:
        r = await client.get(f"https://www.reddit.com/r/{self._path}/new.json",
                             params={"limit": "50", "raw_json": "1"}, headers={"User-Agent": self._ua})
        r.raise_for_status()
        out = []
        for child in r.json().get("data", {}).get("children", []):
            d = child["data"]
            text = d["title"] + ("\n\n" + d["selftext"] if d.get("selftext") else "")
            out.append(RawPost(
                source="reddit", native_id=d["name"], author=d["author"], author_handle=f"u/{d['author']}",
                url="https://www.reddit.com" + d["permalink"], text=text[:4000], created_at=float(d["created_utc"]),
            ))
        return out
