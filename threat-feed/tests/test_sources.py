import asyncio
import json

import httpx

from threatfeed.sources.bluesky import BlueskySource
from threatfeed.sources.demo import DemoSource
from threatfeed.sources.mastodon import MastodonSource
from threatfeed.sources.reddit import RedditSource
from threatfeed.sources.x import MAX_QUERY_LEN, XSource, build_queries


def run(source, handler):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await source.fetch(c)
    return asyncio.run(go())


def test_x_query_batching_respects_length_limit():
    qs = build_queries([f"researcher_{i:03d}" for i in range(60)], [])
    assert len(qs) > 1 and all(len(q) <= MAX_QUERY_LEN for q in qs)
    assert sum(q.count("from:") for q in qs) == 60


def test_x_parses_and_tracks_since_id():
    seen = []

    def handler(req):
        seen.append(dict(req.url.params))
        assert req.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json={
            "data": [{"id": "9", "text": "short", "note_tweet": {"text": "long full text"}, "author_id": "u1",
                      "created_at": "2026-10-01T12:00:00.000Z"}],
            "includes": {"users": [{"id": "u1", "username": "res", "name": "Res"}]},
            "meta": {"newest_id": "9"}})

    src = XSource("tok", ["res"])
    posts = run(src, handler)
    assert posts[0].text == "long full text" and posts[0].url == "https://x.com/res/status/9"
    run(src, handler)
    assert "since_id" not in seen[0] and seen[1]["since_id"] == "9"


def test_mastodon_parses_html_and_reblogs():
    status = {"uri": "https://i/1", "url": "https://i/@a/1", "created_at": "2026-10-01T12:00:00Z",
              "content": "<p>new <b>0day</b> &amp; stuff</p>", "spoiler_text": "",
              "account": {"acct": "a@i", "display_name": "A"}}

    def handler(req):
        assert req.url.path == "/api/v1/timelines/tag/malware"
        return httpx.Response(200, json=[{"reblog": status, "uri": "x", "account": {}}])

    posts = run(MastodonSource("infosec.exchange", ["#malware"], []), handler)
    assert posts[0].text == "new 0day & stuff" and posts[0].author_handle == "a@i"


def test_bluesky_builds_post_url():
    def handler(req):
        return httpx.Response(200, json={"posts": [{
            "uri": "at://did:plc:x/app.bsky.feed.post/3abc", "author": {"handle": "r.bsky.social"},
            "record": {"text": "ransomware wave", "createdAt": "2026-10-01T12:00:00Z"}}]})

    p = run(BlueskySource(["ransomware"]), handler)[0]
    assert p.url == "https://bsky.app/profile/r.bsky.social/post/3abc"


def test_reddit_parses():
    def handler(req):
        assert "netsec+blueteamsec" in req.url.path and req.headers["user-agent"] == "ua"
        return httpx.Response(200, json={"data": {"children": [{"data": {
            "name": "t3_a", "author": "bob", "permalink": "/r/netsec/a", "title": "T", "selftext": "S",
            "created_utc": 1.0}}]}})

    p = run(RedditSource(["r/netsec", "blueteamsec"], "ua"), handler)[0]
    assert p.text == "T\n\nS" and p.author_handle == "u/bob"


def test_demo_uses_only_reserved_indicators():
    from threatfeed.enrich import extract_iocs
    for p in DemoSource(seed=1).generate(50):
        i = extract_iocs(p.text)
        assert all(ip.startswith("203.0.113.") for ip in i.ipv4)
        assert all(d.endswith(".example") for d in i.domains)
        assert all(c.startswith("CVE-2026-9") for c in i.cves)
