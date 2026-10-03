"""
Pro watchlists: keyword / CVE / severity rules that push matching posts to a
webhook (Slack, Teams and Discord-compatible `text` payload).

The webhook URL is user-supplied and fetched by our server, i.e. a classic
SSRF vector. validate_webhook_url() requires https and refuses any host that
resolves to a private, loopback, link-local or otherwise non-global address
(cloud metadata at 169.254.169.254 included). It is checked when the
watchlist is saved *and* again at delivery, since DNS can change.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import httpx

from .models import Post

log = logging.getLogger(__name__)


class WebhookURLError(ValueError):
    pass


def validate_webhook_url(url: str, resolve=socket.getaddrinfo) -> str:
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname:
        raise WebhookURLError("webhook URL must be https://")
    if p.username or p.password:
        raise WebhookURLError("credentials in webhook URL are not allowed")
    try:
        infos = resolve(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise WebhookURLError(f"cannot resolve {p.hostname}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise WebhookURLError("webhook host resolves to a non-public address")
    return url


def matches(post: Post, keywords: list[str], min_severity: int) -> bool:
    if post.severity < min_severity:
        return False
    if not keywords:
        return True
    hay = post.raw.text.lower()
    cves = {c.lower() for c in post.iocs.cves}
    return any(k.lower() in hay or k.lower() in cves for k in keywords)


def format_alert(post: Post, watchlist_name: str) -> dict:
    r = post.raw
    body = r.text if len(r.text) <= 500 else r.text[:497] + "..."
    return {
        "text": f"[Threat Feed · {watchlist_name}] {post.severity_label.upper()} ({post.severity}) "
                f"— @{r.author_handle} on {r.source}\n{body}\n{r.url}",
        "threatfeed": {
            "watchlist": watchlist_name, "id": r.id, "source": r.source, "author": r.author_handle,
            "url": r.url, "severity": post.severity, "categories": post.categories,
            "iocs": post.iocs.as_dict(),
        },
    }


class AlertDispatcher:
    def __init__(self, client: httpx.AsyncClient | None = None, resolve=socket.getaddrinfo):
        self._client = client
        self._resolve = resolve

    async def dispatch(self, posts: list[Post], watchlists: list[dict]) -> int:
        jobs = []
        for wl in watchlists:
            if not wl.get("webhook_url"):
                continue
            for p in posts:
                if matches(p, wl["keywords"], wl["min_severity"]):
                    jobs.append(self._send(wl["webhook_url"], format_alert(p, wl["name"])))
        results = await asyncio.gather(*jobs, return_exceptions=True)
        return sum(1 for r in results if r is True)

    async def _send(self, url: str, payload: dict) -> bool:
        try:
            validate_webhook_url(url, self._resolve)
            client = self._client or httpx.AsyncClient(timeout=10)
            try:
                # No redirects: a 30x to an internal host would bypass the check.
                r = await client.post(url, json=payload, follow_redirects=False)
            finally:
                if self._client is None:
                    await client.aclose()
            return r.is_success
        except Exception as e:  # noqa: BLE001 - one bad webhook must not stop the rest
            log.warning("webhook delivery failed: %s", e)
            return False
