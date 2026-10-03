import asyncio
import socket

import httpx

from threatfeed.alerts import AlertDispatcher, WebhookURLError, matches, validate_webhook_url
from threatfeed.broker import Broker
from threatfeed.enrich import enrich
from threatfeed.ingest import Ingestor
from threatfeed.models import RawPost
from threatfeed.store import Store


def fake_resolve(ip):
    return lambda host, port, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


class FakeSource:
    name = "demo"

    def __init__(self, posts):
        self.posts = posts

    async def fetch(self, client):
        return self.posts


class BrokenSource:
    name = "x"

    async def fetch(self, client):
        raise httpx.HTTPStatusError("429", request=None, response=None)


def raw(nid, text):
    return RawPost("demo", nid, "A", "a", "https://e.com", text, 0.0)


def test_ingest_dedupes_publishes_and_survives_a_failing_source():
    store, broker = Store(), Broker()
    ing = Ingestor(store, broker, [FakeSource([raw("1", "0day exploited"), raw("2", "hi")]), BrokenSource()], set())

    async def go():
        q = broker.subscribe()
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
            first = await ing.run_once(c)
            second = await ing.run_once(c)
        return first, second, q.qsize()

    first, second, published = asyncio.run(go())
    assert (first, second, published) == (2, 0, 2)
    assert "x" in ing.last_errors


def test_watchlist_matching():
    p = enrich(raw("1", "EdgeGate CVE-2026-1111 exploited"), 0)
    assert matches(p, ["edgegate"], 0)
    assert matches(p, ["cve-2026-1111"], 0)
    assert not matches(p, ["fortios"], 0)
    assert not matches(p, ["edgegate"], 99)


def test_webhook_url_validation():
    assert validate_webhook_url("https://hooks.example.com/x", fake_resolve("93.184.216.34"))
    for ip in ["10.0.0.1", "127.0.0.1", "169.254.169.254", "::1"]:
        try:
            validate_webhook_url("https://hooks.example.com/x", fake_resolve(ip))
            raise AssertionError(ip)
        except WebhookURLError:
            pass


def test_dispatcher_delivers_and_rechecks_dns():
    sent = []

    def handler(req):
        sent.append(req)
        return httpx.Response(200)

    p = enrich(raw("1", "EdgeGate 0day"), 0)
    wl = [{"name": "VPN", "keywords": ["edgegate"], "min_severity": 0, "webhook_url": "https://hooks.example.com/x"}]

    async def go(ip):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await AlertDispatcher(c, fake_resolve(ip)).dispatch([p], wl)

    assert asyncio.run(go("93.184.216.34")) == 1
    assert b"EdgeGate" in sent[0].content
    # DNS now points inside the network (rebinding): delivery is refused.
    assert asyncio.run(go("10.0.0.1")) == 0 and len(sent) == 1


def test_lapsed_pro_watchlists_stop_alerting():
    s = Store()
    uid = s.create_user("a@b.co", "x")
    s.create_watchlist(uid, "w", [], 0, None)
    assert s.active_watchlists() == []
    s.set_tier(uid, "pro")
    assert len(s.active_watchlists()) == 1
