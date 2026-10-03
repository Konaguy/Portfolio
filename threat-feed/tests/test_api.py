import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from threatfeed.ads import Ad, AdServer
from threatfeed.api import create_app
from threatfeed.config import Settings
from threatfeed.enrich import enrich
from threatfeed.models import RawPost
from threatfeed.store import Store

WEBHOOK_SECRET = "whsec_test"


def make_post(source, nid, text, age_seconds):
    t = time.time() - age_seconds
    return enrich(RawPost(source, nid, "Res", "res", f"https://example.com/{nid}", text, t), t)


@pytest.fixture
def store():
    s = Store(":memory:")
    posts = [make_post("demo", f"old{i}", f"CVE-2026-1234 0day exploited C2 evil{i}[.]example", 3600) for i in range(12)]
    posts.append(make_post("demo", "fresh", "fresh 0day hxxps://bad[.]example/x", 10))
    posts.append(make_post("x", "xpost", "X-only scoop evil[.]example", 3600))
    s.insert_posts(posts)
    return s


@pytest.fixture
def client(store):
    settings = Settings()
    settings.ingest_enabled = False
    settings.stripe_webhook_secret = WEBHOOK_SECRET
    settings.dev_billing = False
    ads = AdServer([Ad("a1", "Vendor", "H", "B", "Go", "https://vendor.example/")])
    app = create_app(settings, store=store, sources=[], ad_server=ads, researchers={})
    return TestClient(app)


def signup(client, email="a@b.co"):
    tok = client.post("/api/auth/signup", json={"email": email, "password": "correct horse"}).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


def make_pro(store, email="a@b.co"):
    store.set_tier(store.user_by_email(email)["id"], "pro")


def signed(payload: dict, secret=WEBHOOK_SECRET, ts=None):
    body = json.dumps(payload).encode()
    ts = ts or int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return body, {"stripe-signature": f"t={ts},v1={sig}", "content-type": "application/json"}


# ---- Free tier --------------------------------------------------------
def test_anonymous_is_free_with_delay_ads_and_locked_iocs(client):
    data = client.get("/api/feed").json()
    assert data["tier"] == "free" and data["delay_seconds"] == 900
    posts = [i for i in data["items"] if i["type"] == "post"]
    ads = [i for i in data["items"] if i["type"] == "ad"]
    ids = {p["id"] for p in posts}
    assert "demo:fresh" not in ids, "free must not see posts inside the delay window"
    assert "x:xpost" not in ids, "X is a Pro source"
    assert len(posts) == 12 and len(ads) == 2 and all(a["sponsored"] for a in ads)
    assert all("iocs" not in p and p["iocs_locked"] >= 1 for p in posts)
    assert posts[0]["cves"] == ["CVE-2026-1234"]


def test_free_cannot_use_pro_features(client):
    h = signup(client)
    assert client.get("/api/export/iocs.csv", headers=h).status_code == 402
    assert client.get("/api/export/stix", headers=h).status_code == 402
    assert client.post("/api/keys", headers=h, json={}).status_code == 402
    assert client.post("/api/watchlists", headers=h, json={"name": "w"}).status_code == 402
    assert client.get("/api/stream", headers=h).status_code == 402


def test_free_trends_are_capped(client):
    assert len(client.get("/api/trends").json()["trends"]) <= 3


def test_page_size_capped_by_tier(client):
    posts = [i for i in client.get("/api/feed?limit=200").json()["items"] if i["type"] == "post"]
    assert len(posts) <= 50


# ---- Pro tier ---------------------------------------------------------
def test_pro_sees_realtime_all_sources_full_iocs_no_ads(client, store):
    h = signup(client)
    make_pro(store)
    data = client.get("/api/feed", headers=h).json()
    ids = {i["id"] for i in data["items"]}
    assert {"demo:fresh", "x:xpost"} <= ids
    assert all(i["type"] == "post" for i in data["items"])
    fresh = next(i for i in data["items"] if i["id"] == "demo:fresh")
    assert fresh["iocs"]["urls"] == ["https://bad.example/x"]


def test_pro_exports(client, store):
    h = signup(client)
    make_pro(store)
    csv = client.get("/api/export/iocs.csv", headers=h).text
    assert csv.startswith("type,value") and "bad.example" in csv
    bundle = client.get("/api/export/stix", headers=h).json()
    assert bundle["type"] == "bundle"
    patterns = {o["pattern"] for o in bundle["objects"]}
    assert "[domain-name:value = 'evil0.example']" in patterns
    assert len(patterns) == len(bundle["objects"]), "indicators deduplicated"


def test_api_key_lifecycle_and_api_consumers_get_no_ads(client, store):
    h = signup(client)
    make_pro(store)
    key = client.post("/api/keys", headers=h, json={"label": "siem"}).json()["key"]
    kh = {"Authorization": f"Bearer {key}"}
    assert client.get("/api/feed", headers=kh).status_code == 200
    assert client.post("/api/keys", headers=kh, json={}).status_code == 403, "keys cannot mint keys"
    prefix = client.get("/api/keys", headers=h).json()["keys"][0]["prefix"]
    assert client.delete(f"/api/keys/{prefix}", headers=h).status_code == 200
    assert client.get("/api/feed", headers=kh).status_code == 401


def test_watchlist_limits_and_ssrf_guard(client, store):
    h = signup(client)
    make_pro(store)
    for bad in ["http://hooks.example.com/x", "https://127.0.0.1/x", "https://169.254.169.254/latest",
                "https://user:pw@hooks.example.com/"]:
        r = client.post("/api/watchlists", headers=h, json={"name": "w", "webhook_url": bad})
        assert r.status_code == 422, bad
    r = client.post("/api/watchlists", headers=h, json={"name": "VPN", "keywords": ["EdgeGate"], "min_severity": 50})
    assert r.status_code == 201
    assert client.get("/api/watchlists", headers=h).json()["watchlists"][0]["keywords"] == ["EdgeGate"]


# ---- Billing ----------------------------------------------------------
def test_stripe_webhook_upgrades_then_downgrades(client, store):
    h = signup(client)
    uid = store.user_by_email("a@b.co")["id"]
    body, hdr = signed({"id": "evt_1", "type": "checkout.session.completed",
                        "data": {"object": {"client_reference_id": str(uid), "customer": "cus_1", "subscription": "sub_1"}}})
    assert client.post("/api/billing/webhook", content=body, headers=hdr).json()["result"] == "upgraded"
    assert client.get("/api/me", headers=h).json()["tier"] == "pro"
    key = client.post("/api/keys", headers=h, json={}).json()["key"]

    # Replay of the same event id is ignored.
    assert client.post("/api/billing/webhook", content=body, headers=hdr).json()["result"] == "duplicate"

    body, hdr = signed({"id": "evt_2", "type": "customer.subscription.deleted",
                        "data": {"object": {"id": "sub_1", "customer": "cus_1", "status": "canceled"}}})
    assert client.post("/api/billing/webhook", content=body, headers=hdr).json()["result"] == "downgraded"
    assert client.get("/api/me", headers=h).json()["tier"] == "free"
    assert client.get("/api/feed", headers={"Authorization": f"Bearer {key}"}).status_code == 401, \
        "downgrade revokes API keys"


def test_stripe_webhook_rejects_bad_or_stale_signatures(client):
    payload = {"id": "evt_x", "type": "checkout.session.completed", "data": {"object": {"client_reference_id": "1"}}}
    body, hdr = signed(payload, secret="wrong")
    assert client.post("/api/billing/webhook", content=body, headers=hdr).status_code == 400
    body, hdr = signed(payload, ts=int(time.time()) - 3600)
    assert client.post("/api/billing/webhook", content=body, headers=hdr).status_code == 400
    assert client.post("/api/billing/webhook", content=b"{}").status_code == 400


def test_success_url_does_not_grant_pro(client):
    h = signup(client)
    client.get("/?upgraded=1")
    assert client.get("/api/me", headers=h).json()["tier"] == "free"


def test_dev_upgrade_disabled_by_default(client):
    assert client.post("/api/billing/dev-upgrade", headers=signup(client)).status_code == 404


def test_checkout_unconfigured_returns_503(client):
    assert client.post("/api/billing/checkout", headers=signup(client)).status_code == 503


# ---- Auth & ads -------------------------------------------------------
def test_auth_flow(client):
    signup(client)
    assert client.post("/api/auth/signup", json={"email": "A@b.co", "password": "correct horse"}).status_code == 409
    assert client.post("/api/auth/login", json={"email": "a@b.co", "password": "wrong password"}).status_code == 401
    tok = client.post("/api/auth/login", json={"email": "a@b.co", "password": "correct horse"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/me", headers=h).json()["email"] == "a@b.co"
    client.post("/api/auth/logout", headers=h)
    assert client.get("/api/me", headers=h).status_code == 401


def test_login_throttle(client):
    signup(client)
    for _ in range(5):
        client.post("/api/auth/login", json={"email": "a@b.co", "password": "wrong password"})
    r = client.post("/api/auth/login", json={"email": "a@b.co", "password": "correct horse"})
    assert r.status_code == 429


def test_ad_click_redirects_to_configured_url_only(client, store):
    r = client.get("/api/ads/a1/click", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "https://vendor.example/"
    assert client.get("/api/ads/nope/click", follow_redirects=False).status_code == 404
    client.get("/api/feed")
    stats = store.ad_stats()["a1"]
    assert stats["click"] == 1 and stats["impression"] == 2


def test_index_and_config(client):
    assert "Threat Feed" in client.get("/").text
    cfg = client.get("/api/config").json()
    assert cfg["tiers"]["free"]["ad_every_n_posts"] > 0 and cfg["tiers"]["pro"]["ad_every_n_posts"] == 0
