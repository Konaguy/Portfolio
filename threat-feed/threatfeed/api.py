"""
FastAPI app. Built by create_app() so tests can pass an in-memory store and
fake sources; `uvicorn threatfeed.api:app` uses the env-configured default.

Tier enforcement happens server-side in every handler via the viewer's
TierPolicy -- the frontend only *reflects* the policy, it never enforces it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, billing
from .ads import AdServer
from .alerts import WebhookURLError, validate_webhook_url
from .broker import Broker
from .config import Settings, load_json
from .enrich import CATEGORIES
from .exports import to_csv, to_stix_bundle
from .ingest import Ingestor
from .serialize import post_json
from .sources import Source, build_sources, trusted_handles
from .store import Store
from .tiers import POLICIES, Tier, TierPolicy, policy_for
from .trends import detect_trends

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class Viewer:
    user: Any | None            # sqlite Row or None for anonymous
    policy: TierPolicy
    via_api_key: bool = False

    @property
    def user_id(self) -> int | None:
        return self.user["id"] if self.user is not None else None


class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=10, max_length=256)


class WatchlistIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    keywords: list[str] = Field(default_factory=list, max_length=50)
    min_severity: int = Field(default=0, ge=0, le=100)
    webhook_url: str | None = Field(default=None, max_length=2048)


class ApiKeyIn(BaseModel):
    label: str = Field(default="", max_length=80)


def create_app(settings: Settings | None = None, *, store: Store | None = None,
               sources: list[Source] | None = None, ad_server: AdServer | None = None,
               researchers: dict | None = None) -> FastAPI:
    settings = settings or Settings()
    store = store or Store(settings.db_path)
    if researchers is None:
        try:
            researchers = load_json(settings.researchers_path)
        except FileNotFoundError:
            researchers = {}
    sources = sources if sources is not None else build_sources(settings, researchers)
    broker = Broker()
    ingestor = Ingestor(store, broker, sources, trusted_handles(researchers))
    ad_server = ad_server or AdServer.from_file(settings.ads_path, settings.ethicalads_publisher)
    failed_logins: dict[str, list[float]] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = None
        if settings.ingest_enabled and sources:
            task = asyncio.create_task(ingestor.run_forever(settings.poll_interval_seconds))
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Threat Feed", version="0.1.0", lifespan=lifespan)
    app.state.store, app.state.ingestor, app.state.broker = store, ingestor, broker
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # ---- identity ------------------------------------------------------
    def resolve_token(token: str | None) -> Viewer:
        if not token:
            return Viewer(None, policy_for(Tier.FREE))
        found = store.token_user(auth.token_hash(token))
        if found is None:
            raise HTTPException(401, "invalid or expired token")
        user, kind = found
        policy = policy_for(user["tier"])
        if kind == "api" and not policy.api_keys:
            raise HTTPException(403, "API access requires Pro")
        return Viewer(user, policy, via_api_key=(kind == "api"))

    def viewer(request: Request) -> Viewer:
        h = request.headers.get("authorization", "")
        return resolve_token(h[7:].strip() if h.lower().startswith("bearer ") else None)

    def require_user(v: Viewer = Depends(viewer)) -> Viewer:
        if v.user is None:
            raise HTTPException(401, "sign in required")
        return v

    def require(feature: str):
        def dep(v: Viewer = Depends(require_user)) -> Viewer:
            if not getattr(v.policy, feature):
                raise HTTPException(402, f"'{feature}' is a Pro feature")
            return v
        return dep

    # ---- pages & config ------------------------------------------------
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/config")
    def config():
        return {
            "tiers": {t.value: p.public_dict() for t, p in POLICIES.items()},
            "pro_price": settings.pro_price_display,
            "checkout_available": bool(settings.stripe_secret_key and settings.stripe_pro_price_id),
            "dev_billing": settings.dev_billing,
            "categories": CATEGORIES,
            "ad_network": ad_server.network or None,
        }

    @app.get("/api/health")
    def health():
        return {"ok": True, "sources": [s.name for s in sources], "source_errors": ingestor.last_errors,
                "stream_subscribers": broker.subscriber_count}

    # ---- auth ----------------------------------------------------------
    def _session(user_id: int) -> str:
        tok = auth.new_session_token()
        store.add_token(auth.token_hash(tok), user_id, "session", expires_at=time.time() + auth.SESSION_TTL_SECONDS)
        return tok

    @app.post("/api/auth/signup")
    def signup(c: Credentials):
        email = c.email.strip().lower()
        if not EMAIL_RE.match(email):
            raise HTTPException(422, "invalid email")
        if store.user_by_email(email):
            raise HTTPException(409, "account already exists")
        uid = store.create_user(email, auth.hash_password(c.password))
        return {"token": _session(uid)}

    @app.post("/api/auth/login")
    def login(c: Credentials):
        email = c.email.strip().lower()
        now = time.time()
        recent = [t for t in failed_logins.get(email, []) if now - t < 900]
        if len(recent) >= 5:
            raise HTTPException(429, "too many attempts, try again later")
        user = store.user_by_email(email)
        if user is None or not auth.verify_password(c.password, user["password_hash"]):
            failed_logins[email] = recent + [now]
            raise HTTPException(401, "invalid email or password")
        failed_logins.pop(email, None)
        return {"token": _session(user["id"])}

    @app.post("/api/auth/logout")
    def logout(request: Request, v: Viewer = Depends(require_user)):
        store.delete_token(auth.token_hash(request.headers["authorization"][7:].strip()))
        return {"ok": True}

    @app.get("/api/me")
    def me(v: Viewer = Depends(viewer)):
        return {
            "email": v.user["email"] if v.user is not None else None,
            "tier": v.policy.tier.value,
            "policy": v.policy.public_dict(),
            "has_billing_account": bool(v.user is not None and v.user["stripe_customer_id"]),
        }

    # ---- feed ----------------------------------------------------------
    def _query(v: Viewer, *, limit: int, before: float | None, category: str | None, min_severity: int,
               q: str | None, source: str | None, since: float | None = None):
        now = time.time()
        p = v.policy
        srcs = p.sources & ({source} if source else p.sources)
        floor = now - p.history_days * 86400
        return store.query_posts(
            sources=srcs, visible_before=now - p.feed_delay_seconds,
            since=max(floor, since) if since else floor,
            limit=min(limit, p.page_size_max), before=before, category=category,
            min_severity=min_severity, search=q,
        )

    @app.get("/api/feed")
    def feed(
        v: Viewer = Depends(viewer),
        limit: int = Query(50, ge=1, le=200),
        before: float | None = None,
        category: str | None = None,
        min_severity: int = Query(0, ge=0, le=100),
        q: str | None = Query(None, max_length=200),
        source: str | None = None,
    ):
        posts = _query(v, limit=limit, before=before, category=category, min_severity=min_severity, q=q,
                       source=source)
        items = [post_json(p, v.policy) for p in posts]
        if not v.via_api_key:   # API consumers never get ad cards in their data
            items = ad_server.interleave(items, v.policy.ad_every_n_posts)
            for it in items:
                if it["type"] == "ad" and "id" in it:
                    store.record_ad_event(it["id"], "impression")
        return {
            "tier": v.policy.tier.value,
            "delay_seconds": v.policy.feed_delay_seconds,
            "items": items,
            "next_before": posts[-1].ingested_at if posts else None,
        }

    @app.get("/api/trends")
    def trends(v: Viewer = Depends(viewer)):
        now = time.time() - v.policy.feed_delay_seconds
        posts = [p for p in store.posts_since(now - 8 * 86400) if p.raw.source in v.policy.sources]
        found = detect_trends(posts, now)
        return {"trends": [t.as_dict() for t in found[: v.policy.trends_limit]],
                "hidden": max(0, len(found) - v.policy.trends_limit)}

    @app.get("/api/stream")
    async def stream(request: Request, token: str | None = None):
        # EventSource cannot set headers, so the stream accepts ?token=.
        h = request.headers.get("authorization", "")
        v = resolve_token(token or (h[7:].strip() if h.lower().startswith("bearer ") else None))
        if not v.policy.realtime_stream:
            raise HTTPException(402, "real-time stream is a Pro feature")
        q = broker.subscribe()

        async def events():
            try:
                yield "retry: 5000\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(q.get(), timeout=15)
                        if item["source"] in v.policy.sources:
                            yield f"event: post\ndata: {json.dumps(item)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                broker.unsubscribe(q)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ---- Pro: exports --------------------------------------------------
    @app.get("/api/export/iocs.csv")
    def export_csv(v: Viewer = Depends(require("exports")), hours: int = Query(24, ge=1, le=24 * 90),
                   min_severity: int = Query(0, ge=0, le=100)):
        posts = _query(v, limit=v.policy.page_size_max * 50, before=None, category=None,
                       min_severity=min_severity, q=None, source=None, since=time.time() - hours * 3600)
        return PlainTextResponse(to_csv(posts), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=threatfeed-iocs.csv"})

    @app.get("/api/export/stix")
    def export_stix(v: Viewer = Depends(require("exports")), hours: int = Query(24, ge=1, le=24 * 90),
                    min_severity: int = Query(0, ge=0, le=100)):
        posts = _query(v, limit=v.policy.page_size_max * 50, before=None, category=None,
                       min_severity=min_severity, q=None, source=None, since=time.time() - hours * 3600)
        return JSONResponse(to_stix_bundle(posts),
                            headers={"Content-Disposition": "attachment; filename=threatfeed-stix.json"})

    # ---- Pro: watchlists ----------------------------------------------
    @app.get("/api/watchlists")
    def list_watchlists(v: Viewer = Depends(require_user)):
        return {"watchlists": store.list_watchlists(v.user_id), "max": v.policy.max_watchlists}

    @app.post("/api/watchlists", status_code=201)
    def create_watchlist(w: WatchlistIn, v: Viewer = Depends(require_user)):
        existing = store.list_watchlists(v.user_id)
        if len(existing) >= v.policy.max_watchlists:
            raise HTTPException(402, f"your plan allows {v.policy.max_watchlists} watchlists")
        if w.webhook_url:
            try:
                validate_webhook_url(w.webhook_url)
            except WebhookURLError as e:
                raise HTTPException(422, str(e)) from e
        kws = [k.strip()[:100] for k in w.keywords if k.strip()]
        wid = store.create_watchlist(v.user_id, w.name.strip(), kws, w.min_severity, w.webhook_url)
        return {"id": wid}

    @app.delete("/api/watchlists/{wl_id}")
    def delete_watchlist(wl_id: int, v: Viewer = Depends(require_user)):
        if not store.delete_watchlist(v.user_id, wl_id):
            raise HTTPException(404, "not found")
        return {"ok": True}

    # ---- Pro: API keys -------------------------------------------------
    @app.get("/api/keys")
    def list_keys(v: Viewer = Depends(require("api_keys"))):
        return {"keys": [dict(r) for r in store.list_api_keys(v.user_id)]}

    @app.post("/api/keys", status_code=201)
    def create_key(body: ApiKeyIn, v: Viewer = Depends(require("api_keys"))):
        if v.via_api_key:
            raise HTTPException(403, "API keys cannot mint API keys")
        key, prefix = auth.new_api_key()
        store.add_token(auth.token_hash(key), v.user_id, "api", label=body.label or None, prefix=prefix)
        return {"key": key, "prefix": prefix, "note": "Shown once. Store it securely."}

    @app.delete("/api/keys/{prefix}")
    def delete_key(prefix: str, v: Viewer = Depends(require_user)):
        if not store.delete_api_key(v.user_id, prefix):
            raise HTTPException(404, "not found")
        return {"ok": True}

    # ---- billing -------------------------------------------------------
    @app.post("/api/billing/checkout")
    async def checkout(v: Viewer = Depends(require_user)):
        if v.policy.tier == Tier.PRO:
            raise HTTPException(409, "already on Pro")
        if not (settings.stripe_secret_key and settings.stripe_pro_price_id):
            raise HTTPException(503, "billing not configured")
        async with httpx.AsyncClient(timeout=15) as client:
            url = await billing.create_checkout_session(
                client, secret_key=settings.stripe_secret_key, price_id=settings.stripe_pro_price_id,
                user_id=v.user_id, email=v.user["email"], customer_id=v.user["stripe_customer_id"],
                base_url=settings.base_url)
        return {"url": url}

    @app.post("/api/billing/portal")
    async def portal(v: Viewer = Depends(require_user)):
        if not (settings.stripe_secret_key and v.user["stripe_customer_id"]):
            raise HTTPException(404, "no billing account")
        async with httpx.AsyncClient(timeout=15) as client:
            url = await billing.create_portal_session(
                client, secret_key=settings.stripe_secret_key, customer_id=v.user["stripe_customer_id"],
                base_url=settings.base_url)
        return {"url": url}

    @app.post("/api/billing/webhook", include_in_schema=False)
    async def stripe_webhook(request: Request):
        payload = await request.body()
        try:
            event = billing.verify_stripe_signature(
                payload, request.headers.get("stripe-signature", ""), settings.stripe_webhook_secret)
        except billing.SignatureError as e:
            raise HTTPException(400, str(e)) from e
        return {"result": billing.apply_event(store, event)}

    @app.post("/api/billing/dev-upgrade", include_in_schema=False)
    def dev_upgrade(v: Viewer = Depends(require_user)):
        # Local development only: toggles tier without Stripe. Off by default.
        if not settings.dev_billing:
            raise HTTPException(404)
        new = "free" if v.policy.tier == Tier.PRO else "pro"
        store.set_tier(v.user_id, new)
        if new == "free":
            store.delete_api_keys(v.user_id)
        return {"tier": new}

    # ---- ads -----------------------------------------------------------
    @app.get("/api/ads/{ad_id}/click", include_in_schema=False)
    def ad_click(ad_id: str):
        ad = ad_server.ads.get(ad_id)
        if ad is None:
            raise HTTPException(404)
        store.record_ad_event(ad_id, "click")
        # Redirect only to the configured landing URL (never a query param),
        # so this endpoint cannot be used as an open redirect.
        return RedirectResponse(ad.url, status_code=302)

    return app


app = create_app()
