"""Poll every source, enrich, store, then fan out to the stream and watchlists."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from .alerts import AlertDispatcher
from .broker import Broker
from .enrich import enrich
from .serialize import post_json
from .sources import Source
from .store import Store
from .tiers import Tier, policy_for

log = logging.getLogger(__name__)

RETENTION_DAYS = 90


class Ingestor:
    def __init__(self, store: Store, broker: Broker, sources: list[Source], trusted: set[str],
                 dispatcher: AlertDispatcher | None = None):
        self.store = store
        self.broker = broker
        self.sources = sources
        self.trusted = trusted
        self.dispatcher = dispatcher or AlertDispatcher()
        self.last_errors: dict[str, str] = {}

    async def run_once(self, client: httpx.AsyncClient) -> int:
        results = await asyncio.gather(*(s.fetch(client) for s in self.sources), return_exceptions=True)
        now = time.time()
        enriched = []
        for src, res in zip(self.sources, results):
            if isinstance(res, BaseException):
                # One failing platform (rate limit, outage) must not stall the rest.
                self.last_errors[src.name] = f"{type(res).__name__}: {res}"
                log.warning("source %s failed: %s", src.name, res)
                continue
            self.last_errors.pop(src.name, None)
            enriched += [enrich(raw, now, self.trusted) for raw in res if raw.text.strip()]

        new = self.store.insert_posts(enriched)
        if new:
            pro = policy_for(Tier.PRO)
            for p in sorted(new, key=lambda p: p.raw.created_at):
                self.broker.publish(post_json(p, pro))
            await self.dispatcher.dispatch(new, self.store.active_watchlists())
        self.store.prune_posts(now - RETENTION_DAYS * 86400)
        return len(new)

    async def run_forever(self, interval: int) -> None:
        async with httpx.AsyncClient(timeout=20, headers={"Accept": "application/json"}) as client:
            while True:
                try:
                    n = await self.run_once(client)
                    log.info("ingested %d new posts", n)
                except Exception:  # noqa: BLE001
                    log.exception("ingest cycle failed")
                await asyncio.sleep(interval)
