"""In-process pub/sub fan-out for the Pro real-time stream (SSE)."""

from __future__ import annotations

import asyncio


class Broker:
    def __init__(self, queue_size: int = 500):
        self._subs: set[asyncio.Queue] = set()
        self._size = queue_size

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._size)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, item: dict) -> None:
        for q in list(self._subs):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                # A stalled client must not block ingest or other clients;
                # it misses events and can backfill from /api/feed.
                pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)
