"""
SQLite persistence (stdlib only). One connection guarded by a lock: the
write rate is one ingest batch per poll interval, so SQLite is ample for a
single-node deployment; swap for Postgres behind the same methods to scale.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable

from .models import IOCs, Post, RawPost

SCHEMA = """
CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    native_id TEXT NOT NULL,
    author TEXT NOT NULL,
    author_handle TEXT NOT NULL,
    url TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at REAL NOT NULL,
    ingested_at REAL NOT NULL,
    categories TEXT NOT NULL,
    severity INTEGER NOT NULL,
    iocs TEXT NOT NULL,
    hashtags TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_ingested ON posts(ingested_at DESC);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at REAL NOT NULL
);

-- kind: 'session' (web login) or 'api' (Pro API key). Only a SHA-256 of the
-- token is stored, so a DB leak does not leak usable credentials.
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    label TEXT,
    prefix TEXT,
    created_at REAL NOT NULL,
    expires_at REAL
);

CREATE TABLE IF NOT EXISTS watchlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    keywords TEXT NOT NULL,
    min_severity INTEGER NOT NULL DEFAULT 0,
    webhook_url TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_events (
    ad_id TEXT NOT NULL,
    kind TEXT NOT NULL,       -- 'impression' | 'click'
    at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_webhooks (
    event_id TEXT PRIMARY KEY,
    at REAL NOT NULL
);
"""


def _post_row(p: Post) -> tuple:
    r = p.raw
    return (
        r.id, r.source, r.native_id, r.author, r.author_handle, r.url, r.text, r.created_at,
        p.ingested_at, json.dumps(p.categories), p.severity, json.dumps(p.iocs.as_dict()), json.dumps(p.hashtags),
    )


def _row_post(row: sqlite3.Row) -> Post:
    raw = RawPost(
        source=row["source"], native_id=row["native_id"], author=row["author"],
        author_handle=row["author_handle"], url=row["url"], text=row["text"], created_at=row["created_at"],
    )
    return Post(
        raw=raw, ingested_at=row["ingested_at"], categories=json.loads(row["categories"]),
        severity=row["severity"], iocs=IOCs(**json.loads(row["iocs"])), hashtags=json.loads(row["hashtags"]),
    )


class Store:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def _q(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            rows = cur.fetchall()
            self._conn.commit()
            return rows

    def _exec(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur.lastrowid if cur.lastrowid is not None else cur.rowcount

    # ---- posts ---------------------------------------------------------
    def insert_posts(self, posts: list[Post]) -> list[Post]:
        """Insert, ignoring ones already stored. Returns only the new ones."""
        new: list[Post] = []
        with self._lock:
            for p in posts:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO posts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", _post_row(p)
                )
                if cur.rowcount:
                    new.append(p)
            self._conn.commit()
        return new

    def query_posts(
        self,
        *,
        sources: Iterable[str],
        visible_before: float,
        since: float,
        limit: int,
        before: float | None = None,
        category: str | None = None,
        min_severity: int = 0,
        search: str | None = None,
    ) -> list[Post]:
        sources = list(sources)
        if not sources:
            return []
        sql = [f"SELECT * FROM posts WHERE source IN ({','.join('?' * len(sources))})",
               "AND ingested_at <= ? AND ingested_at >= ? AND severity >= ?"]
        params: list[Any] = [*sources, visible_before, since, min_severity]
        if before is not None:
            sql.append("AND ingested_at < ?")
            params.append(before)
        if category:
            # categories is a JSON array of known slugs; quoted match is exact.
            sql.append("AND categories LIKE ?")
            params.append(f'%"{category}"%')
        if search:
            sql.append("AND (text LIKE ? ESCAPE '\\' OR author_handle LIKE ? ESCAPE '\\')")
            like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params += [like, like]
        sql.append("ORDER BY ingested_at DESC, id DESC LIMIT ?")
        params.append(limit)
        return [_row_post(r) for r in self._q(" ".join(sql), params)]

    def posts_since(self, since: float) -> list[Post]:
        return [_row_post(r) for r in self._q("SELECT * FROM posts WHERE ingested_at >= ?", (since,))]

    def prune_posts(self, older_than: float) -> int:
        return self._exec("DELETE FROM posts WHERE ingested_at < ?", (older_than,))

    # ---- users & tokens -----------------------------------------------
    def create_user(self, email: str, password_hash: str) -> int:
        return self._exec(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?,?,?)",
            (email, password_hash, time.time()),
        )

    def user_by_email(self, email: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM users WHERE email = ?", (email,))
        return rows[0] if rows else None

    def user_by_id(self, user_id: int) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM users WHERE id = ?", (user_id,))
        return rows[0] if rows else None

    def user_by_stripe_customer(self, customer_id: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM users WHERE stripe_customer_id = ?", (customer_id,))
        return rows[0] if rows else None

    def set_tier(self, user_id: int, tier: str, customer_id: str | None = None,
                 subscription_id: str | None = None) -> None:
        self._exec(
            "UPDATE users SET tier = ?, stripe_customer_id = COALESCE(?, stripe_customer_id),"
            " stripe_subscription_id = COALESCE(?, stripe_subscription_id) WHERE id = ?",
            (tier, customer_id, subscription_id, user_id),
        )

    def add_token(self, token_hash: str, user_id: int, kind: str, *, label: str | None = None,
                  prefix: str | None = None, expires_at: float | None = None) -> None:
        self._exec(
            "INSERT INTO tokens VALUES (?,?,?,?,?,?,?)",
            (token_hash, user_id, kind, label, prefix, time.time(), expires_at),
        )

    def token_user(self, token_hash: str) -> tuple[sqlite3.Row, str] | None:
        rows = self._q(
            "SELECT u.*, t.kind AS token_kind, t.expires_at AS token_expires FROM tokens t"
            " JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?",
            (token_hash,),
        )
        if not rows:
            return None
        row = rows[0]
        if row["token_expires"] is not None and row["token_expires"] < time.time():
            self.delete_token(token_hash)
            return None
        return row, row["token_kind"]

    def delete_token(self, token_hash: str) -> None:
        self._exec("DELETE FROM tokens WHERE token_hash = ?", (token_hash,))

    def list_api_keys(self, user_id: int) -> list[sqlite3.Row]:
        return self._q(
            "SELECT prefix, label, created_at FROM tokens WHERE user_id = ? AND kind = 'api' ORDER BY created_at",
            (user_id,),
        )

    def delete_api_key(self, user_id: int, prefix: str) -> int:
        return self._exec("DELETE FROM tokens WHERE user_id = ? AND kind = 'api' AND prefix = ?", (user_id, prefix))

    def delete_api_keys(self, user_id: int) -> None:
        self._exec("DELETE FROM tokens WHERE user_id = ? AND kind = 'api'", (user_id,))

    # ---- watchlists ----------------------------------------------------
    def create_watchlist(self, user_id: int, name: str, keywords: list[str], min_severity: int,
                         webhook_url: str | None) -> int:
        return self._exec(
            "INSERT INTO watchlists (user_id, name, keywords, min_severity, webhook_url, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (user_id, name, json.dumps(keywords), min_severity, webhook_url, time.time()),
        )

    def list_watchlists(self, user_id: int) -> list[dict]:
        rows = self._q("SELECT * FROM watchlists WHERE user_id = ? ORDER BY id", (user_id,))
        return [self._wl(r) for r in rows]

    def delete_watchlist(self, user_id: int, wl_id: int) -> int:
        return self._exec("DELETE FROM watchlists WHERE user_id = ? AND id = ?", (user_id, wl_id))

    def active_watchlists(self) -> list[dict]:
        """Watchlists of users currently on Pro (a lapsed sub stops alerting)."""
        rows = self._q("SELECT w.* FROM watchlists w JOIN users u ON u.id = w.user_id WHERE u.tier = 'pro'")
        return [self._wl(r) for r in rows]

    @staticmethod
    def _wl(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "user_id": r["user_id"], "name": r["name"], "keywords": json.loads(r["keywords"]),
                "min_severity": r["min_severity"], "webhook_url": r["webhook_url"], "created_at": r["created_at"]}

    # ---- ads -----------------------------------------------------------
    def record_ad_event(self, ad_id: str, kind: str) -> None:
        self._exec("INSERT INTO ad_events VALUES (?,?,?)", (ad_id, kind, time.time()))

    def ad_stats(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for r in self._q("SELECT ad_id, kind, COUNT(*) AS n FROM ad_events GROUP BY ad_id, kind"):
            out.setdefault(r["ad_id"], {"impression": 0, "click": 0})[r["kind"]] = r["n"]
        return out

    # ---- webhook idempotency ------------------------------------------
    def mark_webhook_processed(self, event_id: str) -> bool:
        """True the first time an event id is seen; False on a replay."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO processed_webhooks VALUES (?,?)", (event_id, time.time())
            )
            self._conn.commit()
            return bool(cur.rowcount)
