"""
Qdrant-backed vector store.

Uses qdrant-client, which supports an embedded ":memory:" mode (no server)
as well as a real Qdrant instance over HTTP. The same code path serves the
tests (in-memory) and production (docker-compose Qdrant) -- only the URL
changes.

Points are keyed by a deterministic UUID derived from the corpus item's
`chunk_id`, so re-ingesting the same export upserts (idempotent) rather than
duplicating.
"""

from __future__ import annotations

import uuid
from typing import Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

from .config import Settings
from .embeddings import Embedder
from .schema import PolicyChunk, RetrievedChunk, Vulnerability

_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def _point_id(chunk_id: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, chunk_id))


class VectorStore:
    def __init__(self, settings: Settings, embedder: Embedder) -> None:
        self._settings = settings
        self._embedder = embedder
        self._collection = settings.qdrant_collection
        if settings.qdrant_url == ":memory:":
            self._client = QdrantClient(location=":memory:")
        else:
            self._client = QdrantClient(url=settings.qdrant_url)
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        exists = self._client.collection_exists(self._collection)
        if not exists:
            self._client.create_collection(
                collection_name=self._collection,
                vectors_config=qm.VectorParams(
                    size=self._embedder.dim, distance=qm.Distance.COSINE
                ),
            )

    def upsert_vulnerabilities(self, vulns: list[Vulnerability]) -> int:
        return self._upsert(
            [(v.chunk_id, "vulnerability", v.to_document(), v.model_dump(mode="json")) for v in vulns]
        )

    def upsert_policies(self, chunks: list[PolicyChunk]) -> int:
        return self._upsert(
            [(c.chunk_id, "policy", c.to_document(), c.model_dump(mode="json")) for c in chunks]
        )

    def _upsert(self, items: list[tuple[str, str, str, dict]]) -> int:
        if not items:
            return 0
        vectors = self._embedder.embed([doc for _, _, doc, _ in items])
        points = [
            qm.PointStruct(
                id=_point_id(chunk_id),
                vector=vector,
                payload={"chunk_id": chunk_id, "kind": kind, "document": doc, **payload},
            )
            for (chunk_id, kind, doc, payload), vector in zip(items, vectors)
        ]
        self._client.upsert(collection_name=self._collection, points=points)
        return len(points)

    def search(
        self, query: str, top_k: int, kind: Optional[str] = None
    ) -> list[RetrievedChunk]:
        query_vec = self._embedder.embed_one(query)
        query_filter = None
        if kind is not None:
            query_filter = qm.Filter(
                must=[qm.FieldCondition(key="kind", match=qm.MatchValue(value=kind))]
            )
        hits = self._client.query_points(
            collection_name=self._collection,
            query=query_vec,
            limit=top_k,
            query_filter=query_filter,
            with_payload=True,
        ).points
        results: list[RetrievedChunk] = []
        for h in hits:
            payload = dict(h.payload or {})
            results.append(
                RetrievedChunk(
                    chunk_id=payload.get("chunk_id", str(h.id)),
                    kind=payload.get("kind", "unknown"),
                    document=payload.get("document", ""),
                    score=float(h.score),
                    payload=payload,
                )
            )
        return results

    def count(self) -> int:
        return self._client.count(self._collection).count
