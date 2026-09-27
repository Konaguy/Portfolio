"""
Embedding backends.

The default `HashingEmbedder` is deterministic and has no third-party
dependencies -- it maps tokens into a fixed-dimension vector via feature
hashing and L2-normalizes. It is not competitive with a trained model on
semantic recall, but it makes the whole pipeline runnable and testable
offline, and keeps the vector-store/retrieval/agent code honest.

`SentenceTransformerEmbedder` uses a real sentence-transformers model when
the package is installed; select it with VULNRAG_EMBEDDER=sentence-transformers.
Both satisfy the same `Embedder` protocol, so the rest of the code doesn't
care which is in use.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

from .config import Settings

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]:
        ...

    def embed_one(self, text: str) -> list[float]:
        ...


class HashingEmbedder:
    """Deterministic feature-hashing embedder. Dependency-free."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    def _tokens(self, text: str) -> list[str]:
        toks = _TOKEN_RE.findall(text.lower())
        # Add character trigrams of longer tokens so near-matches (e.g.
        # "log4j" vs "log4shell") share some signal.
        trigrams: list[str] = []
        for t in toks:
            if len(t) >= 4:
                trigrams.extend(t[i : i + 3] for i in range(len(t) - 2))
        return toks + trigrams

    def embed_one(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for tok in self._tokens(text):
            h = hashlib.md5(tok.encode("utf-8")).digest()
            idx = int.from_bytes(h[:4], "big") % self.dim
            sign = 1.0 if h[4] & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(x * x for x in vec))
        if norm == 0.0:
            return vec
        return [x / norm for x in vec]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self.embed_one(t) for t in texts]


class SentenceTransformerEmbedder:
    """Wraps a sentence-transformers model. Imported lazily so the package
    is only required when actually selected."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - exercised only without the dep
            raise ImportError(
                "sentence-transformers is not installed. Install it, or set "
                "VULNRAG_EMBEDDER=hashing to use the dependency-free embedder."
            ) from exc
        self._model = SentenceTransformer(model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> list[list[float]]:
        vecs = self._model.encode(texts, normalize_embeddings=True)
        return [list(map(float, v)) for v in vecs]

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]


def build_embedder(settings: Settings) -> Embedder:
    if settings.embedder == "sentence-transformers":
        return SentenceTransformerEmbedder(settings.embedding_model)
    if settings.embedder == "hashing":
        return HashingEmbedder(settings.embedding_dim)
    raise ValueError(f"Unknown embedder: {settings.embedder!r}")
