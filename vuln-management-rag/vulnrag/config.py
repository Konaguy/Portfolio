"""
Runtime configuration, read from the environment with sensible defaults so
the app runs out of the box against an in-memory Qdrant and a deterministic
local embedder -- no external services required for a demo or the tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # --- LLM ---
    # Opus 5 supports forced tool-use, which llm.py relies on for structured
    # output. Override with ANTHROPIC_MODEL if you prefer a cheaper model
    # (e.g. claude-sonnet-5) for high-volume use.
    anthropic_model: str = "claude-opus-5"
    max_tokens: int = 1500

    # --- Vector store ---
    # ":memory:" runs an embedded Qdrant (no server). Point qdrant_url at a
    # running instance (see docker-compose.yml) for persistence.
    qdrant_url: str = ":memory:"
    qdrant_collection: str = "vuln_corpus"

    # --- Embeddings ---
    # "hashing" is a deterministic, dependency-free embedder (good for tests
    # and offline demos). "sentence-transformers" uses a real model if the
    # package is installed.
    embedder: str = "hashing"
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dim: int = 384

    # --- Retrieval ---
    top_k: int = 6

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            anthropic_model=os.getenv("ANTHROPIC_MODEL", cls.anthropic_model),
            max_tokens=int(os.getenv("VULNRAG_MAX_TOKENS", cls.max_tokens)),
            qdrant_url=os.getenv("QDRANT_URL", cls.qdrant_url),
            qdrant_collection=os.getenv("QDRANT_COLLECTION", cls.qdrant_collection),
            embedder=os.getenv("VULNRAG_EMBEDDER", cls.embedder),
            embedding_model=os.getenv("VULNRAG_EMBEDDING_MODEL", cls.embedding_model),
            embedding_dim=int(os.getenv("VULNRAG_EMBEDDING_DIM", cls.embedding_dim)),
            top_k=int(os.getenv("VULNRAG_TOP_K", cls.top_k)),
        )
