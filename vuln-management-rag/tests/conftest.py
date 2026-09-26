"""Shared fixtures: an in-memory store seeded with the sample corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnrag.config import Settings
from vulnrag.embeddings import HashingEmbedder
from vulnrag.ingest import parse_policy_dir, parse_tenable_file
from vulnrag.vectorstore import VectorStore

_DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture
def settings() -> Settings:
    return Settings(qdrant_url=":memory:", embedder="hashing", embedding_dim=384, top_k=6)


@pytest.fixture
def seeded_store(settings: Settings) -> VectorStore:
    store = VectorStore(settings, HashingEmbedder(settings.embedding_dim))
    store.upsert_vulnerabilities(parse_tenable_file(_DATA / "sample_tenable_export.csv"))
    store.upsert_policies(parse_policy_dir(_DATA / "sample_policies"))
    return store
