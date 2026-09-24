from __future__ import annotations

from vulnrag.config import Settings
from vulnrag.embeddings import HashingEmbedder
from vulnrag.ingest import parse_tenable_csv
from vulnrag.vectorstore import VectorStore


def test_seeded_store_counts(seeded_store):
    # 10 vulns + several policy chunks.
    assert seeded_store.count() >= 12


def test_search_returns_relevant_vuln(seeded_store):
    hits = seeded_store.search("log4j remote code execution", top_k=3, kind="vulnerability")
    assert hits
    assert all(h.kind == "vulnerability" for h in hits)
    assert any("Log4j" in h.document or "Log4Shell" in h.document for h in hits)


def test_kind_filter_isolates_policy(seeded_store):
    hits = seeded_store.search("patch SLA critical", top_k=3, kind="policy")
    assert hits
    assert all(h.kind == "policy" for h in hits)


def test_upsert_is_idempotent():
    settings = Settings(qdrant_url=":memory:", embedder="hashing", embedding_dim=128)
    store = VectorStore(settings, HashingEmbedder(128))
    csv_text = (
        "Plugin ID,CVE,Name,Severity,Host,Port\n"
        "40001,CVE-2020-1,Repeatable,High,10.0.0.1,443\n"
    )
    vulns = parse_tenable_csv(csv_text)
    store.upsert_vulnerabilities(vulns)
    store.upsert_vulnerabilities(vulns)  # same chunk_id -> upsert, not duplicate
    assert store.count() == 1
