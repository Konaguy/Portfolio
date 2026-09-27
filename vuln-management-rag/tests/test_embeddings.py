from __future__ import annotations

import math

from vulnrag.embeddings import HashingEmbedder


def test_hashing_embedder_is_deterministic():
    e = HashingEmbedder(dim=128)
    a = e.embed_one("apache log4j remote code execution")
    b = e.embed_one("apache log4j remote code execution")
    assert a == b
    assert len(a) == 128


def test_hashing_embedder_normalized():
    e = HashingEmbedder(dim=128)
    v = e.embed_one("some vulnerability text about smb")
    norm = math.sqrt(sum(x * x for x in v))
    assert abs(norm - 1.0) < 1e-6


def test_related_text_more_similar_than_unrelated():
    e = HashingEmbedder(dim=512)

    def cos(x, y):
        return sum(a * b for a, b in zip(x, y))

    log4j = e.embed_one("apache log4j log4shell remote code execution jndi")
    query = e.embed_one("how do I fix log4j log4shell")
    unrelated = e.embed_one("ssl certificate cannot be trusted chain")
    assert cos(log4j, query) > cos(log4j, unrelated)


def test_empty_text_returns_zero_vector():
    e = HashingEmbedder(dim=64)
    v = e.embed_one("")
    assert v == [0.0] * 64
