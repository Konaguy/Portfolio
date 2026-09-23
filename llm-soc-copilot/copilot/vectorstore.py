"""
A minimal case vector store used for RAG retrieval over closed SOC cases.

Deliberately implemented with scikit-learn's TF-IDF + cosine similarity
rather than a hosted vector DB (Chroma/pgvector) or a downloaded embedding
model -- this keeps the whole project runnable offline with no external
services, which matters for a portfolio piece a reviewer will actually
try to run. `VectorStoreBackend` is a small protocol so a production
deployment can swap in Chroma/pgvector/a hosted embeddings API without
touching enrichment.py or triage.py; see the README for that migration
path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .schema import PriorCase


@dataclass
class ClosedCase:
    """A record in the case corpus used for retrieval."""

    case_id: str
    summary: str
    resolution: str
    was_false_positive: bool


class VectorStoreBackend(Protocol):
    """Interface any backend (this TF-IDF one, or a future Chroma/
    pgvector-backed one) must implement so enrichment.py doesn't care
    which is in use."""

    def index(self, cases: list[ClosedCase]) -> None: ...

    def query(self, text: str, k: int = 5) -> list[PriorCase]: ...


class TfidfCaseStore:
    """
    In-memory, TF-IDF-based case store. Rebuilds its similarity index on
    every `index()` call -- fine for the corpus sizes (hundreds to low
    thousands of closed cases) a single SOC accumulates; a production
    deployment with a shared, continuously-updated corpus would want an
    incremental index (Chroma/pgvector), not this.
    """

    def __init__(self) -> None:
        self._vectorizer = TfidfVectorizer(stop_words="english")
        self._matrix = None
        self._cases: list[ClosedCase] = []

    def index(self, cases: list[ClosedCase]) -> None:
        self._cases = cases
        if not cases:
            self._matrix = None
            return
        corpus = [f"{c.summary} {c.resolution}" for c in cases]
        self._matrix = self._vectorizer.fit_transform(corpus)

    def query(self, text: str, k: int = 5) -> list[PriorCase]:
        if self._matrix is None or not self._cases:
            return []
        query_vec = self._vectorizer.transform([text])
        scores = cosine_similarity(query_vec, self._matrix)[0]
        top_indices = np.argsort(scores)[::-1][:k]
        results = []
        for idx in top_indices:
            score = float(scores[idx])
            if score <= 0.0:
                continue
            case = self._cases[idx]
            results.append(
                PriorCase(
                    case_id=case.case_id,
                    summary=case.summary,
                    resolution=case.resolution,
                    was_false_positive=case.was_false_positive,
                    similarity_score=round(score, 4),
                )
            )
        return results
