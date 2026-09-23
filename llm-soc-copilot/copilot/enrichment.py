"""
Enrichment: everything gathered about an alert before it goes to the LLM.

Two sources, both behind small pluggable interfaces so a real deployment
can swap in an actual CMDB (often ServiceNow itself, per the
security-automation-soar project in this portfolio) without touching the
rest of the pipeline:
    - asset criticality / ownership lookup
    - RAG retrieval of similar prior cases from the vector store
"""

from __future__ import annotations

from typing import Protocol

from .schema import Alert, EnrichmentContext
from .vectorstore import VectorStoreBackend


class AssetLookup(Protocol):
    """Interface for asset-criticality lookups. InMemoryAssetLookup below
    is the demo implementation; a real one would call ServiceNow's CMDB
    API (see security-automation-soar/docs/architecture.md)."""

    def lookup(self, entity_value: str) -> tuple[str | None, str | None]:
        """Return (criticality, owner) for an entity, or (None, None) if unknown."""
        ...


class InMemoryAssetLookup:
    """A dict-backed stand-in for a CMDB, for demo/testing purposes."""

    def __init__(self, assets: dict[str, dict[str, str]] | None = None) -> None:
        # keyed by entity_value (hostname, username, etc.)
        self._assets = assets or {}

    def lookup(self, entity_value: str) -> tuple[str | None, str | None]:
        record = self._assets.get(entity_value)
        if not record:
            return None, None
        return record.get("criticality"), record.get("owner")


def build_case_query_text(alert: Alert) -> str:
    """Construct the text used to query the case vector store -- combines
    the alert's title/description with its MITRE techniques, since past
    cases are often summarized with technique-adjacent language."""
    techniques = " ".join(alert.mitre_techniques)
    return f"{alert.raw_title} {alert.raw_description} {techniques}".strip()


def enrich_alert(
    alert: Alert,
    vector_store: VectorStoreBackend,
    asset_lookup: AssetLookup,
    max_prior_cases: int = 5,
) -> EnrichmentContext:
    """Assemble the full enrichment context for one alert."""
    criticality, owner = asset_lookup.lookup(alert.entity_value)
    prior_cases = vector_store.query(build_case_query_text(alert), k=max_prior_cases)

    return EnrichmentContext(
        asset_criticality=criticality,
        asset_owner=owner,
        prior_cases=prior_cases,
    )
