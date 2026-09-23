"""
FastAPI wrapper around the triage pipeline: enrich -> triage -> return.

Dependency injection (get_vector_store / get_asset_lookup / get_engine)
is used deliberately so tests can override these with fakes/mocks without
monkeypatching module internals -- see tests/test_api.py.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException

from .schema import Alert, TriageVerdict, TriageParseError
from .enrichment import enrich_alert, AssetLookup, InMemoryAssetLookup
from .vectorstore import TfidfCaseStore, VectorStoreBackend
from .triage import TriageEngine

app = FastAPI(
    title="SOC Analyst Copilot",
    description="Alert triage: enrichment + RAG-grounded LLM verdicts.",
    version="0.1.0",
)

# Module-level singletons for the demo app. A real deployment would wire
# these through a proper settings/DI layer (e.g. loading the case corpus
# from a database on startup) rather than constructing them here.
_vector_store = TfidfCaseStore()
_asset_lookup = InMemoryAssetLookup()
_engine: TriageEngine | None = None


def get_vector_store() -> VectorStoreBackend:
    return _vector_store


def get_asset_lookup() -> AssetLookup:
    return _asset_lookup


def get_engine() -> TriageEngine:
    global _engine
    if _engine is None:
        _engine = TriageEngine()
    return _engine


@app.post("/triage", response_model=TriageVerdict)
def triage_alert(
    alert: Alert,
    vector_store: VectorStoreBackend = Depends(get_vector_store),
    asset_lookup: AssetLookup = Depends(get_asset_lookup),
    engine: TriageEngine = Depends(get_engine),
) -> TriageVerdict:
    context = enrich_alert(alert, vector_store, asset_lookup)
    try:
        return engine.triage(alert, context)
    except TriageParseError as exc:
        # A schema-validation failure on the LLM's output is a server-side
        # problem (bad model output), not a client error -- surfaced as
        # 502 rather than 400/500 to distinguish it in monitoring.
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
