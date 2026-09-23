import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.api import app, get_engine, get_vector_store, get_asset_lookup
from copilot.schema import TriageVerdict, TriageParseError
from copilot.vectorstore import TfidfCaseStore, ClosedCase
from copilot.enrichment import InMemoryAssetLookup


@pytest.fixture
def client():
    store = TfidfCaseStore()
    store.index([ClosedCase("c1", "Encoded PowerShell", "malicious", False)])
    lookup = InMemoryAssetLookup({"WIN-FIN-04": {"criticality": "crown_jewel", "owner": "Finance"}})

    app.dependency_overrides[get_vector_store] = lambda: store
    app.dependency_overrides[get_asset_lookup] = lambda: lookup

    yield TestClient(app)

    app.dependency_overrides.clear()


VALID_ALERT_PAYLOAD = {
    "alert_id": "a1",
    "source": "sentinel",
    "raw_title": "Encoded PowerShell Execution",
    "entity_type": "host",
    "entity_value": "WIN-FIN-04",
    "timestamp": "2026-09-22T10:00:00Z",
    "mitre_techniques": ["T1059.001"],
}


class TestTriageEndpoint:
    def test_returns_200_with_valid_verdict(self, client):
        fake_engine = MagicMock()
        fake_engine.triage.return_value = TriageVerdict(
            alert_id="a1",
            severity="high",
            false_positive_probability=0.1,
            recommended_action="escalate_tier2",
            rationale="test",
            cited_case_ids=[],
        )
        app.dependency_overrides[get_engine] = lambda: fake_engine

        resp = client.post("/triage", json=VALID_ALERT_PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["severity"] == "high"

    def test_returns_422_on_malformed_alert(self, client):
        bad_payload = {**VALID_ALERT_PAYLOAD, "mitre_techniques": ["not-a-real-technique"]}
        resp = client.post("/triage", json=bad_payload)
        assert resp.status_code == 422

    def test_returns_502_when_engine_raises_parse_error(self, client):
        fake_engine = MagicMock()
        fake_engine.triage.side_effect = TriageParseError("model hallucinated a citation")
        app.dependency_overrides[get_engine] = lambda: fake_engine

        resp = client.post("/triage", json=VALID_ALERT_PAYLOAD)

        assert resp.status_code == 502
        assert "hallucinated" in resp.json()["detail"]

    def test_enrichment_is_actually_invoked(self, client):
        """The engine should receive an EnrichmentContext populated from
        the overridden vector store / asset lookup, not an empty one."""
        fake_engine = MagicMock()
        fake_engine.triage.return_value = TriageVerdict(
            alert_id="a1",
            severity="low",
            false_positive_probability=0.9,
            recommended_action="monitor",
            rationale="test",
            cited_case_ids=[],
        )
        app.dependency_overrides[get_engine] = lambda: fake_engine

        client.post("/triage", json=VALID_ALERT_PAYLOAD)

        _, context_arg = fake_engine.triage.call_args.args
        assert context_arg.asset_criticality == "crown_jewel"


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
