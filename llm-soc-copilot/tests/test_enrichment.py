import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.vectorstore import TfidfCaseStore, ClosedCase
from copilot.enrichment import enrich_alert, InMemoryAssetLookup, build_case_query_text
from copilot.schema import Alert


CASES = [
    ClosedCase("c1", "Encoded PowerShell execution on finance laptop", "Confirmed malicious, IcedID loader", False),
    ClosedCase("c2", "Encoded PowerShell used by IT automation script", "False positive, known Datto RMM script", True),
    ClosedCase("c3", "Mass file rename to .locked extension on file server", "Ransomware, contained and rebuilt", False),
    ClosedCase("c4", "Impossible travel login for sales account", "User was on VPN, false positive", True),
]


class TestTfidfCaseStore:
    def test_query_ranks_relevant_cases_above_irrelevant(self):
        store = TfidfCaseStore()
        store.index(CASES)
        results = store.query("powershell encoded command hidden window", k=4)
        result_ids = [r.case_id for r in results]
        # The two PowerShell cases should outrank the ransomware/login cases.
        assert result_ids[0] in ("c1", "c2")
        assert result_ids[1] in ("c1", "c2")
        assert "c3" not in result_ids[:2]
        assert "c4" not in result_ids[:2]

    def test_query_respects_k_limit(self):
        store = TfidfCaseStore()
        store.index(CASES)
        results = store.query("security alert", k=2)
        assert len(results) <= 2

    def test_empty_store_returns_no_results(self):
        store = TfidfCaseStore()
        store.index([])
        assert store.query("anything") == []

    def test_similarity_scores_are_within_valid_range(self):
        store = TfidfCaseStore()
        store.index(CASES)
        for result in store.query("encoded powershell", k=4):
            assert 0.0 <= result.similarity_score <= 1.0


class TestEnrichAlert:
    def _alert(self, entity_value="WIN-FIN-04"):
        return Alert(
            alert_id="a1",
            source="sentinel",
            raw_title="Encoded PowerShell Execution",
            raw_description="powershell -enc launched",
            entity_type="host",
            entity_value=entity_value,
            timestamp=datetime.now(timezone.utc),
            mitre_techniques=["T1059.001"],
        )

    def test_enrich_combines_asset_and_case_lookup(self):
        store = TfidfCaseStore()
        store.index(CASES)
        lookup = InMemoryAssetLookup(
            {"WIN-FIN-04": {"criticality": "crown_jewel", "owner": "Finance IT"}}
        )

        ctx = enrich_alert(self._alert(), store, lookup)

        assert ctx.asset_criticality == "crown_jewel"
        assert ctx.asset_owner == "Finance IT"
        assert len(ctx.prior_cases) > 0
        assert ctx.prior_cases[0].case_id in ("c1", "c2")

    def test_enrich_handles_unknown_asset_gracefully(self):
        store = TfidfCaseStore()
        store.index(CASES)
        lookup = InMemoryAssetLookup({})  # nothing registered

        ctx = enrich_alert(self._alert(entity_value="UNKNOWN-HOST"), store, lookup)

        assert ctx.asset_criticality is None
        assert ctx.asset_owner is None
        # Case retrieval should still work even with no asset match.
        assert len(ctx.prior_cases) > 0

    def test_build_case_query_text_includes_techniques(self):
        text = build_case_query_text(self._alert())
        assert "T1059.001" in text
        assert "Encoded PowerShell Execution" in text
