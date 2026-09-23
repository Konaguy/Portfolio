import sys
from pathlib import Path
from datetime import datetime, timezone

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.schema import Alert, TriageVerdict, EnrichmentContext, PriorCase, Severity


def _now():
    return datetime.now(timezone.utc)


class TestAlert:
    def test_valid_alert_constructs(self):
        alert = Alert(
            alert_id="a1",
            source="sentinel",
            raw_title="Encoded PowerShell",
            entity_type="host",
            entity_value="WIN-TEST",
            timestamp=_now(),
            mitre_techniques=["T1059.001"],
        )
        assert alert.alert_id == "a1"

    def test_rejects_malformed_mitre_technique(self):
        with pytest.raises(Exception):
            Alert(
                alert_id="a1",
                source="sentinel",
                raw_title="x",
                entity_type="host",
                entity_value="WIN-TEST",
                timestamp=_now(),
                mitre_techniques=["not-a-real-id"],
            )

    def test_defaults_for_optional_fields(self):
        alert = Alert(
            alert_id="a1",
            source="sentinel",
            raw_title="x",
            entity_type="host",
            entity_value="WIN-TEST",
            timestamp=_now(),
        )
        assert alert.mitre_techniques == []
        assert alert.raw_description == ""
        assert alert.severity_reported is None


class TestTriageVerdict:
    def test_valid_verdict_constructs(self):
        v = TriageVerdict(
            alert_id="a1",
            severity=Severity.HIGH,
            false_positive_probability=0.1,
            recommended_action="escalate_tier2",
            rationale="test",
        )
        assert v.severity == Severity.HIGH

    def test_probability_out_of_range_rejected(self):
        with pytest.raises(Exception):
            TriageVerdict(
                alert_id="a1",
                severity=Severity.HIGH,
                false_positive_probability=1.5,
                recommended_action="escalate_tier2",
                rationale="test",
            )

    def test_empty_rationale_rejected(self):
        with pytest.raises(Exception):
            TriageVerdict(
                alert_id="a1",
                severity=Severity.LOW,
                false_positive_probability=0.9,
                recommended_action="monitor",
                rationale="",
            )


class TestEnrichmentContext:
    def test_prior_case_similarity_must_be_0_to_1(self):
        with pytest.raises(Exception):
            PriorCase(
                case_id="c1",
                summary="x",
                resolution="y",
                was_false_positive=True,
                similarity_score=1.2,
            )

    def test_empty_context_is_valid(self):
        ctx = EnrichmentContext()
        assert ctx.prior_cases == []
        assert ctx.asset_criticality is None
