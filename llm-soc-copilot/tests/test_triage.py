import sys
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.schema import Alert, EnrichmentContext, PriorCase, TriageParseError
from copilot.triage import TriageEngine, SUBMIT_VERDICT_TOOL


def _alert():
    return Alert(
        alert_id="a1",
        source="sentinel",
        raw_title="Encoded PowerShell Execution",
        entity_type="host",
        entity_value="WIN-FIN-04",
        timestamp=datetime.now(timezone.utc),
        mitre_techniques=["T1059.001"],
    )


def _context(with_case=True):
    prior_cases = (
        [PriorCase(case_id="c1", summary="x", resolution="y", was_false_positive=False, similarity_score=0.4)]
        if with_case
        else []
    )
    return EnrichmentContext(asset_criticality="crown_jewel", prior_cases=prior_cases)


def _mock_client_returning(tool_input: dict):
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.input = tool_input
    message = MagicMock()
    message.content = [tool_block]
    client = MagicMock()
    client.messages.create.return_value = message
    return client


VALID_VERDICT_INPUT = {
    "severity": "high",
    "false_positive_probability": 0.15,
    "recommended_action": "escalate_tier2",
    "rationale": "Matches prior confirmed-malicious case c1; host is crown jewel asset.",
    "cited_case_ids": ["c1"],
}


class TestTriageEngineHappyPath:
    def test_parses_valid_tool_response(self):
        client = _mock_client_returning(VALID_VERDICT_INPUT)
        engine = TriageEngine(client=client)

        verdict = engine.triage(_alert(), _context())

        assert verdict.alert_id == "a1"
        assert verdict.severity.value == "high"
        assert verdict.cited_case_ids == ["c1"]

    def test_forces_tool_choice_to_submit_triage_verdict(self):
        client = _mock_client_returning(VALID_VERDICT_INPUT)
        engine = TriageEngine(client=client)

        engine.triage(_alert(), _context())

        call_kwargs = client.messages.create.call_args.kwargs
        assert call_kwargs["tool_choice"] == {"type": "tool", "name": "submit_triage_verdict"}
        assert call_kwargs["tools"][0]["name"] == "submit_triage_verdict"

    def test_prompt_includes_prior_case_context(self):
        client = _mock_client_returning(VALID_VERDICT_INPUT)
        engine = TriageEngine(client=client)

        engine.triage(_alert(), _context())

        user_message = client.messages.create.call_args.kwargs["messages"][0]["content"]
        assert "c1" in user_message
        assert "crown_jewel" in user_message


class TestTriageEngineFailureModes:
    def test_rejects_hallucinated_citation(self):
        bad_input = {**VALID_VERDICT_INPUT, "cited_case_ids": ["c1", "c999-not-real"]}
        client = _mock_client_returning(bad_input)
        engine = TriageEngine(client=client)

        with pytest.raises(TriageParseError, match="c999-not-real"):
            engine.triage(_alert(), _context())

    def test_rejects_malformed_severity(self):
        bad_input = {**VALID_VERDICT_INPUT, "severity": "extremely-bad"}
        client = _mock_client_returning(bad_input)
        engine = TriageEngine(client=client)

        with pytest.raises(TriageParseError):
            engine.triage(_alert(), _context())

    def test_rejects_response_with_no_tool_use_block(self):
        message = MagicMock()
        message.content = []  # model responded with prose instead of a tool call
        client = MagicMock()
        client.messages.create.return_value = message
        engine = TriageEngine(client=client)

        with pytest.raises(TriageParseError, match="no tool_use block"):
            engine.triage(_alert(), _context())

    def test_empty_prior_cases_means_no_valid_citations(self):
        client = _mock_client_returning(VALID_VERDICT_INPUT)  # cites c1
        engine = TriageEngine(client=client)

        with pytest.raises(TriageParseError):
            engine.triage(_alert(), _context(with_case=False))  # but no cases offered


class TestToolSchemaConsistency:
    def test_tool_schema_matches_pydantic_model(self):
        """Guards against the hand-written SUBMIT_VERDICT_TOOL schema
        (see triage.py's note on why it's hand-written) drifting out of
        sync with TriageVerdict as the model evolves."""
        from copilot.schema import TriageVerdict

        schema_props = set(SUBMIT_VERDICT_TOOL["input_schema"]["properties"].keys())
        model_fields = set(TriageVerdict.model_fields.keys()) - {"alert_id"}
        assert schema_props == model_fields
