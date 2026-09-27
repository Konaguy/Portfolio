from __future__ import annotations

import pytest

from vulnrag.llm import SUBMIT_ANSWER_TOOL, FakeLLMClient, parse_and_validate
from vulnrag.schema import AnswerParseError, RemediationAnswer


def test_tool_schema_matches_pydantic_model():
    """The hand-written tool schema must stay in sync with RemediationAnswer."""
    schema_props = set(SUBMIT_ANSWER_TOOL["input_schema"]["properties"])
    model_fields = set(RemediationAnswer.model_fields)
    assert schema_props == model_fields
    # Everything the tool requires must be a real model field.
    assert set(SUBMIT_ANSWER_TOOL["input_schema"]["required"]).issubset(model_fields)


def test_parse_and_validate_accepts_valid():
    raw = {
        "summary": "Patch it.",
        "remediation_steps": ["Upgrade", "Re-scan"],
        "prioritization_rationale": "Critical, exposed.",
        "cited_chunk_ids": ["vuln-abc123abc123"],
    }
    answer = parse_and_validate(raw, allowed_chunk_ids={"vuln-abc123abc123"})
    assert isinstance(answer, RemediationAnswer)
    assert answer.cited_chunk_ids == ["vuln-abc123abc123"]


def test_parse_and_validate_rejects_hallucinated_citation():
    raw = {
        "summary": "Patch it.",
        "remediation_steps": [],
        "prioritization_rationale": "",
        "cited_chunk_ids": ["vuln-doesnotexist"],
    }
    with pytest.raises(AnswerParseError):
        parse_and_validate(raw, allowed_chunk_ids={"vuln-abc123abc123"})


def test_parse_and_validate_rejects_bad_schema():
    raw = {"remediation_steps": []}  # missing required summary
    with pytest.raises(AnswerParseError):
        parse_and_validate(raw, allowed_chunk_ids=set())


def test_fake_llm_echoes_chunk_ids_from_prompt():
    fake = FakeLLMClient()
    out = fake.generate_answer("sys", "context has vuln-1234567890ab and pol-abcdef123456")
    assert set(out["cited_chunk_ids"]) == {"vuln-1234567890ab", "pol-abcdef123456"}
