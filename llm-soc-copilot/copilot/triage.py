"""
The triage engine: takes an Alert + EnrichmentContext, calls Claude, and
returns a validated TriageVerdict.

Structured output is enforced via tool-use rather than "please respond in
JSON" prompting -- the model is given exactly one tool
(`submit_triage_verdict`) with a JSON schema matching TriageVerdict, and
`tool_choice` forces it to call that tool. This is more reliable than
parsing free text and gives us a concrete schema-mismatch failure mode
(TriageParseError) to handle, rather than silent prompt-format drift.
"""

from __future__ import annotations

import json
from typing import Any

import anthropic

from .schema import Alert, EnrichmentContext, TriageVerdict, TriageParseError

DEFAULT_MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) triage assistant. \
You are given a security alert and enrichment context (asset criticality, \
similar prior cases). Your job is to produce a triage verdict: severity, \
a false-positive probability, a recommended action, and a short rationale.

Ground your verdict in the evidence given -- the alert's raw fields, the \
asset's criticality, and any similar prior cases and how they were \
resolved. When a prior case materially informs your verdict, cite its \
case_id in cited_case_ids. Do not cite a case_id that wasn't provided in \
the context. If no prior cases are relevant, leave cited_case_ids empty \
rather than citing something borderline.

Call the submit_triage_verdict tool with your answer. Do not respond with \
prose -- your entire response should be the tool call."""

# JSON schema mirrors schema.TriageVerdict exactly. Kept as a hand-written
# dict (rather than derived from the Pydantic model) so this file has no
# import-time dependency on Pydantic's JSON-schema export quirks across
# versions -- but tests assert the two stay in sync (see
# tests/test_triage.py::test_tool_schema_matches_pydantic_model).
SUBMIT_VERDICT_TOOL = {
    "name": "submit_triage_verdict",
    "description": "Submit the structured triage verdict for this alert.",
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
            },
            "false_positive_probability": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "0 = certainly a true positive, 1 = certainly benign",
            },
            "recommended_action": {
                "type": "string",
                "enum": [
                    "close_false_positive",
                    "monitor",
                    "escalate_tier2",
                    "contain_immediately",
                ],
            },
            "rationale": {"type": "string"},
            "cited_case_ids": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": [
            "severity",
            "false_positive_probability",
            "recommended_action",
            "rationale",
            "cited_case_ids",
        ],
    },
}


def _build_user_message(alert: Alert, context: EnrichmentContext) -> str:
    prior_cases_text = "\n".join(
        f"  - [{c.case_id}] (similarity={c.similarity_score}, "
        f"was_false_positive={c.was_false_positive}) {c.summary} -> Resolution: {c.resolution}"
        for c in context.prior_cases
    ) or "  (none found)"

    return f"""## Alert
alert_id: {alert.alert_id}
source: {alert.source}
title: {alert.raw_title}
description: {alert.raw_description or "(none provided)"}
entity: {alert.entity_type} = {alert.entity_value}
severity_reported_by_source: {alert.severity_reported.value if alert.severity_reported else "unknown"}
mitre_techniques: {", ".join(alert.mitre_techniques) or "(none)"}

## Enrichment
asset_criticality: {context.asset_criticality or "unknown"}
asset_owner: {context.asset_owner or "unknown"}

## Similar prior cases (retrieved via RAG)
{prior_cases_text}
"""


class TriageEngine:
    def __init__(
        self,
        client: anthropic.Anthropic | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 1024,
    ) -> None:
        self._client = client or anthropic.Anthropic()
        self._model = model
        self._max_tokens = max_tokens

    def triage(self, alert: Alert, context: EnrichmentContext) -> TriageVerdict:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=SYSTEM_PROMPT,
            tools=[SUBMIT_VERDICT_TOOL],
            tool_choice={"type": "tool", "name": "submit_triage_verdict"},
            messages=[{"role": "user", "content": _build_user_message(alert, context)}],
        )
        return self._parse_response(message, alert, context)

    def _parse_response(
        self, message: Any, alert: Alert, context: EnrichmentContext
    ) -> TriageVerdict:
        tool_use_blocks = [b for b in message.content if getattr(b, "type", None) == "tool_use"]
        if not tool_use_blocks:
            raise TriageParseError(
                f"Model response for alert {alert.alert_id} contained no tool_use block"
            )

        tool_input: dict = tool_use_blocks[0].input

        # Guard against the model citing a case_id that wasn't actually
        # offered to it -- a hallucinated citation would be worse than
        # none, since it implies grounding that doesn't exist.
        valid_case_ids = {c.case_id for c in context.prior_cases}
        cited = tool_input.get("cited_case_ids", [])
        invalid_citations = [c for c in cited if c not in valid_case_ids]
        if invalid_citations:
            raise TriageParseError(
                f"Model cited case_ids not present in context: {invalid_citations}"
            )

        try:
            return TriageVerdict(alert_id=alert.alert_id, **tool_input)
        except Exception as exc:  # pydantic.ValidationError, primarily
            raise TriageParseError(
                f"Model output failed schema validation for alert {alert.alert_id}: {exc}"
            ) from exc
