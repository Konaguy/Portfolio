"""
LLM boundary.

Structured output is enforced via tool-use, not "respond in JSON" prompting:
the model is given exactly one tool (`submit_answer`) whose schema mirrors
`RemediationAnswer`, and `tool_choice` forces it to call that tool. This is
the same pattern as the `llm-soc-copilot` project in this portfolio, for the
same reasons -- a concrete schema-mismatch failure mode instead of silent
prompt-format drift.

`ClaudeClient` calls the real Anthropic API. `FakeLLMClient` returns a
canned, schema-valid answer so the agent graph, ingestion, and retrieval can
be tested end-to-end without network access or an API key. Both satisfy the
`LLMClient` protocol, and the agent nodes depend only on that protocol.

Note on model choice: forced `tool_choice` ({"type": "tool"}) is supported on
claude-opus-5 (the default) but returns 400 on claude-opus-5-5 / the Fable
family. If you switch to one of those, use structured outputs
(output_config.format) instead -- see the Anthropic API docs.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from .schema import AnswerParseError, RemediationAnswer

# Hand-written to mirror schema.RemediationAnswer exactly. Kept as a dict
# (not derived from Pydantic) so this module has no import-time coupling to
# Pydantic's JSON-schema export quirks; a test asserts the two stay in sync.
SUBMIT_ANSWER_TOOL: dict[str, Any] = {
    "name": "submit_answer",
    "description": "Submit the structured remediation answer for the analyst's question.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "One-paragraph answer to the analyst's question.",
            },
            "remediation_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Ordered, concrete remediation steps.",
            },
            "prioritization_rationale": {
                "type": "string",
                "description": "Why this ranks where it does (CVSS/VPR/asset/policy SLA).",
            },
            "cited_chunk_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "chunk_ids from the provided context that the answer relied on.",
            },
        },
        "required": [
            "summary",
            "remediation_steps",
            "prioritization_rationale",
            "cited_chunk_ids",
        ],
    },
}


class LLMClient(Protocol):
    def generate_answer(self, system_prompt: str, user_prompt: str) -> dict:
        """Return the raw tool-input dict for a submit_answer call."""
        ...


class ClaudeClient:
    """Calls the Anthropic Messages API with forced tool-use."""

    def __init__(
        self,
        client: Any | None = None,
        model: str = "claude-opus-5",
        max_tokens: int = 1500,
    ) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def generate_answer(self, system_prompt: str, user_prompt: str) -> dict:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            tools=[SUBMIT_ANSWER_TOOL],
            tool_choice={"type": "tool", "name": "submit_answer"},
            messages=[{"role": "user", "content": user_prompt}],
        )
        tool_blocks = [b for b in message.content if getattr(b, "type", None) == "tool_use"]
        if not tool_blocks:
            raise AnswerParseError("Model response contained no tool_use block")
        # Tool inputs may arrive with model-specific JSON escaping; the SDK
        # already parses them to a dict, but guard against a str just in case.
        raw = tool_blocks[0].input
        return json.loads(raw) if isinstance(raw, str) else dict(raw)


class FakeLLMClient:
    """Deterministic offline client for tests and no-API-key demos.

    Produces a schema-valid answer that echoes the chunk_ids it was given in
    the prompt (so citation-guard behaviour is exercisable), or an explicit
    override for tests that need to force a specific/invalid output.
    """

    def __init__(self, override: dict | None = None) -> None:
        self._override = override
        self.calls: list[tuple[str, str]] = []

    def generate_answer(self, system_prompt: str, user_prompt: str) -> dict:
        self.calls.append((system_prompt, user_prompt))
        if self._override is not None:
            return self._override
        cited = _extract_chunk_ids(user_prompt)
        return {
            "summary": (
                "Based on the retrieved findings and policy context, prioritize the "
                "critical/high items on internet-facing hosts and patch within the "
                "policy SLA."
            ),
            "remediation_steps": [
                "Apply the vendor-listed patch or upgrade for the affected plugin.",
                "Re-scan the host to confirm the finding is resolved.",
                "Record the change and closure in the ticketing system.",
            ],
            "prioritization_rationale": (
                "Ranked by severity and VPR, weighted toward exposed hosts, against "
                "the remediation SLA in the retrieved policy."
            ),
            "cited_chunk_ids": cited,
        }


def _extract_chunk_ids(text: str) -> list[str]:
    import re

    return re.findall(r"\b(?:vuln|pol)-[0-9a-f]{12}\b", text)


def parse_and_validate(raw: dict, allowed_chunk_ids: set[str]) -> RemediationAnswer:
    """Validate the LLM output against the schema and guard against cited
    chunk_ids that were never in the retrieved context (hallucinated
    grounding, treated as a hard failure)."""
    cited = raw.get("cited_chunk_ids", []) or []
    invalid = [c for c in cited if c not in allowed_chunk_ids]
    if invalid:
        raise AnswerParseError(
            f"Model cited chunk_ids not present in retrieved context: {invalid}"
        )
    try:
        return RemediationAnswer(**raw)
    except Exception as exc:  # pydantic.ValidationError, primarily
        raise AnswerParseError(f"Model output failed schema validation: {exc}") from exc
