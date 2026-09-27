"""
LLM boundary for KQL generation.

`ClaudeClient` forces structured output via a single `submit_hunt` tool whose
schema mirrors `GeneratedHunt`. `FakeLLMClient` builds valid, schema-correct
KQL deterministically from the extracted IOCs, so the translator and validator
can be tested end-to-end offline. Both satisfy the `LLMClient` protocol.

Forced `tool_choice` is supported on claude-opus-5 (the default); on
claude-opus-5-5 / the Fable family, use structured outputs
(output_config.format) instead.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from .schema import HuntParseError, ThreatIntel

SUBMIT_HUNT_TOOL: dict[str, Any] = {
    "name": "submit_hunt",
    "description": "Submit the generated Defender hunting queries.",
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string"},
            "queries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "table": {"type": "string"},
                        "kql": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["name", "table", "kql", "rationale"],
                },
            },
            "iocs_used": {"type": "array", "items": {"type": "string"}},
            "mitre_techniques": {"type": "array", "items": {"type": "string"}},
            "caveats": {"type": "string"},
        },
        "required": ["title", "description", "queries", "iocs_used", "mitre_techniques", "caveats"],
    },
}


class LLMClient(Protocol):
    def generate_hunt(self, system_prompt: str, user_prompt: str) -> dict:
        ...


class ClaudeClient:
    def __init__(
        self, client: Any | None = None, model: str = "claude-opus-5", max_tokens: int = 2000
    ) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def generate_hunt(self, system_prompt: str, user_prompt: str) -> dict:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            tools=[SUBMIT_HUNT_TOOL],
            tool_choice={"type": "tool", "name": "submit_hunt"},
            messages=[{"role": "user", "content": user_prompt}],
        )
        tool_blocks = [b for b in message.content if getattr(b, "type", None) == "tool_use"]
        if not tool_blocks:
            raise HuntParseError("Model response contained no tool_use block")
        raw = tool_blocks[0].input
        return json.loads(raw) if isinstance(raw, str) else dict(raw)


class FakeLLMClient:
    """Deterministic offline generator: builds real KQL from the IOCs named in
    the user prompt, one query per IOC-type/table it knows how to hunt."""

    def __init__(self, intel: ThreatIntel | None = None, override: dict | None = None) -> None:
        self._intel = intel
        self._override = override
        self.calls: list[tuple[str, str]] = []

    def generate_hunt(self, system_prompt: str, user_prompt: str) -> dict:
        self.calls.append((system_prompt, user_prompt))
        if self._override is not None:
            return self._override
        if self._intel is None:
            raise HuntParseError("FakeLLMClient needs `intel` (or `override`) to generate")
        return _build_fake_hunt(self._intel)


def _kql_in_list(values: list[str]) -> str:
    return ", ".join(f'"{v}"' for v in values)


def _build_fake_hunt(intel: ThreatIntel) -> dict:
    from .schema import IOCType

    queries: list[dict] = []
    used: list[str] = []
    window = "| where Timestamp > ago(30d)"

    def add_query(name: str, table: str, column: str, values: list[str], op: str = "in") -> None:
        if not values:
            return
        used.extend(values)
        if op == "in":
            clause = f"| where {column} in~ ({_kql_in_list(values)})"
        else:
            clause = f"| where {column} has_any ({_kql_in_list(values)})"
        kql = (
            f"{table}\n{window}\n{clause}\n"
            f"| project Timestamp, DeviceName, {column}"
        )
        queries.append(
            {"name": name, "table": table, "kql": kql, "rationale": f"Hunt {table}.{column} for the IOCs."}
        )

    hashes = intel.by_type(IOCType.SHA256)
    add_query("File hash hunt", "DeviceFileEvents", "SHA256", hashes)
    add_query("Process hash hunt", "DeviceProcessEvents", "SHA256", intel.by_type(IOCType.SHA256))
    add_query("IP network hunt", "DeviceNetworkEvents", "RemoteIP", intel.by_type(IOCType.IPV4))
    add_query(
        "Domain/URL hunt", "DeviceNetworkEvents", "RemoteUrl",
        intel.by_type(IOCType.DOMAIN) + intel.by_type(IOCType.URL), op="has_any",
    )
    add_query("CVE exposure hunt", "DeviceTvmSoftwareVulnerabilities", "CveId", intel.by_type(IOCType.CVE))

    # De-dup iocs_used preserving order.
    seen: set[str] = set()
    iocs_used = [v for v in used if not (v in seen or seen.add(v))]

    return {
        "title": f"Hunt for indicators from {intel.source or 'threat intel'}",
        "description": "Auto-generated Defender hunting queries for the extracted IOCs.",
        "queries": queries,
        "iocs_used": iocs_used,
        "mitre_techniques": [],
        "caveats": "Generated offline (stub); review before running.",
    }
