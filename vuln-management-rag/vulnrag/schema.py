"""
Data models for the vulnerability-management RAG assistant.

Two families of models:

1.  **Corpus models** (`Vulnerability`, `PolicyChunk`) -- the things we
    ingest and embed. Each carries a stable `chunk_id` used both as the
    Qdrant point id and as the citation key the LLM is allowed to cite.
2.  **Runtime models** (`RetrievedChunk`, `RemediationAnswer`) -- what
    flows through the agent graph. `RemediationAnswer` is the structured
    output the LLM is forced to produce via tool-use (see llm.py), never
    free text, so it can be validated and its citations checked against
    what was actually retrieved.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class QueryIntent(str, Enum):
    """What the analyst is asking for -- set by the router node and used to
    pick which specialist agent answers."""

    REMEDIATION = "remediation"
    PRIORITIZATION = "prioritization"
    POLICY = "policy"
    GENERAL = "general"


class Vulnerability(BaseModel):
    """One finding from a Tenable/Nessus export, normalized."""

    chunk_id: str = Field(description="Stable id, also the Qdrant point id and citation key")
    plugin_id: str
    cve: list[str] = Field(default_factory=list)
    name: str
    severity: Severity
    cvss_base_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    vpr_score: Optional[float] = Field(
        default=None, ge=0.0, le=10.0, description="Tenable Vulnerability Priority Rating"
    )
    host: str
    port: Optional[str] = None
    description: str = ""
    solution: str = ""
    see_also: list[str] = Field(default_factory=list)

    @field_validator("cve", mode="before")
    @classmethod
    def split_cve_field(cls, v: object) -> list[str]:
        # Tenable CSV packs multiple CVEs into one comma/space-separated cell.
        if v is None or v == "":
            return []
        if isinstance(v, str):
            return [c.strip() for c in v.replace(";", ",").split(",") if c.strip()]
        return list(v)  # type: ignore[arg-type]

    def to_document(self) -> str:
        """The text that gets embedded and shown to the LLM as evidence."""
        cve_str = ", ".join(self.cve) or "(none)"
        return (
            f"[{self.chunk_id}] Vulnerability: {self.name}\n"
            f"Plugin ID: {self.plugin_id} | CVE: {cve_str}\n"
            f"Severity: {self.severity.value} | CVSS: {self.cvss_base_score} | "
            f"VPR: {self.vpr_score}\n"
            f"Affected host: {self.host}{':' + self.port if self.port else ''}\n"
            f"Description: {self.description}\n"
            f"Vendor solution: {self.solution}"
        )


class PolicyChunk(BaseModel):
    """A chunk of an enterprise security policy or standard."""

    chunk_id: str = Field(description="Stable id, also the Qdrant point id and citation key")
    source: str = Field(description="Policy document filename or title")
    section: str = Field(default="", description="Heading this chunk came from")
    text: str

    def to_document(self) -> str:
        heading = f" > {self.section}" if self.section else ""
        return f"[{self.chunk_id}] Policy: {self.source}{heading}\n{self.text}"


class RetrievedChunk(BaseModel):
    """A corpus item returned by the vector store, with its score."""

    chunk_id: str
    kind: str = Field(description="'vulnerability' or 'policy'")
    document: str = Field(description="The embedded text, for display to the LLM")
    score: float
    payload: dict = Field(default_factory=dict)


class RemediationAnswer(BaseModel):
    """The assistant's structured output. The LLM is forced to produce this
    via tool-use (llm.py); it is never parsed from free text."""

    summary: str = Field(min_length=1, description="One-paragraph answer to the analyst")
    remediation_steps: list[str] = Field(
        default_factory=list, description="Ordered, concrete steps the analyst can act on"
    )
    prioritization_rationale: str = Field(
        default="", description="Why this ranks where it does (CVSS/VPR/asset context/policy SLA)"
    )
    cited_chunk_ids: list[str] = Field(
        default_factory=list,
        description="chunk_ids from the retrieved context the answer relied on",
    )

    model_config = ConfigDict(extra="forbid")


class RagError(Exception):
    """Base class for vulnrag errors."""


class AnswerParseError(RagError):
    """Raised when the LLM's tool-use output fails schema validation or cites
    a chunk_id that was not in the retrieved context (a hallucinated
    citation, which we treat as a hard failure rather than trust)."""
