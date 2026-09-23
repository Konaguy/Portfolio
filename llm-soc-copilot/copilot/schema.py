"""
Data models for the SOC copilot: the alert coming in, the enrichment
context assembled before the LLM call, and the structured verdict coming
out. Using Pydantic here isn't decorative -- it's what lets triage.py
validate the LLM's output against a real schema instead of trusting
whatever JSON-shaped text comes back.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecommendedAction(str, Enum):
    CLOSE_FALSE_POSITIVE = "close_false_positive"
    MONITOR = "monitor"
    ESCALATE_TIER2 = "escalate_tier2"
    CONTAIN_IMMEDIATELY = "contain_immediately"


class Alert(BaseModel):
    """A normalized alert, in the same shape the security-automation-soar
    orchestrator uses internally -- this copilot is designed to slot into
    that pipeline as the enrichment/triage step."""

    alert_id: str
    source: str = Field(description="e.g. 'sentinel', 'defender', 'crowdstrike'")
    raw_title: str
    raw_description: str = ""
    severity_reported: Optional[Severity] = Field(
        default=None, description="Severity as reported by the source platform, if any"
    )
    entity_type: str = Field(description="host | account | ip | url | hash")
    entity_value: str
    timestamp: datetime
    mitre_techniques: list[str] = Field(default_factory=list)
    raw_event_link: Optional[str] = None

    @field_validator("mitre_techniques")
    @classmethod
    def techniques_look_like_attack_ids(cls, v: list[str]) -> list[str]:
        for technique in v:
            if not technique.startswith("T"):
                raise ValueError(f"'{technique}' doesn't look like a MITRE ATT&CK technique ID")
        return v


class PriorCase(BaseModel):
    """A single retrieved prior case, surfaced by the RAG layer."""

    case_id: str
    summary: str
    resolution: str
    was_false_positive: bool
    similarity_score: float = Field(ge=0.0, le=1.0)


class EnrichmentContext(BaseModel):
    """Everything gathered about an alert before it's handed to the LLM."""

    asset_criticality: Optional[str] = Field(
        default=None, description="e.g. 'crown_jewel', 'standard', 'unknown'"
    )
    asset_owner: Optional[str] = None
    prior_cases: list[PriorCase] = Field(default_factory=list)


class TriageParseError(Exception):
    """Raised by triage.py when the model's tool-use output fails
    validation against the TriageVerdict schema."""


class TriageVerdict(BaseModel):
    """The copilot's structured output. This is what the LLM is forced to
    produce via tool-use (see triage.py) -- never free-text."""

    alert_id: str
    severity: Severity
    false_positive_probability: float = Field(
        ge=0.0, le=1.0, description="0 = certainly a true positive, 1 = certainly benign"
    )
    recommended_action: RecommendedAction
    rationale: str = Field(min_length=1)
    cited_case_ids: list[str] = Field(
        default_factory=list,
        description="case_ids from EnrichmentContext.prior_cases the model relied on",
    )
