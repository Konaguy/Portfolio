"""
Data models for the threat-intel -> KQL translator.

`IOC` and `ThreatIntel` are the (deterministically extracted) input side;
`HuntQuery` and `GeneratedHunt` are the structured output the LLM is forced to
produce via tool-use, so it can be validated rather than parsed from prose.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"


class IOC(BaseModel):
    type: IOCType
    value: str

    def __hash__(self) -> int:  # allow set() dedup
        return hash((self.type, self.value))

    model_config = ConfigDict(frozen=True)


class ThreatIntel(BaseModel):
    """Normalized input: the raw text plus the IOCs extracted from it."""

    source: str = Field(default="", description="Where this intel came from")
    raw_text: str
    iocs: list[IOC] = Field(default_factory=list)

    def ioc_values(self) -> set[str]:
        return {i.value for i in self.iocs}

    def by_type(self, ioc_type: IOCType) -> list[str]:
        return [i.value for i in self.iocs if i.type == ioc_type]


class HuntQuery(BaseModel):
    """A single generated KQL hunting query."""

    name: str = Field(min_length=1)
    table: str = Field(description="Primary Defender advanced-hunting table it queries")
    kql: str = Field(min_length=1)
    rationale: str = ""

    model_config = ConfigDict(extra="forbid")


class GeneratedHunt(BaseModel):
    """The translator's structured output -- forced from the LLM via tool-use."""

    title: str = Field(min_length=1)
    description: str = ""
    queries: list[HuntQuery] = Field(default_factory=list)
    iocs_used: list[str] = Field(
        default_factory=list,
        description="IOC values the queries hunt for; must be a subset of the source IOCs",
    )
    mitre_techniques: list[str] = Field(default_factory=list)
    caveats: str = ""

    model_config = ConfigDict(extra="forbid")


class TI2KQLError(Exception):
    """Base error."""


class HuntParseError(TI2KQLError):
    """LLM output failed schema validation, or hunted for an IOC that was not
    in the source intel (a fabricated indicator, treated as a hard failure)."""


class ValidationError(TI2KQLError):
    """Generated KQL failed static validation."""
