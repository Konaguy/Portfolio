"""Runtime configuration, env-driven with sensible defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Opus 5 supports the forced tool-use that llm.py uses for structured
    # output. Override with ANTHROPIC_MODEL for a cheaper model on high volume.
    anthropic_model: str = "claude-opus-5"
    max_tokens: int = 2000
    # Reject generated KQL that references a table not in the known catalog.
    strict_tables: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            anthropic_model=os.getenv("ANTHROPIC_MODEL", cls.anthropic_model),
            max_tokens=int(os.getenv("TI2KQL_MAX_TOKENS", cls.max_tokens)),
            strict_tables=os.getenv("TI2KQL_STRICT_TABLES", "1") not in {"0", "false", "False"},
        )
