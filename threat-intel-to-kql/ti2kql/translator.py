"""
The translator: orchestrates extraction -> LLM generation -> validation.

    raw intel ─► (feeds/iocs) ─► ThreatIntel
                                     │
                                     ▼
                       LLM (forced tool-use) ─► GeneratedHunt
                                     │
                                     ▼
                       validate against schema + table catalog + source IOCs
                                     │
                                     ▼
                              GeneratedHunt (trusted)

Validation failures raise `HuntParseError` / `ValidationError` rather than
returning dubious KQL -- the whole point of the project is that what reaches
the analyst is grounded and syntactically sound.
"""

from __future__ import annotations

from .config import Settings
from .llm import LLMClient
from .prompts import SYSTEM_PROMPT, build_user_message
from .schema import GeneratedHunt, HuntParseError, ThreatIntel, ValidationError
from .validate import validate_hunt


class Translator:
    def __init__(self, llm: LLMClient, settings: Settings | None = None) -> None:
        self._llm = llm
        self._settings = settings or Settings()

    def translate(self, intel: ThreatIntel) -> GeneratedHunt:
        if not intel.iocs:
            raise HuntParseError(
                "No IOCs were extracted from the intel; nothing to hunt for."
            )

        raw = self._llm.generate_hunt(SYSTEM_PROMPT, build_user_message(intel))

        try:
            hunt = GeneratedHunt(**raw)
        except Exception as exc:  # pydantic.ValidationError
            raise HuntParseError(f"LLM output failed schema validation: {exc}") from exc

        problems = validate_hunt(
            hunt, intel.ioc_values(), strict_tables=self._settings.strict_tables
        )
        if problems:
            raise ValidationError(
                "Generated KQL failed validation:\n- " + "\n- ".join(problems)
            )
        return hunt
