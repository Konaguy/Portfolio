"""Exception types for the CrowdStrike Falcon RTR toolkit."""

from __future__ import annotations

from typing import Any, Optional


class FalconClientError(Exception):
    """
    Raised whenever a falconpy SDK call returns a non-success status.

    Wraps the raw falconpy response so calling code (playbooks,
    orchestrators) can catch one exception type instead of inspecting
    falconpy's response dict shape directly at every call site.
    """

    def __init__(self, message: str, response: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.response = response or {}

    @property
    def status_code(self) -> Optional[int]:
        return self.response.get("status_code")

    @property
    def errors(self) -> list:
        body = self.response.get("body", {})
        return body.get("errors", []) if isinstance(body, dict) else []

    def __str__(self) -> str:
        base = super().__str__()
        if self.errors:
            return f"{base} (status={self.status_code}, errors={self.errors})"
        return base


class HostNotFoundError(FalconClientError):
    """Raised when a device ID doesn't resolve to a known host."""


class RTRSessionError(FalconClientError):
    """Raised when an RTR session fails to initialize or a command fails."""
