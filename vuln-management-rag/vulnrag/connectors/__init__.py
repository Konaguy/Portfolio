"""
Connectors that pull vulnerability findings from live sources into the
`Vulnerability` schema the rest of vulnrag already understands.

`DefenderConnector` pulls from Microsoft Defender Vulnerability Management
(MDVM) via the Defender for Endpoint API; `FakeDefenderConnector` returns
bundled sample findings so the whole scan -> ingest -> dashboard flow runs
with no Azure tenant.
"""

from .defender import (
    AuthConfig,
    DefenderConnector,
    FakeDefenderConnector,
    finding_to_vulnerability,
)

__all__ = [
    "AuthConfig",
    "DefenderConnector",
    "FakeDefenderConnector",
    "finding_to_vulnerability",
]
