"""
Microsoft Defender for Endpoint / Defender Vulnerability Management connector.

Pulls per-device software-vulnerability findings (the shape returned by the
Defender for Endpoint "SoftwareVulnerabilitiesByMachine" report) and maps them
into vulnrag's `Vulnerability` model, so the existing embed -> Qdrant ->
LangGraph pipeline works on live Azure data without any downstream changes.

Auth is OAuth2 client credentials (an Entra ID app registration / service
principal). Required Defender for Endpoint *application* permissions:
`Vulnerability.Read.All` and `Machine.Read.All`, with admin consent granted.

`requests` is imported lazily so the package (and its tests, which use
`FakeDefenderConnector`) don't require it or any network access.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from ..schema import Severity, Vulnerability

_MDE_BASE = "https://api.securitycenter.microsoft.com"
_LOGIN = "https://login.microsoftonline.com"
_SCOPE = "https://api.securitycenter.microsoft.com/.default"

_SEVERITY_MAP = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass(frozen=True)
class AuthConfig:
    tenant_id: str
    client_id: str
    client_secret: str

    @classmethod
    def from_env(cls) -> "AuthConfig":
        missing = [
            k for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
            if not os.getenv(k)
        ]
        if missing:
            raise ValueError(
                "Missing Azure credentials in environment: " + ", ".join(missing)
            )
        return cls(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )


class Connector(Protocol):
    def get_findings(self, device_names: list[str] | None = None) -> list[dict]:
        ...


def _severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get((raw or "").lower(), Severity.LOW)


def _float_or_none(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _finding_chunk_id(device: str, cve: str, software: str) -> str:
    basis = f"{device}|{cve}|{software}".encode("utf-8")
    return "vuln-" + hashlib.sha1(basis).hexdigest()[:12]


def finding_to_vulnerability(finding: dict) -> Vulnerability:
    """Map a Defender SoftwareVulnerabilitiesByMachine record to Vulnerability."""
    device = finding.get("deviceName") or finding.get("computerDnsName") or "unknown"
    cve = finding.get("cveId") or finding.get("id") or ""
    vendor = finding.get("softwareVendor", "")
    name = finding.get("softwareName", "")
    version = finding.get("softwareVersion", "")
    software = f"{vendor} {name} {version}".strip()

    exploit = finding.get("exploitabilityLevel", "")
    exploit_note = f" Exploitability: {exploit}." if exploit and exploit != "NoExploit" else ""
    fixed_version = finding.get("recommendedSecurityUpdate") or finding.get(
        "recommendedSecurityUpdateId"
    )
    solution = (
        f"Apply the recommended update: {fixed_version}"
        if fixed_version
        else "Apply the latest security update from the vendor for this software."
    )

    title = f"{software} — {cve}" if cve else software
    description = (
        f"{cve} affects {software} on {device} "
        f"({finding.get('osPlatform', 'unknown OS')}).{exploit_note}"
    ).strip()

    return Vulnerability(
        chunk_id=_finding_chunk_id(device, cve, software),
        plugin_id=cve or _finding_chunk_id(device, cve, software),
        cve=[cve] if cve else [],
        name=title,
        severity=_severity(finding.get("vulnerabilitySeverityLevel", "")),
        cvss_base_score=_float_or_none(finding.get("cvssScore")),
        vpr_score=None,  # MDVM uses exploitability, not Tenable VPR
        host=device,
        port=None,
        description=description,
        solution=solution,
        see_also=[f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else [],
    )


def findings_to_vulnerabilities(findings: Iterable[dict]) -> list[Vulnerability]:
    return [finding_to_vulnerability(f) for f in findings]


class DefenderConnector:
    """Live connector to Defender for Endpoint / MDVM."""

    def __init__(self, auth: AuthConfig | None = None, timeout: int = 30) -> None:
        self._auth = auth or AuthConfig.from_env()
        self._timeout = timeout
        self._token: str | None = None

    def _requests(self):
        try:
            import requests
        except ImportError as exc:  # pragma: no cover - only without the dep
            raise ImportError(
                "The Defender connector needs 'requests'. Install it "
                "(pip install requests) or use FakeDefenderConnector for offline demos."
            ) from exc
        return requests

    def _get_token(self) -> str:
        if self._token:
            return self._token
        requests = self._requests()
        resp = requests.post(
            f"{_LOGIN}/{self._auth.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._auth.client_id,
                "client_secret": self._auth.client_secret,
                "scope": _SCOPE,
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}", "Accept": "application/json"}

    def get_findings(self, device_names: list[str] | None = None) -> list[dict]:
        """Return per-device software-vulnerability findings, optionally
        filtered to a set of device names (case-insensitive prefix/exact
        match on computerDnsName)."""
        requests = self._requests()
        findings: list[dict] = []
        url: str | None = f"{_MDE_BASE}/api/machines/SoftwareVulnerabilitiesByMachine"
        while url:
            resp = requests.get(url, headers=self._headers(), timeout=self._timeout)
            resp.raise_for_status()
            body = resp.json()
            findings.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        if device_names:
            wanted = {d.lower() for d in device_names}
            findings = [f for f in findings if _matches(f, wanted)]
        return findings


def _matches(finding: dict, wanted: set[str]) -> bool:
    name = (finding.get("deviceName") or finding.get("computerDnsName") or "").lower()
    short = name.split(".")[0]
    return any(name == w or short == w or name.startswith(w) for w in wanted)


class FakeDefenderConnector:
    """Offline connector that serves bundled sample findings, so the full
    scan -> ingest -> dashboard flow runs without an Azure tenant."""

    def __init__(self, findings: list[dict]) -> None:
        self._findings = findings

    @classmethod
    def from_json_file(cls, path: str) -> "FakeDefenderConnector":
        import json
        from pathlib import Path

        data = json.loads(Path(path).read_text(encoding="utf-8"))
        findings = data.get("value", data) if isinstance(data, dict) else data
        return cls(findings)

    def get_findings(self, device_names: list[str] | None = None) -> list[dict]:
        if not device_names:
            return list(self._findings)
        wanted = {d.lower() for d in device_names}
        return [f for f in self._findings if _matches(f, wanted)]
