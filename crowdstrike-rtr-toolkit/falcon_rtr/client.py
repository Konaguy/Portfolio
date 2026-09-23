"""
FalconClient: a thin, tested wrapper around the CrowdStrike falconpy SDK
for the incident-response actions called repeatedly across SOAR playbooks.

Design principles (see README for the full rationale):
    - Idempotency: containment actions check current state before acting.
    - Narrow exception surface: all falconpy errors are re-raised as
      FalconClientError (or a subclass) rather than leaking SDK internals.
    - No implicit retries: retry/backoff is the caller's responsibility.
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

from falconpy import Hosts, RealTimeResponse, Alerts

from .exceptions import FalconClientError, HostNotFoundError, RTRSessionError


def _is_success(response: dict[str, Any]) -> bool:
    status = response.get("status_code", 500)
    return 200 <= status < 300


def _raise_for_error(
    response: dict[str, Any],
    message: str,
    exc_type: type[FalconClientError] = FalconClientError,
) -> None:
    if not _is_success(response):
        raise exc_type(message, response=response)


class FalconClient:
    """
    Wraps falconpy's Hosts, RealTimeResponse, and Alerts service classes.

    Credentials are read from the constructor args, falling back to the
    FALCON_CLIENT_ID / FALCON_CLIENT_SECRET environment variables -- the
    same convention falconpy itself documents for CI/service-account use.
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: str = "auto",
        **falconpy_kwargs: Any,
    ):
        client_id = client_id or os.environ.get("FALCON_CLIENT_ID")
        client_secret = client_secret or os.environ.get("FALCON_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ValueError(
                "Falcon API credentials required: pass client_id/client_secret "
                "or set FALCON_CLIENT_ID / FALCON_CLIENT_SECRET."
            )

        auth = {
            "client_id": client_id,
            "client_secret": client_secret,
            "base_url": base_url,
            **falconpy_kwargs,
        }
        self._hosts = Hosts(**auth)
        self._rtr = RealTimeResponse(**auth)
        self._alerts = Alerts(**auth)

    # ------------------------------------------------------------------
    # Host details / containment state
    # ------------------------------------------------------------------

    def get_host_details(self, device_id: str) -> dict[str, Any]:
        """Return the raw device details resource for a single host."""
        response = self._hosts.get_device_details_v2(ids=[device_id])
        _raise_for_error(
            response, f"Failed to get details for host {device_id}", HostNotFoundError
        )
        resources = response.get("body", {}).get("resources", [])
        if not resources:
            raise HostNotFoundError(f"No host found for device_id={device_id}", response=response)
        return resources[0]

    def is_contained(self, device_id: str) -> bool:
        """True if the host is currently network-contained (or pending)."""
        details = self.get_host_details(device_id)
        return details.get("status") in ("contained", "contain_pending")

    # ------------------------------------------------------------------
    # Containment (idempotent)
    # ------------------------------------------------------------------

    def contain_host(self, device_id: str, note: Optional[str] = None) -> dict[str, Any]:
        """
        Network-isolate a host. No-ops (returns immediately) if the host
        is already contained or a containment action is already pending,
        so this is safe to call repeatedly from a playbook retry.
        """
        if self.is_contained(device_id):
            return {"device_id": device_id, "action": "contain", "status": "already_contained"}

        kwargs: dict[str, Any] = {"action_name": "contain", "ids": [device_id]}
        if note:
            kwargs["note"] = note
        response = self._hosts.perform_action(**kwargs)
        _raise_for_error(response, f"Failed to contain host {device_id}")
        return {"device_id": device_id, "action": "contain", "status": "requested"}

    def lift_containment(self, device_id: str, note: Optional[str] = None) -> dict[str, Any]:
        """Reverse containment on a host. No-ops if not currently contained."""
        if not self.is_contained(device_id):
            return {"device_id": device_id, "action": "lift_containment", "status": "not_contained"}

        kwargs: dict[str, Any] = {"action_name": "lift_containment", "ids": [device_id]}
        if note:
            kwargs["note"] = note
        response = self._hosts.perform_action(**kwargs)
        _raise_for_error(response, f"Failed to lift containment on host {device_id}")
        return {"device_id": device_id, "action": "lift_containment", "status": "requested"}

    # ------------------------------------------------------------------
    # Real Time Response
    # ------------------------------------------------------------------

    def _init_rtr_session(self, device_id: str) -> str:
        """Start a batch RTR session on one host and return the batch ID."""
        response = self._rtr.batch_init_sessions(host_ids=[device_id])
        _raise_for_error(
            response, f"Failed to initialize RTR session on {device_id}", RTRSessionError
        )
        batch_id = response.get("body", {}).get("batch_id")
        if not batch_id:
            raise RTRSessionError(
                f"RTR session init returned no batch_id for {device_id}", response=response
            )
        return batch_id

    def run_rtr_command(
        self,
        device_id: str,
        base_command: str,
        command_string: str,
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        """
        Run a single RTR active-responder command on one host and return
        the per-host result. `base_command` is the RTR command family
        (e.g. 'ps', 'kill', 'get'); `command_string` is the full command
        line, matching the RTR console syntax.
        """
        batch_id = self._init_rtr_session(device_id)
        response = self._rtr.batch_active_responder_command(
            batch_id=batch_id,
            base_command=base_command,
            command_string=command_string,
            host_timeout_duration=f"{timeout_seconds}s",
        )
        _raise_for_error(
            response, f"RTR command '{command_string}' failed on {device_id}", RTRSessionError
        )
        resources = response.get("body", {}).get("combined", {}).get("resources", {})
        result = resources.get(device_id, {})
        return result

    def kill_process(self, device_id: str, pid: int) -> dict[str, Any]:
        """Terminate a process by PID via RTR's `kill` command."""
        return self.run_rtr_command(
            device_id=device_id,
            base_command="kill",
            command_string=f"kill {pid}",
        )

    def collect_process_list(self, device_id: str) -> dict[str, Any]:
        """Run `ps` via RTR -- used for evidence collection before/after containment."""
        return self.run_rtr_command(
            device_id=device_id,
            base_command="ps",
            command_string="ps",
        )

    # ------------------------------------------------------------------
    # Detection / alert status
    # ------------------------------------------------------------------

    def update_detection_status(
        self,
        detection_id: str,
        status: str,
        comment: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Update a detection's status (e.g. 'closed', 'in_progress',
        'reopened') -- typically called from the case-closure-sync
        playbook once a ServiceNow case resolves.
        """
        valid_statuses = {"new", "in_progress", "closed", "reopened"}
        if status not in valid_statuses:
            raise ValueError(f"status must be one of {valid_statuses}, got {status!r}")

        kwargs: dict[str, Any] = {
            "composite_ids": [detection_id],
            "action_parameters": [{"name": "update_status", "value": status}],
        }
        response = self._alerts.update_alerts_v3(**kwargs)
        _raise_for_error(response, f"Failed to update detection {detection_id} to {status}")

        if comment:
            self._alerts.update_alerts_v3(
                composite_ids=[detection_id],
                action_parameters=[{"name": "append_comment", "value": comment}],
            )

        return {"detection_id": detection_id, "status": status}

    # ------------------------------------------------------------------
    # Polling helper
    # ------------------------------------------------------------------

    def wait_for_containment(
        self, device_id: str, timeout_seconds: int = 120, poll_interval: int = 5
    ) -> bool:
        """
        Poll host status until containment completes or timeout elapses.
        Useful after contain_host() when a playbook needs confirmation
        before proceeding (e.g. before attaching evidence to a case).
        """
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            details = self.get_host_details(device_id)
            if details.get("status") == "contained":
                return True
            time.sleep(poll_interval)
        return False
