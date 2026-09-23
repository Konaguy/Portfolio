# CrowdStrike Falcon RTR Toolkit

A small, tested Python library wrapping the CrowdStrike Falcon API
(via [`falconpy`](https://github.com/CrowdStrike/falconpy)) for the
handful of incident-response actions a SOC automation layer calls
over and over: containment, process termination, evidence collection,
and detection-status updates.

## Why this exists

Most IR automation code I've seen calls the raw SDK inline, scattered
across playbook scripts, with no shared error handling or idempotency
checks. This packages those calls once, tested, so a playbook (or the
`security-automation-soar` orchestrator in this same portfolio) can call
`contain_host("aid-123")` instead of hand-rolling the API call every time.

## What's included

| Function | Falcon API used | Purpose |
|---|---|---|
| `contain_host(device_id)` | Hosts `PerformActionV2` (`action_name=contain`) | Network-isolate a host |
| `lift_containment(device_id)` | Hosts `PerformActionV2` (`action_name=lift_containment`) | Reverse containment |
| `get_host_details(device_id)` | Hosts `GetDeviceDetailsV2` | Pull host metadata (hostname, OS, containment state) |
| `is_contained(device_id)` | Hosts `GetDeviceDetailsV2` | Idempotency check before containing/lifting |
| `run_rtr_command(device_id, base_command, command_string)` | Real Time Response `BatchInitSessions` + `BatchActiveResponderCmd` | Run a single RTR command (e.g. kill a process, collect a file) on one host |
| `kill_process(device_id, pid)` | RTR `kill` command via `run_rtr_command` | Terminate a specific process by PID |
| `update_detection_status(detection_id, status)` | Alerts `UpdateAlertsV3` | Close/update a detection's status after case resolution |

Every state-changing function checks current state first where the API
allows it (see `is_contained()`), so calling `contain_host()` twice in a
row is a no-op on the second call rather than an error or a wasted API
call.

## Usage

```python
from falcon_rtr import FalconClient

client = FalconClient(client_id="...", client_secret="...")

# Containment (idempotent)
client.contain_host("8f3a1b2c...")
client.contain_host("8f3a1b2c...")  # no-op, already contained

# Run an RTR command
result = client.run_rtr_command(
    device_id="8f3a1b2c...",
    base_command="ps",
    command_string="ps",
)

# Kill a process
client.kill_process(device_id="8f3a1b2c...", pid=4821)

# Close out a detection after the case resolves
client.update_detection_status(detection_id="ldt:...", status="closed")
```

Credentials can also be supplied via environment variables
(`FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`) — see `falcon_rtr/client.py`.

## Testing

```bash
pip install -r requirements.txt
pytest tests/
```

Tests mock the `falconpy` SDK calls (no live Falcon tenant required) and
verify: correct API parameters are passed, idempotency checks short-
circuit redundant actions, and errors from the SDK are wrapped in the
library's own exception type rather than leaking raw SDK exceptions.

## Design notes

- **Idempotency first.** `contain_host()` and `lift_containment()` both
  call `is_contained()` before acting. This matters in a SOAR context
  where a playbook step might be retried after a transient failure —
  you don't want a retry to be indistinguishable from a duplicate action
  in the audit log.
- **Narrow exception surface.** All falconpy errors are caught and
  re-raised as `FalconClientError` with the original response body
  attached, so calling code (playbooks) can catch one exception type
  instead of guessing at falconpy's internals.
- **No implicit retries.** Retry/backoff logic is deliberately left to
  the caller (the orchestrator) rather than baked into this library —
  a playbook needs to control retry semantics per action type (e.g.
  containment retries differently than evidence collection).
