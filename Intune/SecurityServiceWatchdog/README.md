# Endpoint Security Service Watchdog (Intune)

Checks that the endpoint security agents are running, restarts anything that has
stopped, and emails a support ticket for whatever it cannot fix.

Monitored services:

| Service name      | Product                                      | Missing = alert |
|-------------------|----------------------------------------------|-----------------|
| `WinDefend`       | Microsoft Defender Antivirus                 | yes             |
| `Sense`           | Microsoft Defender for Endpoint (EDR sensor) | yes             |
| `HuntressAgent`   | Huntress Agent                                | yes             |
| `HuntressUpdater` | Huntress Updater                              | no              |
| `HuntressRio`     | Huntress EDR (Rio) — newer agents only        | no              |

## Files

- `Detect-SecurityServices.ps1` — detection half of an Intune Remediation. Exits 1
  when any monitored service is stopped or missing.
- `Repair-SecurityServices.ps1` — does the work: repair start type, restart with
  retries, verify, and email the ticket. Also runs fine standalone as a Platform
  Script.

## What the repair script does per service

1. Reads current status and start type.
2. If the start type is `Disabled`, sets it back to `Automatic` (toggle with
   `Repair.RepairStartType`).
3. Waits out `StopPending` / `StartPending`, resumes a `Paused` service, then
   calls `Start-Service` — 3 attempts, 5 s apart, waiting up to 90 s for the
   service to reach `Running`.
4. Re-checks status. Anything still not running is collected for the ticket,
   along with the exception text and the most recent related `System` event log
   entry (7000/7001/7009/7011/7023/7024/7031/7034).

The ticket email also carries device details (name, serial, model, OS, build,
last boot, logged-on user, IP) and security context: Defender running mode
(`Normal` / `Passive` / `EDR Block`), real-time protection state, signature age,
tamper protection state, AV products registered in Security Center, and MDE
onboarding state. That context matters — a stopped `WinDefend` on a device where
a third-party AV owns real-time protection is a different ticket than one where
Defender is supposed to be primary.

A copy of the last ticket is always written to
`C:\ProgramData\SecurityServiceWatchdog\last-ticket.html`, even when mail fails.

## Configure

Everything editable is in the `CONFIG` region at the top of
`Repair-SecurityServices.ps1`. At minimum set:

```powershell
Organization = 'CONTOSO'
Email.To     = @('support@contoso.com')     # your ticket queue address
Email.From   = 'intune-alerts@contoso.com'
```

### Email transport

**`Smtp`** (default) — relay through an internal or authenticated SMTP host:

```powershell
Transport = 'Smtp'
Smtp = @{ Server = 'smtp.contoso.com'; Port = 25; UseSsl = $false; CredentialFile = '' }
```

An unauthenticated internal relay that accepts mail from your subnets is the
simplest option for a SYSTEM-context script — no secret ends up on the endpoint.
To authenticate, export a credential **as SYSTEM on the device** (e.g. via
PsExec) and point `CredentialFile` at it; `Import-Clixml` only decrypts under the
account that wrote the file.

**`Graph`** — Microsoft Graph `sendMail` with an app registration
(`Mail.Send` application permission, ideally scoped with an application access
policy to the single sending mailbox):

```powershell
Transport = 'Graph'
Graph = @{ TenantId = '<guid>'; ClientId = '<guid>'; Sender = 'intune-alerts@contoso.com'
           SecretEnvironmentVariable = 'SECWATCH_GRAPH_SECRET'; SecretFile = '' }
```

Do **not** paste the client secret into the script — anything shipped in an
Intune script body is readable by anyone who can read the policy, and by anyone
with local admin on an enrolled device. Deliver it as a machine environment
variable or a protected file and reference it by name. If you cannot protect a
secret on the endpoint, use the SMTP relay instead, or have the script write an
event and alert from the server side.

### Noise control

`Alerting.CooldownHours` (default 12) stops a persistently broken agent from
opening a new ticket on every run. State lives in
`C:\ProgramData\SecurityServiceWatchdog\alert-state.json`, per service. Set to
`0` to alert every run, or use `-Force` to bypass it during testing.

## Deploy

### Option A — Remediation (recommended, runs on a schedule)

Intune admin center → **Devices → Remediations → Create script package**

- Detection script: `Detect-SecurityServices.ps1`
- Remediation script: `Repair-SecurityServices.ps1`
- Run this script using the logged-on credentials: **No**
- Enforce script signature check: **No** (unless you sign it)
- Run script in 64-bit PowerShell: **Yes**
- Schedule: hourly or daily, depending on how fast you want to know

Exit codes: detection `0` = compliant / `1` = run remediation. Remediation `0` =
fixed, `1` = still down (ticket raised), `2` = script error. The last STDOUT line
shows up in the remediation output column, so the portal shows e.g.
`FAIL - Sense could not be restarted. Support ticket e-mailed.`

### Option B — Platform script (runs once, then retries on failure)

**Devices → Scripts and remediations → Platform scripts → Add → Windows 10 and later**,
upload `Repair-SecurityServices.ps1`, run as SYSTEM, 64-bit host. Note that
platform scripts do not run on a repeating schedule, so Option A is better for
ongoing monitoring.

## Test before rolling out

Run elevated (ideally as SYSTEM via PsExec, since that is how Intune runs it):

```powershell
# check + repair, no mail, full trace
.\Repair-SecurityServices.ps1 -NoEmail -Verbose

# verify the mail path only — sends a clearly-labelled TEST ticket
.\Repair-SecurityServices.ps1 -TestEmail

# exercise one service, ignoring the alert cooldown
.\Repair-SecurityServices.ps1 -ServiceName HuntressAgent -Force -Verbose
```

To simulate a real failure on a lab device, stop `HuntressAgent` (Defender's
services are protected — see below) and run the script.

Log: `C:\ProgramData\SecurityServiceWatchdog\Repair-SecurityServices.log`,
rotated at 1 MB, 3 generations kept.

## Things to know

- **Tamper Protection.** With it enabled, `WinDefend` and `Sense` cannot be
  reconfigured or started even by SYSTEM; `Set-Service` / `Start-Service` return
  access denied. That is by design. The script does not try to work around it —
  it records the error and raises the ticket, which is the correct outcome, since
  Defender being stopped under Tamper Protection needs a human.
- **Defender in passive mode.** If a third-party AV is registered, `WinDefend`
  can legitimately be stopped or passive. Check `DefenderRunningMode` in the
  ticket before treating it as an incident; drop `WinDefend` from the list on
  fleets where another AV is primary.
- **`Sense` on non-onboarded devices.** `Sense` exists on Windows 10/11 but only
  runs once the device is onboarded to Defender for Endpoint. Target the policy
  at onboarded devices, or set `Required = $false` for `Sense`.
- **Huntress service names** vary by agent version. `HuntressAgent` and
  `HuntressUpdater` are on every version; `HuntressRio` only on agents with the
  EDR component. Missing optional services are skipped silently.
- The script does not stop or reinstall anything. Repeated restart failures mean
  a repair or reinstall of the agent, which is deliberately left to a technician.
