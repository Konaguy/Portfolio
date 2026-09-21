# SOAR Detection Rules — Defender XDR + Microsoft Sentinel

Detection content for a Security Orchestration, Automation & Response (SOAR)
pipeline built around Microsoft Defender XDR, Microsoft Sentinel, and a
case-management system of record (ServiceNow SecOps). The rules are the
*detection* layer: they fire the alerts that the orchestrator enriches, tickets,
and responds to.

Two files, 15 parallel detections each:

| File | Platform | Deploy target |
|------|----------|---------------|
| `defender-custom-detection-rules.json` | Microsoft Defender XDR | Graph Security API — `POST /beta/security/rules/detectionRules` (scope `CustomDetection.ReadWrite.All`) |
| `sentinel-analytics-rules.yaml` | Microsoft Sentinel | `Microsoft.SecurityInsights/alertRules` ARM API, or the Sentinel Repositories (GitHub/DevOps) content pipeline |

The two are kept in lockstep so you can run either platform as the primary
detection engine (or both, deduplicating downstream) without rewriting logic.
`CD-nn` in the Defender file corresponds to `SR-nn` in the Sentinel file.

## Where these fit in the SOAR architecture

```
[Defender XDR / Sentinel]  ← these rules generate the alerts/incidents
        │  (webhook / Graph alert / Sentinel incident)
        ▼
[Orchestrator: SOAR / Tines / Logic Apps / custom]
   │            │              │
   ▼            ▼              ▼
[Enrichment]  [CrowdStrike/    [ServiceNow SecOps]
 (VT, TI feed,  Defender RTR]   (create sn_si_incident,
  CMDB, Entra)  (isolate,        map fields, work notes,
                disable, collect) close → reverse sync)
```

Design pattern: **detect → enrich → case → respond → write back.** The rules
below stop at *detect* and carry the response *intent* (which containment action
should run) so the orchestration layer can execute it consistently on either
platform.

### How the two platforms express response actions

- **Defender XDR** executes response actions **inline in the rule**
  (`detectionAction.responseActions`). This repo wires:
  - `isolateDeviceResponseAction` — CD-01 ransomware, CD-02 LSASS dump, CD-03
    office-macro, CD-05 shadow-copy deletion
  - `disableUserResponseAction` — CD-11 impossible travel (identity takeover)
  - `collectInvestigationPackageResponseAction` — CD-02, CD-04, CD-08, CD-10
    (forensic triage)
- **Sentinel** has no inline response; it triggers **automation rules +
  Logic App playbooks** on incident creation. Each YAML rule's description names
  the playbook to bind (`PB-Isolate-Device`, `PB-Disable-User`,
  `PB-Collect-Package`, `PB-Block-IP`, `PB-Purge-Email`) so the mapping to the
  Defender auto-actions stays 1:1.

## The 15 detections

| # | Detection | Tactic (MITRE) | Severity | Auto-action |
|---|-----------|----------------|----------|-------------|
| 01 | Ransomware — mass file encryption | Impact (T1486) | High | Isolate (full) |
| 02 | LSASS credential dumping | Credential Access (T1003.001) | High | Isolate + collect package |
| 03 | Office app spawned suspicious child (macro) | Execution (T1204.002) | High | Isolate (selective) |
| 04 | Obfuscated / encoded PowerShell | Execution (T1059.001) | Medium | Collect package |
| 05 | Shadow copy / backup deletion | Impact (T1490) | High | Isolate (full) |
| 06 | Suspicious scheduled task | Persistence (T1053.005) | Medium | — |
| 07 | Registry Run-key autorun | Persistence (T1547.001) | Low | — |
| 08 | PsExec / remote service lateral movement | Lateral Movement (T1021.002) | Medium | Collect package |
| 09 | LOLBin download (certutil/bitsadmin/mshta) | Command & Control (T1105) | Medium | — |
| 10 | C2 beaconing pattern | Command & Control (T1071.001) | Medium | Collect package |
| 11 | Impossible travel sign-in | Initial Access (T1078.004) | High | Disable user |
| 12 | Password spray (Entra ID) | Credential Access (T1110.003) | Medium | — |
| 13 | Privileged group membership change | Priv. Escalation (T1098) | High | — |
| 14 | Kerberoasting — anomalous TGS | Credential Access (T1558.003) | Medium | — |
| 15 | Malicious attachment delivered | Initial Access (T1566.001) | Medium | — |

Rules 01–10 are endpoint-behavioral (Defender for Endpoint tables). 11–12 are
Entra ID sign-in analytics. 13–15 depend on identity/mail telemetry.

## Data connector / licensing prerequisites

- **Rules 01–10** — Microsoft Defender for Endpoint (`Device*` advanced-hunting
  tables via the M365 Defender connector).
- **Rules 11–12** — Entra ID sign-in logs. In the Sentinel file these query
  `SigninLogs` (Azure Active Directory connector); the Defender file uses the
  `AADSignInEventsBeta` advanced-hunting table.
- **Rule 13** — `IdentityDirectoryEvents` (Microsoft Defender for Identity).
- **Rule 14** — `IdentityLogonEvents` (Microsoft Defender for Identity).
- **Rule 15** — `EmailEvents` / `EmailAttachmentInfo` (Microsoft Defender for
  Office 365).

Confirm 13–15's connectors are onboarded before enabling those rules, or they
run against empty tables.

## Before you deploy — read this

- **Auto-containment scope.** `isolateDevice` and `disableUser` are high-impact.
  They are applied only to the highest-confidence rules (ransomware, LSASS dump,
  office-macro, shadow-copy deletion, impossible travel). Validate the thresholds
  against your own false-positive tolerance, and consider gating them behind an
  approval task in ServiceNow (human-in-the-loop) until you trust the fidelity.
  Crown-jewel assets in particular should route to approval, not auto-isolate.
- **Idempotency.** Response playbooks should check current state before acting
  (don't re-isolate an already-isolated host, don't disable an already-disabled
  account). The auto-actions here assume the orchestration layer enforces that.
- **Grouping / dedup.** Every Sentinel rule sets `groupingConfiguration` to
  bucket repeat matches into one incident per entity. Tune `groupByEntities` and
  `lookbackDuration` for tighter or looser consolidation.
- **Thresholds are starting points.** File-count (200), beacon counts (30/20),
  spray breadth (15 accounts), Kerberoast SPN counts (10) are conservative
  defaults — baseline them against your environment before trusting the
  auto-actions.

## Tuning notes

- **CD-04 / SR-04** (encoded PowerShell) is the most likely source of noise in
  admin-heavy environments; add an allow-list for known management tooling.
- **CD-12 / SR-12** (password spray) deliberately has **no** auto-disable —
  legitimate NAT/VPN egress can look like spray. It blocks the source IP instead.
- **CD-10 / SR-10** (beaconing) is a summarize-over-3h heuristic; pair it with a
  reputation-lookup enrichment step before escalating.

## Not included here

Enrichment connectors (VirusTotal, AbuseIPDB, MISP), the ServiceNow field
mapping, and the CrowdStrike/Defender RTR containment wrappers live in the
orchestration layer, not the detection layer. These files are the detection
content that feeds that pipeline.
