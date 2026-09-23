# Architecture: SIEM / CrowdStrike / ServiceNow Orchestration

## 1. Goals

- Turn a detection into an auditable case with minimal analyst toil.
- Auto-execute low-risk actions (enrichment, ticket creation); gate
  high-impact actions (host isolation, account disable) behind either a
  confidence threshold or an explicit approval step.
- Keep every action idempotent and logged, so the system is defensible
  under audit and safe to retry.

## 2. Components

| Layer | Role | Example tech |
|---|---|---|
| Detection | Fires the initial alert | Microsoft Sentinel / Defender XDR |
| Orchestrator | Normalizes alerts, runs playbook logic, calls other systems | Custom Python service, Tines, Logic Apps, or Sentinel Playbooks (Logic Apps under the hood) |
| Enrichment | Adds context before a human or automation decides | VirusTotal, AbuseIPDB, internal TI feed, CMDB |
| Response | Executes containment/remediation | CrowdStrike Falcon API (RTR, Hosts, Detections) |
| Case management | System of record, assignment, audit trail | ServiceNow Security Incident Response (`sn_si_incident`) |

## 3. Data flow

1. A Sentinel analytics rule (or Defender custom detection) fires and
   creates an incident.
2. The orchestrator picks up the incident via webhook (Logic Apps trigger)
   or polls the Sentinel Incidents API.
3. The orchestrator normalizes the alert into a common schema:

   ```json
   {
     "alert_id": "string",
     "source": "sentinel | defender",
     "severity": "low | medium | high",
     "entity_type": "host | account | ip | url",
     "entity_value": "string",
     "timestamp": "ISO8601",
     "mitre_techniques": ["T1003.001"],
     "raw_event_link": "url"
   }
   ```
4. Enrichment calls run in parallel: TI reputation lookup, CMDB asset
   criticality (often ServiceNow itself), AD/Entra group membership for
   identity-related alerts.
5. A ServiceNow Security Incident is created via the Table API, populated
   with the normalized alert plus enrichment results as work notes.
6. **Decision gate:** if severity is High/Critical *and* the response
   action is on the pre-approved auto-response list (see table in the
   project README), the orchestrator calls the relevant Falcon API action
   directly. Otherwise, it creates an approval task in ServiceNow and
   waits.
7. All actions taken — enrichment results, response actions, approvals —
   are written back to the ServiceNow case as work notes, producing a full
   audit trail.
8. On case closure, a ServiceNow business rule (or scheduled poll) notifies
   the orchestrator of the resolution code. If resolved as false positive,
   the orchestrator reverses any containment (lift host isolation,
   re-enable account) and updates the detection status in the source
   platform.

## 4. Design principles

- **Idempotency.** Every response action checks current state before
  acting (e.g., don't re-isolate an already-isolated host). This matters
  because playbooks will be retried after transient failures.
- **Human-in-the-loop gating.** Containment and account-disable actions
  are the highest-blast-radius operations in this design. They're limited
  to detections with high confidence (few false positives observed in
  testing) and reversible outcomes (isolation and disablement are both
  easily undone, unlike, say, deleting data).
- **Full audit trail.** Every API call — input and output — gets logged to
  the case as a work note. This is what makes the automation defensible
  to an auditor and debuggable when something goes wrong.
- **Fail-safe defaults.** If an enrichment call times out, the case still
  gets created; enrichment failure never blocks case creation.
- **Deduplication.** Alerts are correlated on entity + time window before
  creating a new case vs. updating an existing one, to avoid case sprawl
  during multi-stage incidents.

## 5. Build vs. buy

Before building custom orchestration code, it's worth checking whether:

- **CrowdStrike Falcon Fusion (SOAR)** already covers the workflow with
  native Falcon connectors (avoids Falcon API auth plumbing).
- **ServiceNow SecOps' Flow Designer + Security Operations spokes**
  already covers it if you're heavily ServiceNow-centric.
- **Sentinel Playbooks** (Logic Apps) cover it if you're Microsoft-native
  end to end.

Custom orchestration (a dedicated Python service, or a workflow tool like
Tines) earns its complexity when the logic needs to span more systems or
more conditional branching than the native connectors support cleanly —
e.g., correlating across SIEM + EDR + a non-Microsoft ITSM, or custom
scoring logic that native playbook builders can't express well.

## 6. What's not yet implemented here

This repo documents the design and provides the detection content; it does
not (yet) include the orchestrator's runtime code. A natural next step
would be a small FastAPI service with:

- `/webhook/sentinel-incident` — ingestion endpoint
- `enrichment.py` — pluggable enrichment provider interface
- `falcon_actions.py` — thin wrapper reusing the `crowdstrike-rtr-toolkit`
  project in this same portfolio
- `servicenow_client.py` — Table API wrapper for case CRUD
