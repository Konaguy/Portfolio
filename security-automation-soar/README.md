# Security Automation & Orchestration Reference Architecture

A reference design for orchestrating detection, enrichment, response, and
case management across a SIEM, an EDR (CrowdStrike Falcon), and an ITSM
platform (ServiceNow), plus 15 production-ready detection rules for
Microsoft Defender XDR and Microsoft Sentinel.

## Why this exists

Most detection-engineering portfolios show isolated rules. In a real SOC,
a rule firing is the *start* of a workflow — enrichment, ticket creation,
a containment decision, an audit trail — not the end of one. This project
documents that whole loop and provides working detection content for two
of the most common enterprise SIEM/XDR platforms.

## Architecture

```
[SIEM: Sentinel / Splunk]
        │  (webhook / API poll)
        ▼
[Orchestrator: SOAR / Tines / custom]
   │        │            │
   ▼        ▼            ▼
[Enrichment] [CrowdStrike] [ServiceNow]
 (TI feeds,   (isolate,     (create case,
  VT, WHOIS,   kill process, update fields,
  AD lookup)   quarantine)   assign, close)
```

See [`docs/architecture.md`](./docs/architecture.md) for the full design
doc, including integration details, idempotency/audit requirements, and
the build-vs-buy discussion.

## Contents

- **`detection-rules/`** — 15 detections covering endpoint, identity, and
  email telemetry, provided in two formats:
  - `defender-custom-detection-rules.json` — Microsoft Graph Security API
    payloads (`POST /security/rules/detectionRules`), with automated
    response actions (device isolation, user disable, evidence collection)
    wired in for the highest-confidence rules.
  - `sentinel-analytics-rules.yaml` — Scheduled analytics rules in the
    Azure-Sentinel content-repo YAML format, with MITRE ATT&CK mappings
    and entity mappings for incident graphs.
- **`playbooks/`** — Response workflow documentation for the four most
  common case types: malware containment, phishing/account takeover, IOC
  sweeps, and case-closure sync (reversing containment on false positives).
- **`diagrams/`** — Mermaid source for the architecture diagram (renders
  natively on GitHub).

## Detection coverage summary

| # | Rule | Tactic | Severity | Auto-response |
|---|---|---|---|---|
| 1 | LSASS credential dumping | Credential Access | High | Isolate + collect |
| 2 | Encoded PowerShell | Execution | Medium | Collect evidence |
| 3 | LOLBin external connection | C2 | Medium | — |
| 4 | Scheduled task/service persistence | Persistence | Medium | — |
| 5 | Office app spawns script interpreter | Initial Access | High | Isolate + collect |
| 6 | Mass file rename (ransomware) | Impact | High | Full isolation |
| 7 | Security tooling disabled | Defense Evasion | High | Isolate + collect |
| 8 | Archive staging sensitive paths | Collection | Medium | — |
| 9 | Beaconing to public IP | C2 | Medium | — |
| 10 | Rare domain via scripting engine | C2 | Low | — |
| 11 | Impossible travel logon | Initial Access | Medium | Disable user |
| 12 | Password spray pattern | Credential Access | High | — |
| 13 | Privileged group membership change | Privilege Escalation | High | — |
| 14 | MFA registration → immediate sign-in | Credential Access | High | Disable user |
| 15 | Phishing — lookalike domain | Initial Access | Medium | — |

Full KQL and rule metadata are in the `detection-rules/` files.

## What I'd build next

- Wire the orchestrator layer (currently documented, not code) as an actual
  Python service or Tines/Logic Apps flow calling the Falcon and ServiceNow
  APIs.
- Add a small Streamlit/FastAPI dashboard showing case volume and MTTR
  pulled from ServiceNow's Table API.
