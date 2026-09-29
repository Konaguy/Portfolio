# Security Architecture Portfolio

I design detection, response, and automation systems — not just individual
rules or scripts. The projects here are organized around a single idea:
**defense-in-depth requires the pieces to talk to each other.** A detection
is only as useful as the response it triggers and the case record it leaves
behind; a SOC's tooling is only as fast as its weakest hand-off.

Each project below is self-contained, with its own README, working code
(not pseudocode), and — where relevant — tests. AI/LLM components are used
where they add real leverage (triage summarization, translation between
detection languages), not as a buzzword.

## Projects

| Project | What it demonstrates |
|---|---|
| [`security-automation-soar/`](./security-automation-soar) | End-to-end SOAR design: SIEM → EDR → ITSM orchestration, 15 production-ready detection rules for Defender/Sentinel, and documented response playbooks. |
| [`sigma-rule-translator/`](./sigma-rule-translator) | A CLI tool that translates vendor-agnostic Sigma detection rules into Microsoft Sentinel KQL and CrowdStrike Falcon query syntax, so detection logic isn't locked to one platform. |
| [`crowdstrike-rtr-toolkit/`](./crowdstrike-rtr-toolkit) | A tested, packaged Python library wrapping the CrowdStrike Falcon Real Time Response API for common incident response actions (containment, process kill, evidence collection). |
| [`llm-soc-copilot/`](./llm-soc-copilot) | An LLM-powered alert triage assistant: RAG-grounded enrichment over closed cases, schema-validated structured output via forced tool-use, a hallucinated-citation guard, and an eval harness scoring verdicts against labeled ground truth. |
| [`vuln-management-rag/`](./vuln-management-rag) | A multi-agent RAG assistant (LangGraph + Qdrant + Chainlit) that ingests Tenable exports and security policies and answers SOC-analyst questions with policy-grounded, cited remediation guidance. |
| [`threat-intel-to-kql/`](./threat-intel-to-kql) | Turns raw threat intel (CVE advisories, STIX/MISP feeds, IOC lists) into validated Microsoft Defender KQL hunting queries: deterministic IOC extraction, LLM synthesis, and static KQL + IOC-grounding validation. |
| [`attack-coverage-tracker/`](./attack-coverage-tracker) | Parses the repo's Defender/Sentinel/Sigma detections, maps them to MITRE ATT&CK, and reports coverage — an ATT&CK Navigator layer plus a self-contained heatmap dashboard showing what's covered and where the gaps are. |
| [`detection-ci/`](./detection-ci) | A Detection-as-Code CI gate: a GitHub Actions pipeline that parses and validates the repo's Sigma / Defender / Sentinel rules (structure, ATT&CK tags, KQL sanity) on every PR, so a broken detection never merges. |
| [`ActiveDirectory/OUPermissionsAudit/`](./ActiveDirectory/OUPermissionsAudit) | A read-only PowerShell audit of Active Directory OU permissions: resolves every ACE to what it actually allows in plain language, flags non–Tier 0 principals with dangerous rights (DCSync, write-owner, GPO edit), and emits one interactive HTML report. No RSAT required. |

## Why these projects

- **SOAR architecture** shows I can design at the systems level — how alerts
  become cases, how response actions get gated by risk, how the audit trail
  holds up under review.
- **The Sigma translator** shows platform-agnostic detection engineering —
  understanding *why* KQL and Falcon query syntax differ, not just how to
  write in one of them.
- **The RTR toolkit** shows I write production-quality code: tested, typed,
  documented, safe to hand to a teammate.
- **The SOC copilot** shows applied AI engineering with the guardrails that
  matter in a security context — forced structured output, a hallucination
  check on RAG citations, and an eval harness rather than a demo that "seems
  to work."
- **The vuln-management RAG assistant** shows a full multi-agent RAG system —
  ingestion, a vector store, a LangGraph router/retriever/specialist pipeline,
  and a chat UI — with verified grounding rather than a wrapper around an API.
- **The threat-intel → KQL translator** shows the right division of labour
  between deterministic code and an LLM: regex for the indicators that must be
  exact, the model for the query synthesis, and static validation so nothing
  ungrounded reaches an analyst's console.
- **The ATT&CK coverage tracker** shows detection-program maturity — measuring
  what the detections actually cover against the adversary playbook, gaps
  included, instead of just adding more rules.
- **The AD OU permission audit** shows identity-tier / attack-path thinking —
  turning raw AD ACEs into the handful that actually enable domain takeover, in
  a safe read-only script that runs anywhere without RSAT.
- **The Detection-as-Code CI** shows detection engineering as a software
  discipline — detections are version-controlled, validated, and gated in CI
  like any other code, not hand-edited in a console.

## Background

[A couple of sentences about you — years of experience, prior roles,
relevant certifications (e.g. GCIH, GCIA, Security+), and what kind of role
you're targeting. Replace this paragraph with your own bio.]

## Contact

[LinkedIn] · [Email] · [Resume link]
