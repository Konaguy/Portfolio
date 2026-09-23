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

## Why these three

- **SOAR architecture** shows I can design at the systems level — how alerts
  become cases, how response actions get gated by risk, how the audit trail
  holds up under review.
- **The Sigma translator** shows platform-agnostic detection engineering —
  understanding *why* KQL and Falcon query syntax differ, not just how to
  write in one of them.
- **The RTR toolkit** shows I write production-quality code: tested, typed,
  documented, safe to hand to a teammate.

## Background

[A couple of sentences about you — years of experience, prior roles,
relevant certifications (e.g. GCIH, GCIA, Security+), and what kind of role
you're targeting. Replace this paragraph with your own bio.]

## Contact

[LinkedIn] · [Email] · [Resume link]
