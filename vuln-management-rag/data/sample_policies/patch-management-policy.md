# Patch and Vulnerability Remediation Policy

## Purpose and scope

This policy defines how the organization identifies, prioritizes, and
remediates security vulnerabilities across all servers, workstations, network
devices, and internet-facing applications. It applies to all IT and security
staff responsible for those assets.

## Remediation SLAs by severity

Remediation timelines are measured from the date a vulnerability is confirmed
by the vulnerability management team (a validated finding in the authorized
scanner), not the date the vendor published the advisory.

- **Critical** (CVSS 9.0–10.0, or any actively exploited vulnerability
  regardless of score): remediate within **7 calendar days**. Internet-facing
  critical findings must be remediated or mitigated within **48 hours**.
- **High** (CVSS 7.0–8.9): remediate within **30 calendar days**.
- **Medium** (CVSS 4.0–6.9): remediate within **90 calendar days**.
- **Low** (CVSS below 4.0): remediate within **180 calendar days** or accept
  the risk with sign-off.

Tenable VPR (Vulnerability Priority Rating) is used to break ties within a
severity band: a finding with a higher VPR is patched first even when two
findings share the same CVSS base score.

## Prioritization principles

When more findings are due than can be patched at once, prioritize in this
order:

1. Actively exploited vulnerabilities (known exploited, or with public
   exploit code) on any asset.
2. Critical and high findings on internet-facing or DMZ assets.
3. Critical and high findings on crown-jewel assets (domain controllers,
   identity providers, financial systems).
4. Everything else by descending VPR, then CVSS.

## Exceptions and compensating controls

If a finding cannot be remediated within its SLA, the asset owner must file a
risk exception with a compensating control (for example, network segmentation,
a WAF rule, or disabling the affected service) and a remediation target date.
Exceptions for critical findings require CISO approval.

## Verification

Every remediation must be verified by an authenticated re-scan before the
finding is closed. The vulnerability management team owns closure; asset
owners cannot self-close findings.
