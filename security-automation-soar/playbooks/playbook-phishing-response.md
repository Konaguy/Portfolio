# Playbook: Phishing / Suspicious Login → Account Response

**Trigger:** Identity-based detection rules — impossible travel (`CD-11`/
`SR-11`), password spray (`CD-12`/`SR-12`), MFA-then-signin (`CD-14`/
`SR-14`), or phishing email delivery (`CD-15`/`SR-15`).

## Steps

1. **Enrich.**
   - IP geolocation and reputation for the sign-in source.
   - Pull the user's recent CrowdStrike host activity (any endpoint
     activity correlated to the account around the alert time).
   - AD/Entra ID group membership, to assess blast radius if the account
     is compromised.
2. **Case creation.** Create a ServiceNow Security Incident tagged
   `identity-compromise`.
3. **Auto-actions** (no approval gate — these are low-blast-radius and
   reversible):
   - Force password reset via the identity provider API.
   - Revoke active session tokens.
4. **Correlate.** Query CrowdStrike for any host activity tied to the
   user account around the alert time window — this catches cases where
   the compromised credential was also used for endpoint access, not just
   a cloud sign-in.
5. **Notify.** Trigger a ServiceNow notification workflow to the user's
   manager and the user themselves (out-of-band, e.g. SMS/phone — never
   the potentially compromised email).

## Escalation condition

If step 4 finds correlated endpoint activity, escalate to the malware
containment playbook for the associated host.

## Idempotency notes

- Session revocation and password reset are safe to call repeatedly — the
  IdP APIs treat both as terminal operations, not increments.
