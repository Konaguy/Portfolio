# Playbook: Case Closure Sync

**Trigger:** A ServiceNow Security Incident is closed by an analyst.

## Steps

1. **Detect closure.** A ServiceNow business rule (or a scheduled poll,
   if webhooks aren't available in your instance) notifies the
   orchestrator that a case closed, along with its resolution code.
2. **Branch on resolution code:**
   - **False positive** → orchestrator reverses any containment actions
     taken during the case: lift host isolation (Falcon RTR
     `liftContainmentResponseAction`), re-enable any disabled user
     accounts.
   - **True positive / resolved** → orchestrator updates the detection
     status in the source platform (`update_detection_status` → closed
     in CrowdStrike; incident status update in Sentinel/Defender) so
     detection dashboards reflect ground truth.
   - **True positive / escalated** → no automated reversal; case handoff
     to a higher-severity workflow or external IR team is logged instead.
3. **Write-back.** Every reversal or status update is logged to the case
   as a final work note, closing the audit loop.

## Why this matters

Without this step, a false-positive containment action becomes permanent
by default — the host stays isolated and the user stays locked out until
someone remembers to undo it manually. This is one of the most common gaps
in SOAR implementations I've seen: the *forward* path (detect → respond)
gets automated, but the *reverse* path (analyst says "this was nothing") 
doesn't, which erodes trust in automation over time.

## Idempotency notes

- Lift-containment and re-enable-account calls check current state first,
  same as their forward-path counterparts — this handles the case where
  an analyst manually reversed the action before the sync job ran.
