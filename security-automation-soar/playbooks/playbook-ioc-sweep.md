# Playbook: IOC Sweep

**Trigger:** A new indicator of compromise (hash, IP, domain) ingested
from a threat intel feed (commercial feed, ISAC sharing, or internal
research).

## Steps

1. **Ingest.** New IOC arrives via TIP (MISP/ThreatConnect) API poll or
   push webhook.
2. **Push to CrowdStrike.** Upload the indicator to Falcon's custom IOC
   management (Threat Intel API) for future detection/prevention.
3. **Historical sweep.** Query Falcon for any historical hits against the
   IOC across the fleet (`indicator-of-compromise` search on the Hosts/
   Detections API).
4. **Fan-out.** If hits are found:
   - Auto-create one ServiceNow case per affected host, tagged with the
     source IOC and feed.
   - Chain each case into the malware containment playbook.
5. **No hits.** If no historical hits, log the sweep result (for audit —
   "we checked and found nothing" is itself a useful record) and close
   without a case.

## Idempotency notes

- IOC upload to Falcon is idempotent by design (duplicate indicator
  submissions are deduplicated server-side).
- The historical sweep should be time-bounded (e.g., last 90 days) to
  avoid re-litigating already-closed incidents on every re-run of a
  recurring feed sync.
