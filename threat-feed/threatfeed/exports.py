"""Pro IOC exports: CSV for spreadsheets/SIEM lookups, STIX 2.1 for TIPs."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone

from .models import Post

# Fixed namespace -> deterministic STIX ids, so re-exporting the same IOC
# updates the object in a TIP instead of duplicating it.
NAMESPACE = uuid.UUID("6f7c1f0e-3b8a-4c55-9d0e-7a1b2c3d4e5f")

STIX_PATTERNS = {
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
    "domains": "[domain-name:value = '{v}']",
    "urls": "[url:value = '{v}']",
}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def iter_iocs(posts: list[Post]):
    for p in posts:
        for kind in STIX_PATTERNS:
            for v in getattr(p.iocs, kind):
                yield kind, v, p


def to_csv(posts: list[Post]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "first_seen", "severity", "categories", "source", "author", "post_url"])
    seen = set()
    for kind, v, p in iter_iocs(sorted(posts, key=lambda p: p.ingested_at)):
        if (kind, v) in seen:
            continue
        seen.add((kind, v))
        value = v
        # Neutralise spreadsheet formula injection from attacker-controlled text.
        if value[:1] in ("=", "+", "-", "@"):
            value = "'" + value
        w.writerow([kind, value, _iso(p.ingested_at), p.severity, ";".join(p.categories), p.raw.source,
                    p.raw.author_handle, p.raw.url])
    return buf.getvalue()


def to_stix_bundle(posts: list[Post]) -> dict:
    objects: dict[str, dict] = {}
    for kind, v, p in iter_iocs(sorted(posts, key=lambda p: p.ingested_at)):
        pattern = STIX_PATTERNS[kind].format(v=v.replace("\\", "\\\\").replace("'", "\\'"))
        sid = f"indicator--{uuid.uuid5(NAMESPACE, pattern)}"
        if sid in objects:
            continue
        ts = _iso(p.ingested_at)
        objects[sid] = {
            "type": "indicator", "spec_version": "2.1", "id": sid, "created": ts, "modified": ts,
            "name": f"{kind}: {v}", "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix", "valid_from": ts,
            "confidence": p.severity,
            "labels": p.categories,
            "external_references": [{"source_name": f"threat-feed:{p.raw.source}", "url": p.raw.url,
                                     "description": f"Reported by @{p.raw.author_handle}"}],
        }
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objects.values())}
