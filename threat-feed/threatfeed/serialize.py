"""Turn a Post into API JSON, applying the viewer's tier policy."""

from __future__ import annotations

from .models import Post
from .tiers import TierPolicy


def post_json(p: Post, policy: TierPolicy) -> dict:
    r = p.raw
    d = {
        "type": "post",
        "id": r.id,
        "source": r.source,
        "author": r.author,
        "author_handle": r.author_handle,
        "url": r.url,
        "text": r.text,
        "created_at": r.created_at,
        "ingested_at": p.ingested_at,
        "categories": p.categories,
        "severity": p.severity,
        "severity_label": p.severity_label,
        "hashtags": p.hashtags,
        # CVE ids are public advisory references: always shown.
        "cves": p.iocs.cves,
    }
    if policy.show_iocs:
        d["iocs"] = p.iocs.as_dict()
    else:
        # Free sees *that* indicators exist (the upsell), not the values.
        d["iocs_locked"] = p.iocs.count()
    return d
