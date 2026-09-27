"""
Build the coverage model from parsed detections.

Coverage is counted at the top-level technique: a detection for a sub-technique
(e.g. T1003.001) marks its parent technique (T1003) covered, and the exact
sub-technique id is recorded too. Per-tactic coverage is
`covered top-level techniques / total top-level techniques in the catalog`.

The output document is what the dashboard renders and what `navigator.py`
turns into an ATT&CK Navigator layer.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from . import attack_data as ad
from .parsers import Detection


def build_coverage(detections: list[Detection], layer_name: str = "Portfolio detection coverage") -> dict:
    # detection count per exact technique id (incl. sub-techniques)
    count_by_id: dict[str, int] = defaultdict(int)
    # which detections hit each top-level technique
    dets_by_parent: dict[str, set[str]] = defaultdict(set)
    unknown_ids: set[str] = set()
    source_counts: dict[str, int] = defaultdict(int)

    for det in detections:
        source_counts[det.source] += 1
        for tid in det.normalized_ids():
            count_by_id[tid] += 1
            parent = ad.parent_of(tid)
            if ad.is_known(tid):
                dets_by_parent[parent].add(det.name)
            else:
                unknown_ids.add(tid)

    covered_parents = {p for p in dets_by_parent}

    tactics_out = []
    total_techniques = 0
    total_covered = 0
    for shortname, (taid, display) in ad.TACTICS.items():
        tech_ids = ad.techniques_in_tactic(shortname)
        techs = []
        covered_here = 0
        for tid in sorted(tech_ids):
            parent_count = sum(c for i, c in count_by_id.items() if ad.parent_of(i) == tid)
            is_cov = tid in covered_parents
            if is_cov:
                covered_here += 1
            subs = sorted(
                {i for i in count_by_id if ad.parent_of(i) == tid and "." in i}
            )
            techs.append({
                "id": tid,
                "name": ad.TECHNIQUES[tid][0],
                "covered": is_cov,
                "detection_count": parent_count,
                "detections": sorted(dets_by_parent.get(tid, set())),
                "covered_subtechniques": [
                    {"id": s, "name": ad.technique_name(s), "count": count_by_id[s]} for s in subs
                ],
            })
        total_techniques += len(tech_ids)
        total_covered += covered_here
        tactics_out.append({
            "shortname": shortname,
            "attack_id": taid,
            "name": display,
            "covered": covered_here,
            "total": len(tech_ids),
            "coverage_pct": round(100 * covered_here / len(tech_ids), 1) if tech_ids else 0.0,
            "techniques": techs,
        })

    detections_out = [
        {
            "name": d.name,
            "source": d.source,
            "platform": d.platform,
            "techniques": [
                {"id": tid, "name": ad.technique_name(tid), "known": ad.is_known(tid)}
                for tid in d.normalized_ids()
            ],
        }
        for d in detections
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "layer_name": layer_name,
        "summary": {
            "detections_parsed": len(detections),
            "techniques_covered": len(covered_parents),
            "techniques_total": total_techniques,
            "coverage_pct": round(100 * total_covered / total_techniques, 1) if total_techniques else 0.0,
            "tactics_total": len(ad.TACTICS),
            "tactics_with_coverage": sum(1 for t in tactics_out if t["covered"] > 0),
            "sources": dict(source_counts),
            "unknown_technique_ids": sorted(unknown_ids),
            "max_detections_on_a_technique": max(
                (sum(c for i, c in count_by_id.items() if ad.parent_of(i) == p) for p in covered_parents),
                default=0,
            ),
        },
        "tactics": tactics_out,
        "detections": detections_out,
        "_count_by_id": dict(count_by_id),  # used by navigator.py
    }
