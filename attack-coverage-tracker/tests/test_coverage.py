from __future__ import annotations

from pathlib import Path

from attackcov import attack_data as ad
from attackcov.coverage import build_coverage
from attackcov.parsers import Detection, parse_path

_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_rules"


def test_build_coverage_from_sample():
    cov = build_coverage(parse_path(_SAMPLE))
    s = cov["summary"]
    assert s["detections_parsed"] == 5
    # Covered parent techniques: T1003, T1486, T1490, T1078, T1110, T1059, T1027
    assert s["techniques_covered"] == 7
    assert s["sources"] == {"defender": 2, "sentinel": 2, "sigma": 1}
    assert 0 < s["coverage_pct"] <= 100


def test_subtechnique_marks_parent_covered():
    cov = build_coverage([Detection(name="d", source="defender", platform="p",
                                    technique_ids=["T1003.001"])])
    cred = next(t for t in cov["tactics"] if t["shortname"] == "credential-access")
    t1003 = next(t for t in cred["techniques"] if t["id"] == "T1003")
    assert t1003["covered"] is True
    assert t1003["covered_subtechniques"][0]["id"] == "T1003.001"


def test_unknown_technique_is_flagged_not_counted():
    cov = build_coverage([Detection(name="d", source="sigma", platform="Sigma",
                                    technique_ids=["T9999"])])
    assert cov["summary"]["techniques_covered"] == 0
    assert "T9999" in cov["summary"]["unknown_technique_ids"]


def test_detection_count_accumulates_across_subtechniques():
    dets = [
        Detection(name="a", source="defender", platform="p", technique_ids=["T1003.001"]),
        Detection(name="b", source="sentinel", platform="p", technique_ids=["T1003.002"]),
    ]
    cov = build_coverage(dets)
    cred = next(t for t in cov["tactics"] if t["shortname"] == "credential-access")
    t1003 = next(t for t in cred["techniques"] if t["id"] == "T1003")
    assert t1003["detection_count"] == 2
    assert len(t1003["covered_subtechniques"]) == 2


def test_all_tactics_present_in_output():
    cov = build_coverage(parse_path(_SAMPLE))
    shortnames = [t["shortname"] for t in cov["tactics"]]
    assert shortnames == list(ad.TACTICS)  # order preserved, all 14 present
