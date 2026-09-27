from __future__ import annotations

from pathlib import Path

from attackcov.coverage import build_coverage
from attackcov.navigator import build_layer
from attackcov.parsers import parse_path

_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_rules"


def _layer():
    return build_layer(build_coverage(parse_path(_SAMPLE)))


def test_layer_shape():
    layer = _layer()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["techniques"], "should have scored techniques"


def test_layer_scores_are_detection_counts():
    layer = _layer()
    by_id = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    # T1003.001 appears once in the sample
    assert by_id["T1003.001"] == 1
    assert all(t["score"] >= 1 for t in layer["techniques"])


def test_layer_excludes_unknown_ids():
    from attackcov.parsers import Detection
    cov = build_coverage([Detection(name="d", source="sigma", platform="Sigma",
                                    technique_ids=["T9999", "T1059.001"])])
    layer = build_layer(cov)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1059.001" in ids
    assert "T9999" not in ids


def test_gradient_max_matches_densest_coverage():
    layer = _layer()
    max_score = max(t["score"] for t in layer["techniques"])
    assert layer["gradient"]["maxValue"] >= max_score
