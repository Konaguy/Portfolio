from __future__ import annotations

from pathlib import Path

from attackcov.parsers import (
    parse_defender_json,
    parse_path,
    parse_sentinel_yaml,
    parse_sigma_yaml,
)

_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_rules"


def test_parse_defender_json():
    dets = parse_defender_json((_SAMPLE / "defender-sample.json").read_text())
    assert len(dets) == 2
    lsass = next(d for d in dets if "LSASS" in d.name)
    assert lsass.source == "defender"
    assert lsass.normalized_ids() == ["T1003.001"]
    ransom = next(d for d in dets if "Ransomware" in d.name)
    assert set(ransom.normalized_ids()) == {"T1486", "T1490"}


def test_parse_sentinel_yaml():
    dets = parse_sentinel_yaml((_SAMPLE / "sentinel-sample.yaml").read_text())
    assert len(dets) == 2
    assert all(d.source == "sentinel" for d in dets)
    ids = {i for d in dets for i in d.normalized_ids()}
    assert ids == {"T1078.004", "T1110.003"}


def test_parse_sigma_yaml():
    dets = parse_sigma_yaml((_SAMPLE / "sigma-sample.yml").read_text())
    assert len(dets) == 1
    assert dets[0].source == "sigma"
    # tactic tags (attack.execution) are ignored; only technique ids are kept
    assert set(dets[0].normalized_ids()) == {"T1059.001", "T1027"}


def test_parse_path_directory_classifies_all_three():
    dets = parse_path(_SAMPLE)
    sources = {d.source for d in dets}
    assert sources == {"defender", "sentinel", "sigma"}
    assert len(dets) == 5  # 2 defender + 2 sentinel + 1 sigma


def test_ids_are_uppercased():
    dets = parse_sigma_yaml("title: t\ntags: [attack.t1059.001]\ndetection:\n  a: b\n  condition: a\n")
    assert dets[0].normalized_ids() == ["T1059.001"]
