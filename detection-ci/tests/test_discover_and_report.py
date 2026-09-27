from __future__ import annotations

import json
from pathlib import Path

from dac.discover import classify, scan
from dac.report import Finding, Report, Severity

FIX = Path(__file__).resolve().parent / "fixtures"


def test_classify_by_content():
    assert classify(Path("x.json"), '[{"displayName":"a","detectionAction":{}}]') == "defender"
    assert classify(Path("x.yml"), "title: t\nlogsource:\n  product: windows\ndetection:\n  a: b\n  condition: a") == "sigma"
    assert classify(Path("x.yaml"), "- name: r\n  kind: Scheduled\n  relevantTechniques: [T1]") == "sentinel"
    assert classify(Path("x.txt"), "whatever") is None


def test_scan_good_fixtures_pass():
    report = scan([FIX / "good"])
    assert report.files_checked == 3
    assert report.rules_checked == 3
    assert report.ok
    assert report.errors == []


def test_scan_bad_fixtures_fail():
    report = scan([FIX / "bad"])
    assert not report.ok
    assert len(report.errors) > 0


def test_report_json_roundtrip():
    r = Report(files_checked=1, rules_checked=2)
    r.add(Finding(file="f", code="c", message="m", severity=Severity.ERROR))
    data = json.loads(r.to_json())
    assert data["ok"] is False
    assert data["errors"] == 1
    assert data["findings"][0]["code"] == "c"


def test_report_github_annotations():
    r = Report()
    r.add(Finding(file="rules/x.yml", code="sigma-bad-status", message="bad", severity=Severity.ERROR, line=3))
    gh = r.to_github()
    assert gh.startswith("::error ")
    assert "file=rules/x.yml,line=3" in gh


def test_repo_detections_pass_the_gate():
    """The portfolio's real detections must pass the gate (keeps CI green)."""
    repo_root = Path(__file__).resolve().parents[2]
    dirs = [repo_root / "security-automation-soar" / "detection-rules",
            repo_root / "sigma-rule-translator" / "rules"]
    dirs = [d for d in dirs if d.exists()]
    if not dirs:
        return  # sources not present in this checkout; nothing to assert
    report = scan(dirs)
    assert report.ok, report.to_text()
