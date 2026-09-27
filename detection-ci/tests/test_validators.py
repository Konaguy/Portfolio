from __future__ import annotations

from pathlib import Path

from dac.report import Severity
from dac.rules import validate_defender_text, validate_sentinel_text
from dac.sigma import lint_sigma_text

FIX = Path(__file__).resolve().parent / "fixtures"


def _codes(findings, sev=None):
    return {f.code for f in findings if sev is None or f.severity == sev}


# --- Sigma ---
def test_good_sigma_has_no_errors():
    findings = lint_sigma_text((FIX / "good/good.sigma.yml").read_text())
    assert not [f for f in findings if f.severity == Severity.ERROR]


def test_bad_sigma_flags_expected_problems():
    findings = lint_sigma_text((FIX / "bad/bad.sigma.yml").read_text())
    codes = _codes(findings)
    assert "sigma-bad-status" in codes
    assert "sigma-bad-attack-tag" in codes          # attack.t99 malformed
    assert "sigma-bad-logsource" in codes           # only 'foo'
    assert "sigma-unknown-identifier" in codes       # condition 'selektion' typo
    assert "sigma-missing-level" in codes            # no level field


def test_sigma_invalid_yaml():
    findings = lint_sigma_text("title: x\n  bad: : :\n")
    assert any(f.code == "sigma-invalid-yaml" for f in findings)


# --- Defender ---
def test_good_defender_no_errors():
    findings = validate_defender_text((FIX / "good/good.defender.json").read_text())
    assert not [f for f in findings if f.severity == Severity.ERROR]


def test_bad_defender_flags_problems():
    findings = validate_defender_text((FIX / "bad/bad.defender.json").read_text())
    codes = _codes(findings)
    assert "defender-bad-severity" in codes   # 'extreme'
    assert "rule-bad-technique" in codes      # '1003' (shared technique-format check)
    assert "defender-bad-kql" in codes        # .drop + unbalanced + unknown table


def test_defender_invalid_json():
    assert any(f.code == "defender-invalid-json" for f in validate_defender_text("{not json"))


# --- Sentinel ---
def test_good_sentinel_no_errors():
    findings = validate_sentinel_text((FIX / "good/good.sentinel.yaml").read_text())
    assert not [f for f in findings if f.severity == Severity.ERROR]


def test_sentinel_missing_query_and_severity():
    text = "- id: s1\n  name: No query rule\n  relevantTechniques: [T1059.001]\n"
    codes = _codes(validate_sentinel_text(text))
    assert "sentinel-no-query" in codes
