from __future__ import annotations

from pathlib import Path

import pytest

from ti2kql.config import Settings
from ti2kql.feeds import load_file
from ti2kql.llm import SUBMIT_HUNT_TOOL, FakeLLMClient
from ti2kql.schema import GeneratedHunt, HuntParseError, ThreatIntel, ValidationError
from ti2kql.translator import Translator

_DATA = Path(__file__).resolve().parent.parent / "data"


def test_tool_schema_matches_model():
    schema_props = set(SUBMIT_HUNT_TOOL["input_schema"]["properties"])
    model_fields = set(GeneratedHunt.model_fields)
    assert schema_props == model_fields


def test_end_to_end_fake_generates_valid_hunt():
    intel = load_file(_DATA / "sample_cve.txt")
    translator = Translator(FakeLLMClient(intel=intel), Settings())
    hunt = translator.translate(intel)
    assert isinstance(hunt, GeneratedHunt)
    assert hunt.queries
    # Every generated query starts with a known table and references a source IOC.
    source = intel.ioc_values()
    for q in hunt.queries:
        assert any(v.lower() in q.kql.lower() for v in source)


def test_generated_iocs_are_grounded():
    intel = load_file(_DATA / "sample_iocs.csv")
    translator = Translator(FakeLLMClient(intel=intel), Settings())
    hunt = translator.translate(intel)
    assert set(hunt.iocs_used).issubset(intel.ioc_values())


def test_empty_intel_raises():
    intel = ThreatIntel(source="empty", raw_text="nothing here", iocs=[])
    translator = Translator(FakeLLMClient(override={}), Settings())
    with pytest.raises(HuntParseError):
        translator.translate(intel)


def test_fabricated_ioc_from_llm_is_rejected():
    intel = load_file(_DATA / "sample_cve.txt")
    bad = {
        "title": "Bad hunt",
        "description": "",
        "queries": [
            {
                "name": "q",
                "table": "DeviceNetworkEvents",
                "kql": 'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in~ ("9.9.9.9")',
                "rationale": "",
            }
        ],
        "iocs_used": ["9.9.9.9"],  # not in the source intel
        "mitre_techniques": [],
        "caveats": "",
    }
    translator = Translator(FakeLLMClient(override=bad), Settings())
    with pytest.raises(ValidationError):
        translator.translate(intel)


def test_invalid_kql_table_is_rejected():
    intel = load_file(_DATA / "sample_cve.txt")
    ip = "148.113.152.144"
    bad = {
        "title": "Bad table",
        "description": "",
        "queries": [
            {
                "name": "q",
                "table": "NotARealTable",
                "kql": f'NotARealTable | where Timestamp > ago(30d) | where RemoteIP in~ ("{ip}")',
                "rationale": "",
            }
        ],
        "iocs_used": [ip],
        "mitre_techniques": [],
        "caveats": "",
    }
    translator = Translator(FakeLLMClient(override=bad), Settings())
    with pytest.raises(ValidationError):
        translator.translate(intel)
