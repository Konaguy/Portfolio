from __future__ import annotations

from pathlib import Path

import pytest

from vulnrag.ingest import chunk_policy_text, parse_tenable_csv, parse_tenable_file
from vulnrag.schema import Severity

_DATA = Path(__file__).resolve().parent.parent / "data"


def test_parse_tenable_export_basic():
    vulns = parse_tenable_file(_DATA / "sample_tenable_export.csv")
    # 10 data rows, none informational -> all kept.
    assert len(vulns) == 10
    log4j = [v for v in vulns if v.plugin_id == "182252"]
    assert len(log4j) == 2  # same plugin on two hosts -> two findings
    assert {v.host for v in log4j} == {"10.20.30.11", "10.20.30.12"}
    assert log4j[0].cve == ["CVE-2021-44228"]
    assert log4j[0].severity == Severity.CRITICAL
    assert log4j[0].cvss_base_score == 10.0


def test_chunk_ids_are_stable_and_unique():
    vulns = parse_tenable_file(_DATA / "sample_tenable_export.csv")
    ids = [v.chunk_id for v in vulns]
    assert len(ids) == len(set(ids))
    # Re-parsing yields identical ids (idempotent upsert relies on this).
    again = parse_tenable_file(_DATA / "sample_tenable_export.csv")
    assert [v.chunk_id for v in again] == ids


def test_informational_rows_dropped():
    csv_text = (
        "Plugin ID,Name,Severity,Host,Port\n"
        "10001,Nessus Scan Information,Info,10.0.0.1,0\n"
        "10002,Real Finding,High,10.0.0.1,443\n"
    )
    vulns = parse_tenable_csv(csv_text)
    assert len(vulns) == 1
    assert vulns[0].name == "Real Finding"


def test_multiple_cve_cell_is_split():
    csv_text = (
        "Plugin ID,CVE,Name,Severity,Host,Port\n"
        "20001,\"CVE-2021-1, CVE-2021-2\",Multi,High,10.0.0.1,443\n"
    )
    vulns = parse_tenable_csv(csv_text)
    assert vulns[0].cve == ["CVE-2021-1", "CVE-2021-2"]


def test_column_aliases_tolerated():
    # Tenable.io style headers (Risk instead of Severity, IP Address instead of Host).
    csv_text = (
        "Plugin,CVE,Plugin Name,Risk,CVSS V3 Base Score,IP Address,Port\n"
        "30001,CVE-2020-1,Aliased Finding,Critical,9.5,10.0.0.9,8080\n"
    )
    vulns = parse_tenable_csv(csv_text)
    assert len(vulns) == 1
    assert vulns[0].name == "Aliased Finding"
    assert vulns[0].severity == Severity.CRITICAL
    assert vulns[0].host == "10.0.0.9"


def test_non_tenable_csv_rejected():
    with pytest.raises(ValueError):
        parse_tenable_csv("foo,bar\n1,2\n")


def test_policy_chunking_splits_on_headings():
    text = (
        "# Title\n\nIntro paragraph.\n\n"
        "## Section A\n\nBody A one.\n\nBody A two.\n\n"
        "## Section B\n\nBody B.\n"
    )
    chunks = chunk_policy_text(text, source="test.md", target_chars=1000)
    sections = {c.section for c in chunks}
    assert "Section A" in sections
    assert "Section B" in sections
    assert all(c.chunk_id.startswith("pol-") for c in chunks)
