from __future__ import annotations

from dac.kql import _balanced, check_kql


def test_clean_query_passes():
    q = 'DeviceProcessEvents\n| where Timestamp > ago(1d)\n| where FileName =~ "x.exe"'
    assert check_kql(q) == []


def test_unknown_table():
    problems = check_kql('MadeUpTable\n| where x == 1')
    assert any("unknown table" in p for p in problems)


def test_missing_where():
    problems = check_kql("DeviceProcessEvents\n| project FileName")
    assert any("where" in p for p in problems)


def test_unbalanced():
    assert any("unbalanced" in p for p in check_kql('DeviceEvents | where x in ("a"'))


def test_control_command_rejected():
    assert any("control/management" in p for p in check_kql(".drop table DeviceEvents"))


def test_empty():
    assert check_kql("") == ["query is empty"]


def test_balanced_helper_handles_strings():
    assert _balanced('where Url has_any (")")')
