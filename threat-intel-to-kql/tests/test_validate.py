from __future__ import annotations

from ti2kql.schema import GeneratedHunt, HuntQuery
from ti2kql.validate import _balanced, validate_hunt, validate_query


def _q(kql: str, table: str = "DeviceNetworkEvents", name: str = "q") -> HuntQuery:
    return HuntQuery(name=name, table=table, kql=kql, rationale="")


def test_balanced_helper():
    assert _balanced('DeviceNetworkEvents | where RemoteIP in ("1.2.3.4")')
    assert not _balanced("foo | where x in (1, 2")
    assert _balanced('where Url has_any (")")')  # paren inside string is fine


def test_valid_query_passes():
    kql = 'DeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where RemoteIP in~ ("1.2.3.4")'
    assert validate_query(_q(kql), {"1.2.3.4"}) == []


def test_unknown_table_rejected():
    kql = 'MadeUpTable\n| where RemoteIP in~ ("1.2.3.4")'
    problems = validate_query(_q(kql, table="MadeUpTable"), {"1.2.3.4"})
    assert any("unknown Defender table" in p for p in problems)


def test_missing_where_rejected():
    kql = 'DeviceNetworkEvents\n| project RemoteIP'
    problems = validate_query(_q(kql), {"1.2.3.4"})
    assert any("no 'where' filter" in p for p in problems)


def test_query_without_source_ioc_rejected():
    kql = 'DeviceNetworkEvents\n| where RemoteIP in~ ("9.9.9.9")'
    problems = validate_query(_q(kql), {"1.2.3.4"})
    assert any("none of the source IOCs" in p for p in problems)


def test_declared_table_mismatch_rejected():
    kql = 'DeviceFileEvents\n| where SHA256 in~ ("abc")'
    problems = validate_query(_q(kql, table="DeviceNetworkEvents"), {"abc"})
    assert any("does not match" in p for p in problems)


def test_control_command_rejected():
    kql = '.drop table DeviceNetworkEvents'
    problems = validate_query(_q(kql, table="DeviceNetworkEvents"), {"1.2.3.4"})
    assert any("control/management command" in p for p in problems)


def test_validate_hunt_flags_fabricated_ioc():
    hunt = GeneratedHunt(
        title="t",
        queries=[_q('DeviceNetworkEvents | where RemoteIP in~ ("1.2.3.4")')],
        iocs_used=["1.2.3.4", "5.6.7.8"],  # 5.6.7.8 not in source
    )
    problems = validate_hunt(hunt, {"1.2.3.4"})
    assert any("not present in the source intel" in p for p in problems)


def test_validate_hunt_clean():
    hunt = GeneratedHunt(
        title="t",
        queries=[
            _q('DeviceNetworkEvents\n| where Timestamp > ago(30d)\n| where RemoteIP in~ ("1.2.3.4")')
        ],
        iocs_used=["1.2.3.4"],
    )
    assert validate_hunt(hunt, {"1.2.3.4"}) == []
