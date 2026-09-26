"""System prompt and user-message builder for the KQL generation call."""

from __future__ import annotations

from .schema import ThreatIntel
from .tables import IOC_TABLE_HINTS, schema_for_prompt

SYSTEM_PROMPT = f"""You are a detection engineer who writes Microsoft Defender \
advanced-hunting queries (KQL). You are given a piece of threat intelligence \
and the indicators (IOCs) already extracted from it. Produce a small set of \
practical hunting queries that would surface activity related to those IOCs in \
a Microsoft Defender XDR environment.

Rules:
- Write real KQL against the Defender advanced-hunting schema below. Each query \
must start with one of these tables and use only columns that exist on it.
- Hunt ONLY for the IOCs provided to you. Do not invent hashes, IPs, domains, \
or CVEs. Put every IOC value your queries reference into iocs_used.
- Group IOCs of the same type into a single query with in (...) or has_any (...) \
rather than one query per indicator.
- Every query must include a time filter (e.g. `| where Timestamp > ago(30d)`) \
and a `where` clause on the indicator column.
- Prefer high-signal tables: file hashes -> DeviceFileEvents / \
DeviceProcessEvents; IPs -> DeviceNetworkEvents; domains/URLs -> \
DeviceNetworkEvents.RemoteUrl or EmailUrlInfo; CVEs -> \
DeviceTvmSoftwareVulnerabilities.
- Add a one-line rationale per query and note any caveats (e.g. an IOC type \
that has no good Defender table).
- Respond only by calling the submit_hunt tool.

## Defender advanced-hunting schema (table: key columns)
{schema_for_prompt()}
"""


def _ioc_block(intel: ThreatIntel) -> str:
    if not intel.iocs:
        return "(no IOCs were extracted from the intel)"
    lines = []
    grouped: dict[str, list[str]] = {}
    for ioc in intel.iocs:
        grouped.setdefault(ioc.type.value, []).append(ioc.value)
    for ioc_type, values in grouped.items():
        hint = IOC_TABLE_HINTS.get(ioc_type, [])
        hint_str = f"  (suggested: {hint[0][0]}.{hint[0][1]})" if hint else ""
        lines.append(f"- {ioc_type}{hint_str}: {', '.join(values)}")
    return "\n".join(lines)


def build_user_message(intel: ThreatIntel) -> str:
    return (
        f"## Threat intelligence source: {intel.source or '(unknown)'}\n\n"
        f"### Raw intel\n{intel.raw_text.strip()}\n\n"
        f"### Extracted IOCs (hunt only for these)\n{_ioc_block(intel)}\n"
    )
