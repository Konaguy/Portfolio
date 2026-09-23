"""
A minimal pySigma backend targeting CrowdStrike Falcon's Event Search
query syntax (the query language used in Falcon's "Investigate > Event
Search" and Fusion SOAR condition builder).

CrowdStrike doesn't publish an official pySigma backend (unlike Microsoft,
which maintains pysigma-backend-microsoft365defender), so this is a
from-scratch implementation covering the subset of Falcon's query syntax
needed for process-creation and network-connection detections — the two
log source categories used throughout this portfolio's detection rules.

Falcon query syntax basics this backend targets:
    event_simpleName=ProcessRollup2 FileName="powershell.exe"
    event_simpleName=ProcessRollup2 CommandLine="*-enc*"
    (A OR B) AND C   -- standard boolean grouping with explicit parens

Extending to other log sources (registry, file, image-load) means adding
entries to FIELD_MAPPINGS and EVENT_TYPE_MAPPING below, following the same
pattern -- the query-construction logic itself doesn't need to change.
"""

from __future__ import annotations

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.conditions import LogsourceCondition
from sigma.rule import SigmaRule
from typing import ClassVar, Optional, Any


# --- Field name mapping: Sigma's common taxonomy -> Falcon field names ---
# Falcon's raw event schema differs from Sigma's Windows taxonomy the same
# way Sentinel's DeviceProcessEvents schema does -- this table is the
# CrowdStrike analogue of the Microsoft365Defender pipeline's field map.
PROCESS_CREATION_FIELD_MAP = {
    "Image": "FileName",
    "CommandLine": "CommandLine",
    "ParentImage": "ParentBaseFileName",
    "ParentCommandLine": "ParentCommandLine",
    "User": "UserName",
    "ComputerName": "ComputerName",
    "Hashes": "SHA256HashData",
}

NETWORK_CONNECTION_FIELD_MAP = {
    "DestinationIp": "RemoteAddressIP4",
    "DestinationPort": "RemotePort",
    "SourceIp": "LocalAddressIP4",
    "Image": "FileName",
    "ComputerName": "ComputerName",
}

# Falcon's event_simpleName value per Sigma logsource category. Used to
# prefix every generated query so it's scoped to the right event type.
EVENT_TYPE_MAPPING = {
    "process_creation": "ProcessRollup2",
    "network_connection": "NetworkConnectIP4",
}


def falcon_pipeline() -> ProcessingPipeline:
    """
    Build the field-mapping pipeline applied before conversion, mirroring
    how pysigma-backend-microsoft365defender's pipeline works: map generic
    Sigma field names onto the target platform's actual schema, scoped by
    logsource category so process-creation and network-connection rules
    each get the right mapping table.
    """
    return ProcessingPipeline(
        name="crowdstrike_falcon_pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="falcon_process_creation_fieldmapping",
                transformation=FieldMappingTransformation(PROCESS_CREATION_FIELD_MAP),
                rule_conditions=[
                    LogsourceCondition(category="process_creation", product="windows")
                ],
            ),
            ProcessingItem(
                identifier="falcon_network_connection_fieldmapping",
                transformation=FieldMappingTransformation(NETWORK_CONNECTION_FIELD_MAP),
                rule_conditions=[
                    LogsourceCondition(category="network_connection", product="windows")
                ],
            ),
        ],
    )


class FalconBackend(TextQueryBackend):
    """pySigma backend emitting CrowdStrike Falcon Event Search queries."""

    name: ClassVar[str] = "CrowdStrike Falcon Event Search backend"
    formats: ClassVar[dict] = {"default": "Falcon Event Search query string"}
    requires_pipeline: ClassVar[bool] = True

    # --- boolean operators ---
    # Left plain (no surrounding spaces) -- pySigma's token_separator
    # (a single space) is inserted around these automatically when
    # joining conditions, so adding spaces here would double them up.
    and_token: ClassVar[str] = "AND"
    or_token: ClassVar[str] = "OR"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    # --- grouping ---
    group_expression: ClassVar[str] = "({expr})"

    # --- field/value quoting ---
    field_quote: ClassVar[str] = ""
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = '"\\'

    # --- comparison ---
    # Falcon's query syntax has no dedicated startswith/endswith/contains
    # operators -- everything is expressed as a quoted value with `*`
    # wildcards. So we deliberately leave startswith/endswith/contains
    # unset and let every wildcard-bearing value fall through to
    # wildcard_match_expression, where convert_value_str() has already
    # rendered the Sigma wildcard markers as literal `*` characters inside
    # the quoted string (see FalconBackend's `wildcard_multi` above).
    startswith_expression: ClassVar[Optional[str]] = None
    endswith_expression: ClassVar[Optional[str]] = None
    contains_expression: ClassVar[Optional[str]] = None
    wildcard_match_expression: ClassVar[str] = "{field}={value}"

    field_null_expression: ClassVar[str] = "{field}=null"

    # --- IN expressions rendered as OR groups (Falcon has no native IN) ---
    convert_or_as_in: ClassVar[bool] = False

    def finalize_query(
        self,
        rule: SigmaRule,
        query: str,
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> str:
        """Prefix every query with the correct event_simpleName scope."""
        category = getattr(rule.logsource, "category", None)
        event_name = EVENT_TYPE_MAPPING.get(category)
        if event_name:
            return f'event_simpleName={event_name} {query}'
        return query
