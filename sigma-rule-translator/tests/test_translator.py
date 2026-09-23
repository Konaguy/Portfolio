"""
Tests for the Sigma -> Sentinel / Falcon translator.

Run with: pytest tests/
"""

import sys
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.microsoft365defender import KustoBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "translator"))
from falcon_backend import FalconBackend, falcon_pipeline  # noqa: E402


ENCODED_POWERSHELL_RULE = """
title: Encoded PowerShell Execution
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
"""

NETWORK_CONNECTION_RULE = """
title: Suspicious Network Connection
status: test
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort: 4444
    Image|endswith: '\\beacon.exe'
  condition: selection
"""


def _fresh(rule_yaml: str) -> SigmaCollection:
    """Parse a new SigmaCollection each time -- see cli.py's _load_rules
    docstring for why reusing one across backends is unsafe."""
    return SigmaCollection.from_yaml(rule_yaml)


class TestFalconBackend:
    def test_process_creation_field_mapping(self):
        backend = FalconBackend(processing_pipeline=falcon_pipeline())
        result = backend.convert(_fresh(ENCODED_POWERSHELL_RULE))[0]

        # Fields renamed per the Falcon field map, not left as Sigma's
        # generic 'Image'/'CommandLine' names.
        assert "FileName=" in result
        assert "CommandLine=" in result
        assert "Image=" not in result

    def test_event_type_prefix(self):
        backend = FalconBackend(processing_pipeline=falcon_pipeline())
        result = backend.convert(_fresh(ENCODED_POWERSHELL_RULE))[0]
        assert result.startswith("event_simpleName=ProcessRollup2")

    def test_network_connection_event_type_and_fields(self):
        backend = FalconBackend(processing_pipeline=falcon_pipeline())
        result = backend.convert(_fresh(NETWORK_CONNECTION_RULE))[0]
        assert result.startswith("event_simpleName=NetworkConnectIP4")
        assert "RemotePort=4444" in result
        assert "FileName=" in result

    def test_wildcard_rendered_with_asterisks_not_double_quoted(self):
        backend = FalconBackend(processing_pipeline=falcon_pipeline())
        result = backend.convert(_fresh(ENCODED_POWERSHELL_RULE))[0]
        # endswith should render as a single quoted string with a leading
        # wildcard, not nested/doubled quotes.
        assert '"*\\\\powershell.exe"' in result
        assert '""' not in result

    def test_boolean_operators_have_single_spacing(self):
        backend = FalconBackend(processing_pipeline=falcon_pipeline())
        result = backend.convert(_fresh(ENCODED_POWERSHELL_RULE))[0]
        assert "  AND  " not in result
        assert "  OR  " not in result
        assert " AND " in result
        assert " OR " in result

    def test_no_query_level_syntax_errors_across_soar_ruleset(self, soar_falcon_candidate_rules):
        """
        Smoke-test the Falcon backend against every process_creation /
        network_connection rule pattern used in the
        security-automation-soar project's detection set, to catch
        backend bugs that only show up on more complex condition trees
        (multiple OR-groups, negation, numeric fields).
        """
        backend = FalconBackend(processing_pipeline=falcon_pipeline())
        for rule_yaml in soar_falcon_candidate_rules:
            result = backend.convert(_fresh(rule_yaml))[0]
            assert result.startswith("event_simpleName=")
            assert "None" not in result  # catches unmapped/failed fields


class TestSentinelBackend:
    def test_field_mapping_to_device_process_events(self):
        backend = KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())
        result = backend.convert(_fresh(ENCODED_POWERSHELL_RULE))[0]
        assert result.startswith("DeviceProcessEvents")
        assert "ProcessCommandLine" in result


class TestCrossBackendIndependence:
    def test_converting_sentinel_then_falcon_does_not_leak_field_names(self):
        """
        Regression test for a real bug found during development: pySigma
        pipelines mutate SigmaRule objects in place. Converting the same
        parsed SigmaCollection through Sentinel's backend first, then the
        Falcon backend, silently left Sentinel's renamed field names
        ('FolderPath') in place for the Falcon output instead of Falcon's
        own mapping ('FileName'). Always parse a fresh SigmaCollection
        per backend -- this test guards against reintroducing the shared-
        object shortcut.
        """
        rules = _fresh(ENCODED_POWERSHELL_RULE)

        kusto = KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())
        kusto.convert(rules)  # mutates `rules` in place

        falcon = FalconBackend(processing_pipeline=falcon_pipeline())
        # Re-parsing (as cli.py does) rather than reusing `rules` is the
        # correct pattern -- this call would produce 'FolderPath' instead
        # of 'FileName' if we reused the already-converted `rules` object.
        result = falcon.convert(_fresh(ENCODED_POWERSHELL_RULE))[0]
        assert "FileName=" in result
        assert "FolderPath" not in result


@pytest.fixture
def soar_falcon_candidate_rules():
    """A small set of Sigma equivalents to a few rules from the
    security-automation-soar detection set, used for a broader smoke
    test of the Falcon backend."""
    return [
        # Equivalent of CD-04: scheduled task/service creation
        """
title: Scheduled Task Creation
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\schtasks.exe'
      - '\\sc.exe'
    CommandLine|contains: 'create'
  condition: selection
""",
        # Equivalent of CD-07: security tooling disabled
        """
title: Security Tooling Disabled
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'Set-MpPreference'
      - 'DisableRealtimeMonitoring'
      - 'Stop-Service WinDefend'
  condition: selection
""",
    ]
