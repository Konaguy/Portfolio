"""
Tests for FalconClient. All falconpy SDK calls are mocked -- no live
Falcon tenant or credentials required to run this suite.

Run with: pytest tests/
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def mocked_client():
    """
    Build a FalconClient with Hosts / RealTimeResponse / Alerts patched
    at the point they're imported into falcon_rtr.client, and yield both
    the client and the three mock objects so tests can set return values
    and assert on call args.
    """
    with patch("falcon_rtr.client.Hosts") as MockHosts, \
         patch("falcon_rtr.client.RealTimeResponse") as MockRTR, \
         patch("falcon_rtr.client.Alerts") as MockAlerts:

        from falcon_rtr import FalconClient

        client = FalconClient(client_id="test-id", client_secret="test-secret")
        yield client, MockHosts.return_value, MockRTR.return_value, MockAlerts.return_value


class TestHostDetails:
    def test_get_host_details_returns_first_resource(self, mocked_client):
        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "abc123", "hostname": "WIN-TEST", "status": "normal"}]},
        }
        details = client.get_host_details("abc123")
        assert details["hostname"] == "WIN-TEST"

    def test_get_host_details_raises_when_empty(self, mocked_client):
        from falcon_rtr.exceptions import HostNotFoundError

        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        with pytest.raises(HostNotFoundError):
            client.get_host_details("nonexistent")

    def test_get_host_details_raises_on_api_error(self, mocked_client):
        from falcon_rtr.exceptions import HostNotFoundError

        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "access denied"}]},
        }
        with pytest.raises(HostNotFoundError) as exc_info:
            client.get_host_details("abc123")
        assert exc_info.value.status_code == 403


class TestContainment:
    def test_contain_host_calls_perform_action_when_not_contained(self, mocked_client):
        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "abc123", "status": "normal"}]},
        }
        mock_hosts.perform_action.return_value = {"status_code": 202, "body": {}}

        result = client.contain_host("abc123")

        mock_hosts.perform_action.assert_called_once_with(action_name="contain", ids=["abc123"])
        assert result["status"] == "requested"

    def test_contain_host_is_idempotent(self, mocked_client):
        """Calling contain_host on an already-contained host should not
        make a second perform_action API call."""
        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "abc123", "status": "contained"}]},
        }

        result = client.contain_host("abc123")

        mock_hosts.perform_action.assert_not_called()
        assert result["status"] == "already_contained"

    def test_lift_containment_is_idempotent(self, mocked_client):
        """Calling lift_containment on a host that isn't contained should
        not make a perform_action API call."""
        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "abc123", "status": "normal"}]},
        }

        result = client.lift_containment("abc123")

        mock_hosts.perform_action.assert_not_called()
        assert result["status"] == "not_contained"

    def test_contain_host_raises_on_api_error(self, mocked_client):
        from falcon_rtr.exceptions import FalconClientError

        client, mock_hosts, _, _ = mocked_client
        mock_hosts.get_device_details_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [{"device_id": "abc123", "status": "normal"}]},
        }
        mock_hosts.perform_action.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "internal error"}]},
        }

        with pytest.raises(FalconClientError):
            client.contain_host("abc123")


class TestRealTimeResponse:
    def test_kill_process_initializes_session_then_sends_command(self, mocked_client):
        client, _, mock_rtr, _ = mocked_client
        mock_rtr.batch_init_sessions.return_value = {
            "status_code": 201,
            "body": {"batch_id": "batch-xyz"},
        }
        mock_rtr.batch_active_responder_command.return_value = {
            "status_code": 201,
            "body": {"combined": {"resources": {"abc123": {"complete": True, "stdout": "killed"}}}},
        }

        result = client.kill_process("abc123", pid=4821)

        mock_rtr.batch_init_sessions.assert_called_once_with(host_ids=["abc123"])
        mock_rtr.batch_active_responder_command.assert_called_once()
        call_kwargs = mock_rtr.batch_active_responder_command.call_args.kwargs
        assert call_kwargs["base_command"] == "kill"
        assert call_kwargs["command_string"] == "kill 4821"
        assert call_kwargs["batch_id"] == "batch-xyz"
        assert result["complete"] is True

    def test_run_rtr_command_raises_when_session_init_fails(self, mocked_client):
        from falcon_rtr.exceptions import RTRSessionError

        client, _, mock_rtr, _ = mocked_client
        mock_rtr.batch_init_sessions.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "session init failed"}]},
        }

        with pytest.raises(RTRSessionError):
            client.kill_process("abc123", pid=999)

        # Should never attempt the command if session init failed.
        mock_rtr.batch_active_responder_command.assert_not_called()

    def test_run_rtr_command_raises_when_no_batch_id_returned(self, mocked_client):
        from falcon_rtr.exceptions import RTRSessionError

        client, _, mock_rtr, _ = mocked_client
        mock_rtr.batch_init_sessions.return_value = {"status_code": 201, "body": {}}

        with pytest.raises(RTRSessionError):
            client.collect_process_list("abc123")


class TestDetectionStatus:
    def test_update_detection_status_calls_alerts_api(self, mocked_client):
        client, _, _, mock_alerts = mocked_client
        mock_alerts.update_alerts_v3.return_value = {"status_code": 200, "body": {}}

        result = client.update_detection_status("ldt:abc:123", status="closed")

        mock_alerts.update_alerts_v3.assert_called_once_with(
            composite_ids=["ldt:abc:123"],
            action_parameters=[{"name": "update_status", "value": "closed"}],
        )
        assert result["status"] == "closed"

    def test_update_detection_status_rejects_invalid_status(self, mocked_client):
        client, _, _, _ = mocked_client
        with pytest.raises(ValueError):
            client.update_detection_status("ldt:abc:123", status="not_a_real_status")

    def test_update_detection_status_appends_comment_when_given(self, mocked_client):
        client, _, _, mock_alerts = mocked_client
        mock_alerts.update_alerts_v3.return_value = {"status_code": 200, "body": {}}

        client.update_detection_status("ldt:abc:123", status="closed", comment="Confirmed false positive")

        assert mock_alerts.update_alerts_v3.call_count == 2
        second_call_kwargs = mock_alerts.update_alerts_v3.call_args_list[1].kwargs
        assert second_call_kwargs["action_parameters"][0]["name"] == "append_comment"


class TestClientConstruction:
    def test_raises_without_credentials(self, monkeypatch):
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        with patch("falcon_rtr.client.Hosts"), \
             patch("falcon_rtr.client.RealTimeResponse"), \
             patch("falcon_rtr.client.Alerts"):
            from falcon_rtr import FalconClient
            with pytest.raises(ValueError):
                FalconClient()

    def test_reads_credentials_from_environment(self, monkeypatch):
        monkeypatch.setenv("FALCON_CLIENT_ID", "env-id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "env-secret")
        with patch("falcon_rtr.client.Hosts") as MockHosts, \
             patch("falcon_rtr.client.RealTimeResponse"), \
             patch("falcon_rtr.client.Alerts"):
            from falcon_rtr import FalconClient
            FalconClient()
            _, kwargs = MockHosts.call_args
            assert kwargs["client_id"] == "env-id"
            assert kwargs["client_secret"] == "env-secret"
