from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from collection.schema import ThreatObservation
from collection.sinks.wazuh import WazuhSinkConnector


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="203.0.113.5",
        source_verdict="DDoS",
        evidence={},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


def test_send_authenticates_then_triggers_the_configured_active_response_command():
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000", user="wazuh", password="a-password"
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 0}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response) as mock_auth, \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response) as mock_put:
        connector.send(observation)

    mock_auth.assert_called_once()
    assert mock_auth.call_args.kwargs["auth"] == ("wazuh", "a-password")

    mock_put.assert_called_once()
    put_call = mock_put.call_args
    assert put_call.args[0] == "https://wazuh.example:55000/active-response"
    assert put_call.kwargs["headers"]["Authorization"] == "Bearer a-jwt-token"
    body = put_call.kwargs["json"]
    assert body["command"] == "firewall-drop600"
    assert body["alert"]["data"]["srcip"] == "203.0.113.5"
    ar_response.raise_for_status.assert_called_once()


def test_send_uses_a_custom_command_when_configured():
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000",
        user="wazuh",
        password="a-password",
        command="firewall-drop3600",
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 0}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response), \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response) as mock_put:
        connector.send(observation)

    assert mock_put.call_args.kwargs["json"]["command"] == "firewall-drop3600"


def test_send_raises_when_wazuh_reports_an_error():
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000", user="wazuh", password="a-password"
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 1, "message": "invalid command"}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response), \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response):
        with pytest.raises(RuntimeError, match="invalid command"):
            connector.send(observation)


def test_send_verifies_tls_by_default(monkeypatch):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000", user="wazuh", password="a-password"
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 0}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response) as mock_post, \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response) as mock_put:
        connector.send(observation)

    assert mock_post.call_args.kwargs["verify"] is True
    assert mock_put.call_args.kwargs["verify"] is True
