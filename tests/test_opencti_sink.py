from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from collection.schema import ThreatObservation
from collection.sinks.opencti import OpenCtiSinkConnector


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="203.0.113.5",
        source_verdict="DDoS",
        evidence={"rate": 950.0, "entropy": 0.2},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


def test_send_posts_a_valid_indicator_add_mutation():
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    mock_post.assert_called_once()
    call = mock_post.call_args
    assert call.args[0] == "http://localhost:8080/graphql"
    assert call.kwargs["headers"]["Authorization"] == "Bearer a-token"
    body = call.kwargs["json"]
    assert "indicatorAdd" in body["query"]
    variables = body["variables"]["input"]
    assert variables["pattern_type"] == "stix"
    assert variables["pattern"] == "[ipv4-addr:value = '203.0.113.5']"
    assert variables["name"] == "ddos-flood: 203.0.113.5"
    assert variables["indicator_types"] == ["ddos-flood"]
    mock_response.raise_for_status.assert_called_once()


def test_send_escapes_a_single_quote_in_the_indicator_value():
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = ThreatObservation(
        observation_id="22222222-2222-2222-2222-222222222222",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="fake-value-with-a-'-quote",
        source_verdict="DDoS",
        evidence={},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    pattern = mock_post.call_args.kwargs["json"]["variables"]["input"]["pattern"]
    assert pattern == "[ipv4-addr:value = 'fake-value-with-a-\\'-quote']"


def test_send_raises_when_opencti_returns_graphql_errors():
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"errors": [{"message": "bad input"}]}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response):
        with pytest.raises(RuntimeError, match="bad input"):
            connector.send(observation)


def test_send_verifies_tls_by_default(monkeypatch):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    assert mock_post.call_args.kwargs["verify"] is True


def test_send_skips_tls_verification_only_when_explicitly_allowed(monkeypatch):
    monkeypatch.setenv("CTI_ALLOW_INSECURE_TLS", "true")
    connector = OpenCtiSinkConnector(url="https://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    assert mock_post.call_args.kwargs["verify"] is False
