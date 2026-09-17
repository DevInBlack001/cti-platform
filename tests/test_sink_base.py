from __future__ import annotations

from collection.schema import ThreatObservation
from collection.sinks.base import SinkConnector


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="10.0.0.6",
        source_verdict="DDoS",
        evidence={"rate": 950.0},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


class _RecordingSink:
    def __init__(self) -> None:
        self.received: list[ThreatObservation] = []

    def send(self, observation: ThreatObservation) -> None:
        self.received.append(observation)


def test_a_sink_implementing_the_protocol_receives_the_observation():
    sink: SinkConnector = _RecordingSink()
    observation = _sample_observation()

    sink.send(observation)

    assert sink.received == [observation]
