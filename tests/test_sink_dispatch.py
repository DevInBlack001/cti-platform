from __future__ import annotations

from collection.schema import ThreatObservation
from collection.sinks.dispatch import send_to_all


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


class _RecordingSink:
    def __init__(self) -> None:
        self.received: list[ThreatObservation] = []

    def send(self, observation: ThreatObservation) -> None:
        self.received.append(observation)


class _FailingSink:
    def send(self, observation: ThreatObservation) -> None:
        raise RuntimeError("this sink is down")


def test_send_to_all_reaches_every_configured_sink():
    sink_a = _RecordingSink()
    sink_b = _RecordingSink()
    observation = _sample_observation()

    errors = send_to_all(observation, [sink_a, sink_b])

    assert errors == []
    assert sink_a.received == [observation]
    assert sink_b.received == [observation]


def test_a_failing_sink_does_not_block_the_others():
    good_sink = _RecordingSink()
    bad_sink = _FailingSink()
    observation = _sample_observation()

    errors = send_to_all(observation, [bad_sink, good_sink])

    assert len(errors) == 1
    assert "this sink is down" in str(errors[0])
    assert good_sink.received == [observation]
