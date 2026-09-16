from __future__ import annotations

from typing import Iterator

from collection.sources.base import RawSignal, SourceConnector


def test_raw_signal_holds_its_fields():
    signal = RawSignal(
        observed_at=1_700_000_000.0,
        source_address="10.0.0.6",
        indicator_type="ddos-flood",
        source_verdict="DDoS",
        evidence={"rate": 950.0},
    )
    assert signal.source_address == "10.0.0.6"
    assert signal.evidence["rate"] == 950.0


class _DummyConnector:
    def iter_signals(self) -> Iterator[RawSignal]:
        yield RawSignal(
            observed_at=1.0,
            source_address="1.2.3.4",
            indicator_type="ddos-flood",
            source_verdict="DDoS",
            evidence={},
        )


def test_a_connector_implementing_the_protocol_is_iterable():
    connector: SourceConnector = _DummyConnector()
    signals = list(connector.iter_signals())
    assert len(signals) == 1
    assert signals[0].source_address == "1.2.3.4"
