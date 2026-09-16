from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from collection.extractor import run
from collection.sources.base import RawSignal


class _StubConnector:
    def __init__(self, signals: list[RawSignal]):
        self._signals = signals

    def iter_signals(self) -> Iterator[RawSignal]:
        yield from self._signals


def _signal(address: str) -> RawSignal:
    return RawSignal(
        observed_at=1_700_000_001.0,
        source_address=address,
        indicator_type="ddos-flood",
        source_verdict="DDoS",
        evidence={"rate": 950.0, "entropy": 0.2, "proto": "TCP"},
    )


def test_run_writes_one_line_per_signal(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"
    connector = _StubConnector([_signal("10.0.0.6"), _signal("10.0.0.7")])

    written = run(connector, sink_path=sink_path)

    assert written == 2
    lines = sink_path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["indicator_value"] == "10.0.0.6"


def test_run_signs_each_observation_with_the_node_key(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"
    connector = _StubConnector([_signal("10.0.0.6")])

    run(connector, sink_path=sink_path)

    written = json.loads(sink_path.read_text().splitlines()[0])
    assert len(written["signature"]) == 128  # hex-encoded 64-byte Ed25519 signature


def test_run_appends_across_two_separate_calls(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"

    run(_StubConnector([_signal("10.0.0.6")]), sink_path=sink_path)
    run(_StubConnector([_signal("10.0.0.7")]), sink_path=sink_path)

    lines = sink_path.read_text().splitlines()
    assert len(lines) == 2
    addresses = [json.loads(line)["indicator_value"] for line in lines]
    assert addresses == ["10.0.0.6", "10.0.0.7"]


def test_run_creates_the_sinks_parent_directory(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "nested" / "dir" / "observations.ndjson"

    run(_StubConnector([_signal("10.0.0.6")]), sink_path=sink_path)

    assert sink_path.exists()
