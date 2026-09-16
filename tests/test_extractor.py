from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

import pytest

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


def test_refuses_to_write_through_a_symlinked_sink_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_dir = tmp_path / "sink_dir"
    sink_dir.mkdir()
    sink_path = sink_dir / "observations.ndjson"

    # Create a symlink to some other file at the sink path
    other_file = tmp_path / "other_file"
    other_file.write_text("dummy")
    sink_path.symlink_to(other_file)

    connector = _StubConnector([_signal("10.0.0.6")])

    with pytest.raises(OSError):
        run(connector, sink_path=sink_path)

    # The symlink target must not have been written through
    assert other_file.read_text() == "dummy"


def test_sink_file_is_owner_only(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"

    run(_StubConnector([_signal("10.0.0.6")]), sink_path=sink_path)

    mode = sink_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_sink_directory_is_owner_only(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "nested" / "dir" / "observations.ndjson"

    run(_StubConnector([_signal("10.0.0.6")]), sink_path=sink_path)

    mode = sink_path.parent.stat().st_mode & 0o777
    assert mode == 0o700
