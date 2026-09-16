from __future__ import annotations

import os
from pathlib import Path

import pytest

from collection.sources.flod import FlodConnector, SymlinkDatabaseError


def test_normal_rows_produce_no_signal(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    verdicts = [signal.source_verdict for signal in signals]
    assert "Normal" not in verdicts


def test_blocked_and_released_rows_are_skipped(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    verdicts = [signal.source_verdict for signal in signals]
    assert "Blocked" not in verdicts
    assert "Released" not in verdicts


def test_every_detection_verdict_produces_a_signal(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    verdicts = {signal.source_verdict for signal in signals}
    assert verdicts == {"DDoS", "Flash Crowd", "Anomalous"}


def test_signal_carries_evidence_from_the_row(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    ddos_signal = next(s for s in signals if s.source_verdict == "DDoS")
    assert ddos_signal.source_address == "10.0.0.6"
    assert ddos_signal.evidence["rate"] == 950.0
    assert ddos_signal.evidence["entropy"] == 0.2
    assert ddos_signal.evidence["proto"] == "TCP"


def test_symlinked_database_path_is_rejected(tmp_path: Path, flod_db_path: Path):
    symlink_path = tmp_path / "symlinked.db"
    symlink_path.symlink_to(flod_db_path)
    connector = FlodConnector(symlink_path)

    with pytest.raises(SymlinkDatabaseError):
        list(connector.iter_signals())


def test_missing_database_raises_file_not_found(tmp_path: Path):
    connector = FlodConnector(tmp_path / "does_not_exist.db")

    with pytest.raises(FileNotFoundError):
        list(connector.iter_signals())


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permission checks")
def test_unreadable_database_raises_permission_error(flod_db_path: Path):
    flod_db_path.chmod(0o000)
    try:
        connector = FlodConnector(flod_db_path)
        with pytest.raises(PermissionError):
            list(connector.iter_signals())
    finally:
        flod_db_path.chmod(0o600)
