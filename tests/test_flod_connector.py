from __future__ import annotations

import os
import sqlite3
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


def _make_flod_db(db_path: Path) -> None:
    """Builds a real FLOD-shaped database (same layout as the flod_db_path
    fixture) at an arbitrary path, for tests that need control over the
    filename itself."""
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT,
                proto TEXT,
                rate REAL,
                entropy REAL,
                classification TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO logs "
            "(timestamp, src_ip, dst_ip, proto, rate, entropy, classification) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1_700_000_001.0, "10.0.0.6", "10.0.0.1", "TCP", 950.0, 0.2, "DDoS"),
        )
        connection.commit()
    finally:
        connection.close()


def test_uri_special_characters_in_path_do_not_change_which_file_is_opened(
    tmp_path: Path,
):
    """A path containing '?mode=rwc&j=' must not be interpreted as SQLite URI
    query syntax: it must be percent-encoded so SQLite opens exactly the file
    the symlink/existence checks validated, not some other path SQLite's URI
    parser derives by truncating at the first '?'."""
    odd_dir = tmp_path / "evidence?mode=rwc&j="
    odd_dir.mkdir()
    odd_db_path = odd_dir / "stage2.db?mode=rwc&j="

    # A decoy file at the path SQLite's URI parser would truncate to
    # (everything before the first '?') must NOT be the file that gets
    # opened.
    decoy_path = tmp_path / "evidence"
    decoy_path.write_text("not a sqlite database")

    _make_flod_db(odd_db_path)

    connector = FlodConnector(odd_db_path)
    signals = list(connector.iter_signals())

    assert len(signals) == 1
    assert signals[0].source_address == "10.0.0.6"
    assert signals[0].evidence["proto"] == "TCP"


def test_connection_is_genuinely_read_only_even_with_special_characters_in_path(
    tmp_path: Path,
):
    """Confirms mode=ro is still honored (not silently overridden to rwc by a
    truncated URI) when the path contains characters that could otherwise be
    interpreted as URI query syntax."""
    odd_db_path = tmp_path / "stage2.db?mode=rwc&j="
    _make_flod_db(odd_db_path)

    connector = FlodConnector(odd_db_path)
    connector._check_path_is_safe_to_open()

    from urllib.parse import quote

    safe_path = quote(str(odd_db_path.resolve()))
    connection = sqlite3.connect(f"file:{safe_path}?mode=ro", uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            connection.execute("INSERT INTO logs (timestamp, src_ip, classification) VALUES (0, 'x', 'DDoS')")
            connection.commit()
    finally:
        connection.close()
