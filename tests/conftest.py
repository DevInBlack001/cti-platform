"""Shared pytest fixtures: a FLOD-shaped database for the connector tests.

The logs table below is copied verbatim from FLOD's own
stage2/schema.py (ddos-reduction-system), not assumed from its docs.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

FLOD_LOGS_TABLE = """
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

# (timestamp, src_ip, dst_ip, proto, rate, entropy, classification)
FIXTURE_ROWS = [
    (1_700_000_000.0, "10.0.0.5", "10.0.0.1", "TCP", 12.5, 3.9, "Normal"),
    (1_700_000_001.0, "10.0.0.6", "10.0.0.1", "TCP", 950.0, 0.2, "DDoS"),
    (1_700_000_002.0, "10.0.0.7", "10.0.0.1", "TCP", 420.0, 1.1, "Flash Crowd"),
    (1_700_000_003.0, "10.0.0.8", "10.0.0.1", "UDP", 200.0, 4.7, "Anomalous"),
    (1_700_000_004.0, "10.0.0.6", "10.0.0.1", "TCP", None, None, "Blocked"),
    (1_700_000_005.0, "10.0.0.6", "10.0.0.1", "TCP", None, None, "Released"),
]


@pytest.fixture
def flod_db_path(tmp_path: Path) -> Path:
    db_path = tmp_path / "stage2.db"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(FLOD_LOGS_TABLE)
        connection.executemany(
            "INSERT INTO logs "
            "(timestamp, src_ip, dst_ip, proto, rate, entropy, classification) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            FIXTURE_ROWS,
        )
        connection.commit()
    finally:
        connection.close()
    return db_path
