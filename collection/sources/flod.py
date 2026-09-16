"""Reads a FLOD-shaped SQLite database and yields RawSignals.

Table and column layout taken from FLOD's own stage2/schema.py.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Iterator

from collection.sources.base import RawSignal

DETECTION_VERDICTS = {"Flash Crowd", "DDoS", "Anomalous"}


class SymlinkDatabaseError(RuntimeError):
    """Raised when the configured database path is a symlink."""


class FlodConnector:
    def __init__(self, db_path: Path):
        self._db_path = db_path

    def iter_signals(self) -> Iterator[RawSignal]:
        self._check_path_is_safe_to_open()

        connection = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
        try:
            cursor = connection.execute(
                "SELECT timestamp, src_ip, proto, rate, entropy, classification "
                "FROM logs"
            )
            for timestamp, src_ip, proto, rate, entropy, classification in cursor:
                if classification not in DETECTION_VERDICTS:
                    continue
                yield RawSignal(
                    observed_at=timestamp,
                    source_address=src_ip,
                    indicator_type="ddos-flood",
                    source_verdict=classification,
                    evidence={"rate": rate, "entropy": entropy, "proto": proto},
                )
        finally:
            connection.close()

    def _check_path_is_safe_to_open(self) -> None:
        if self._db_path.is_symlink():
            raise SymlinkDatabaseError(
                f"{self._db_path} is a symlink, refusing to open it"
            )
        if not self._db_path.exists():
            raise FileNotFoundError(f"No database found at {self._db_path}")
        if not os.access(self._db_path, os.R_OK):
            raise PermissionError(
                f"{self._db_path} exists but is not readable by this user"
            )
