"""Extracts threat signals from a FLOD SQLite database.

Implements the SourceConnector protocol to read FLOD's threat intelligence
database, filtering for detection verdicts of interest, and yielding signals
that report on DDoS/flood traffic. Validates the database path for safety
before opening.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from collection.sources.base import RawSignal

# Classification verdicts from FLOD that indicate a threat. Only signals with
# one of these verdicts are yielded as RawSignals.
DETECTION_VERDICTS = {"Flash Crowd", "DDoS", "Anomalous"}


class SymlinkDatabaseError(RuntimeError):
    """Raised when the configured database path is a symlink."""


class FlodConnector:
    """Reads threat signals from a FLOD SQLite database."""

    def __init__(self, db_path: Path):
        """Initializes the connector with the path to a FLOD database file."""
        self._db_path = db_path

    def iter_signals(self) -> Iterator[RawSignal]:
        """Yields every threat signal from the FLOD database.

        Validates the database path for safety (not a symlink, readable, exists),
        then queries the logs table for all rows. Filters to only detection
        verdicts and maps each row to a RawSignal with evidence from the traffic
        rate, entropy, and protocol fields.
        """
        self._check_path_is_safe_to_open()

        safe_path = quote(str(self._db_path.resolve()))
        connection = sqlite3.connect(f"file:{safe_path}?mode=ro", uri=True)
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
        """Validates that the database path is safe before opening.

        Rejects symlinks, missing files, and unreadable files. Called before
        any database access to fail fast with a clear error.
        """
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
