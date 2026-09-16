"""Ties a source connector to the Threat Observation sink."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from collection.config import resolve_sink_path
from collection.keys import load_or_create_node_key, node_fingerprint
from collection.schema import build_and_sign
from collection.sources.base import SourceConnector


def run(connector: SourceConnector, sink_path: Path | None = None) -> int:
    """Processes every signal the connector yields, once. Returns the count written."""
    destination = sink_path if sink_path is not None else resolve_sink_path().value
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    private_key = load_or_create_node_key()
    reporting_node_id = node_fingerprint(private_key)

    written = 0
    fd = os.open(
        str(destination),
        os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
        mode=0o600,
    )
    with os.fdopen(fd, "a", encoding="utf-8") as sink_file:
        for signal in connector.iter_signals():
            try:
                observation = build_and_sign(signal, reporting_node_id, private_key)
                sink_file.write(observation.to_json() + "\n")
            except Exception as exc:
                source = getattr(signal, "source_address", "unknown")
                print(
                    f"cti-platform: skipping signal from {source}: {exc}",
                    file=sys.stderr,
                )
                continue
            written += 1
    return written
