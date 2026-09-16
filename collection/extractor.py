"""Ties a source connector to the Threat Observation sink."""

from __future__ import annotations

from pathlib import Path

from collection.config import resolve_sink_path
from collection.keys import load_or_create_node_key, node_fingerprint
from collection.schema import build_and_sign
from collection.sources.base import SourceConnector


def run(connector: SourceConnector, sink_path: Path | None = None) -> int:
    """Processes every signal the connector yields, once. Returns the count written."""
    destination = sink_path if sink_path is not None else resolve_sink_path().value
    destination.parent.mkdir(parents=True, exist_ok=True)

    private_key = load_or_create_node_key()
    reporting_node_id = node_fingerprint(private_key)

    written = 0
    with destination.open("a", encoding="utf-8") as sink_file:
        for signal in connector.iter_signals():
            observation = build_and_sign(signal, reporting_node_id, private_key)
            sink_file.write(observation.to_json() + "\n")
            written += 1
    return written
