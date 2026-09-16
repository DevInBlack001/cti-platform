"""Ties a source connector to the Threat Observation sink."""

from __future__ import annotations

import itertools
import os
import sys
from pathlib import Path

from collection.config import resolve_sink_path
from collection.keys import load_or_create_node_key, node_fingerprint
from collection.schema import build_and_sign
from collection.sources.base import SourceConnector

_NO_SIGNAL = object()


def run(connector: SourceConnector, sink_path: Path | None = None) -> int:
    """Processes every signal the connector yields, once. Returns the count written."""
    signals = connector.iter_signals()
    # Forces the connector's own safety checks (a generator's body only runs up
    # to its first yield on this first call) to happen before the sink file or
    # this node's signing key are created, so a source that fails validation
    # never leaves a permanent node identity or an empty sink file behind.
    first_signal = next(signals, _NO_SIGNAL)

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
        if first_signal is _NO_SIGNAL:
            return written

        for signal in itertools.chain([first_signal], signals):
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
