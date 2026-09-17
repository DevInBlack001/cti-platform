"""Fans a believed observation out to every configured sink.

This module provides the core fan-out logic for distributing threat
observations to multiple sinks. Each sink is tried independently, and
failures in one sink do not prevent others from receiving the observation.
This allows a node with multiple downstream systems to continue feeding
data to functional sinks even when one is temporarily unavailable.
"""

from __future__ import annotations

from collection.schema import ThreatObservation
from collection.sinks.base import SinkConnector


def send_to_all(
    observation: ThreatObservation, sinks: list[SinkConnector]
) -> list[Exception]:
    """Calls send() on every sink. One sink failing does not stop the rest.

    Args:
        observation: The threat observation to distribute to all sinks.
        sinks: A list of sink instances, each with a send() method.

    Returns:
        A list of exceptions raised by any sinks that failed. An empty list
        means all sinks accepted the observation successfully.
    """
    # Accumulate exceptions from any failing sinks so they can be reported
    # by the caller without preventing other sinks from processing.
    errors: list[Exception] = []
    for sink in sinks:
        try:
            # Each sink receives the observation independently.
            sink.send(observation)
        except Exception as exc:
            # Capture the exception and continue to the next sink.
            errors.append(exc)
    return errors
