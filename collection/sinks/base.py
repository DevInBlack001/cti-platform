"""Defines the SinkConnector protocol for observation delivery.

Every sink connector (OpenCTI, MISP, etc.) implements this protocol to receive
and forward signed Threat Observations to its destination system.
"""

from __future__ import annotations

from typing import Protocol

from collection.schema import ThreatObservation


class SinkConnector(Protocol):
    """Protocol for delivering signed observations to a downstream system.

    Any class implementing the send method conforms to this protocol and can be
    passed to the collection pipeline to deliver observations.
    """
    def send(self, observation: ThreatObservation) -> None:
        """Sends a signed observation to the destination system.

        Raises an exception if the send fails. Whatever calls send() on a
        list of configured sinks is responsible for deciding what happens
        after one of them raises.
        """
        ...
