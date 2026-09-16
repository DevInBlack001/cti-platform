"""The interface every believed-observation destination implements."""

from __future__ import annotations

from typing import Protocol

from collection.schema import ThreatObservation


class SinkConnector(Protocol):
    def send(self, observation: ThreatObservation) -> None: ...
