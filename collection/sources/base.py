"""Defines the RawSignal and SourceConnector protocol for threat data sources.

Sources (FLOD, Wazuh, MISP, etc.) emit RawSignals that are converted into
signed Threat Observations by the collection pipeline. Every source implements
the SourceConnector protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Protocol


@dataclass(frozen=True)
class RawSignal:
    """A single threat indicator extracted from a source.

    Represents a raw detection or observation from a source system before it is
    converted into a signed ThreatObservation. Contains the indicator value
    (IP, domain, hash, etc.), its type, the source's verdict on it, and any
    supporting evidence.
    """
    observed_at: float
    source_address: str
    indicator_type: str
    source_verdict: str
    evidence: dict = field(default_factory=dict)


class SourceConnector(Protocol):
    """Protocol for extracting threat indicators from a source system.

    Any class implementing iter_signals conforms to this protocol and can be
    passed to the collection pipeline to feed observations.
    """
    def iter_signals(self) -> Iterator[RawSignal]:
        """Yields every threat signal available from the source.

        Implementations should validate their configuration and data access during
        the first iteration, before yielding any signals, so the extractor can
        fail fast without creating the key or sink.
        """
        ...
