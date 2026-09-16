"""The interface every threat data source implements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Protocol


@dataclass(frozen=True)
class RawSignal:
    observed_at: float
    source_address: str
    indicator_type: str
    source_verdict: str
    evidence: dict = field(default_factory=dict)


class SourceConnector(Protocol):
    def iter_signals(self) -> Iterator[RawSignal]:
        ...
