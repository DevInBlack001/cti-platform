"""The Threat Observation format this project shares between nodes, and its signing."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from collection.sources.base import RawSignal


@dataclass(frozen=True)
class ThreatObservation:
    observation_id: str
    reporting_node_id: str
    observed_at: str
    indicator_type: str
    indicator_value: str
    source_verdict: str
    evidence: dict
    severity: str | None
    confidence: float | None
    signature: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def _unsigned_payload(
    observation_id: str,
    reporting_node_id: str,
    observed_at: str,
    indicator_type: str,
    indicator_value: str,
    source_verdict: str,
    evidence: dict,
    severity: str | None,
    confidence: float | None,
) -> bytes:
    payload = {
        "observation_id": observation_id,
        "reporting_node_id": reporting_node_id,
        "observed_at": observed_at,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "source_verdict": source_verdict,
        "evidence": evidence,
        "severity": severity,
        "confidence": confidence,
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def build_and_sign(
    signal: RawSignal, reporting_node_id: str, private_key: Ed25519PrivateKey
) -> ThreatObservation:
    observation_id = str(uuid.uuid4())
    observed_at = datetime.fromtimestamp(signal.observed_at, tz=timezone.utc).isoformat()

    payload = _unsigned_payload(
        observation_id,
        reporting_node_id,
        observed_at,
        signal.indicator_type,
        signal.source_address,
        signal.source_verdict,
        signal.evidence,
        None,
        None,
    )
    signature_bytes = private_key.sign(payload)

    return ThreatObservation(
        observation_id=observation_id,
        reporting_node_id=reporting_node_id,
        observed_at=observed_at,
        indicator_type=signal.indicator_type,
        indicator_value=signal.source_address,
        source_verdict=signal.source_verdict,
        evidence=signal.evidence,
        severity=None,
        confidence=None,
        signature=signature_bytes.hex(),
    )


def verify(observation: ThreatObservation, public_key: Ed25519PublicKey) -> bool:
    payload = _unsigned_payload(
        observation.observation_id,
        observation.reporting_node_id,
        observation.observed_at,
        observation.indicator_type,
        observation.indicator_value,
        observation.source_verdict,
        observation.evidence,
        observation.severity,
        observation.confidence,
    )
    try:
        public_key.verify(bytes.fromhex(observation.signature), payload)
        return True
    except InvalidSignature:
        return False
