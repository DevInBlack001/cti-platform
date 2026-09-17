"""Defines the Threat Observation schema and its Ed25519 signing protocol.

Observations are the core unit of threat intelligence shared between collection
nodes. Each one represents a single indicator (IP, domain, hash, etc.) matched
against a source, signed with the reporting node's private key so downstream
systems can verify their authenticity.
"""

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
    """A signed threat intelligence observation shared between collection nodes.

    Each observation represents a single indicator matched against a source, along
    with the evidence supporting that match. The signature is an Ed25519 signature
    over all fields except the signature itself, allowing downstream systems to
    verify the observation's authenticity and integrity.
    """
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
        """Serializes this observation to newline-delimited JSON.

        Produces a sorted JSON representation suitable for appending to an NDJSON file.
        Rejects any non-finite field values (NaN or infinity) at serialization time.
        """
        return json.dumps(asdict(self), sort_keys=True, allow_nan=False)


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
    """Constructs the JSON bytes to be signed by the node's private key.

    Used both to create the signature during build_and_sign and to verify it
    during verify. The signature covers all observation fields to detect any
    tampering or mutation.
    """
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
    return json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8")


def build_and_sign(
    signal: RawSignal, reporting_node_id: str, private_key: Ed25519PrivateKey
) -> ThreatObservation:
    """Constructs a ThreatObservation from a raw signal and signs it.

    Generates a unique observation ID, converts the signal's timestamp to ISO 8601
    UTC format, and creates an Ed25519 signature over the observation's canonical
    JSON representation. Severity and confidence are currently left empty.
    """
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
    """Verifies an observation's signature using its reporting node's public key.

    Returns True if the signature is valid and the observation's data has not been
    tampered with, False if the signature is invalid.
    """
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
