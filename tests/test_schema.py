from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collection.schema import build_and_sign, verify
from collection.sources.base import RawSignal


def _sample_signal() -> RawSignal:
    return RawSignal(
        observed_at=1_700_000_001.0,
        source_address="10.0.0.6",
        indicator_type="ddos-flood",
        source_verdict="DDoS",
        evidence={"rate": 950.0, "entropy": 0.2, "proto": "TCP"},
    )


def test_build_and_sign_maps_the_signal_correctly():
    private_key = Ed25519PrivateKey.generate()
    signal = _sample_signal()

    observation = build_and_sign(signal, "node-abc123", private_key)

    assert observation.indicator_type == "ddos-flood"
    assert observation.indicator_value == "10.0.0.6"
    assert observation.source_verdict == "DDoS"
    assert observation.reporting_node_id == "node-abc123"
    assert observation.evidence == {"rate": 950.0, "entropy": 0.2, "proto": "TCP"}


def test_severity_and_confidence_stay_empty_this_milestone():
    private_key = Ed25519PrivateKey.generate()

    observation = build_and_sign(_sample_signal(), "node-abc123", private_key)

    assert observation.severity is None
    assert observation.confidence is None


def test_observed_at_is_converted_to_iso_8601_utc():
    private_key = Ed25519PrivateKey.generate()
    signal = _sample_signal()

    observation = build_and_sign(signal, "node-abc123", private_key)

    expected = datetime.fromtimestamp(signal.observed_at, tz=timezone.utc).isoformat()
    assert observation.observed_at == expected


def test_signature_verifies_against_the_signing_nodes_public_key():
    private_key = Ed25519PrivateKey.generate()

    observation = build_and_sign(_sample_signal(), "node-abc123", private_key)

    assert verify(observation, private_key.public_key()) is True


def test_signature_fails_to_verify_if_a_field_is_altered_afterward():
    private_key = Ed25519PrivateKey.generate()
    observation = build_and_sign(_sample_signal(), "node-abc123", private_key)

    tampered = replace(observation, indicator_value="9.9.9.9")

    assert verify(tampered, private_key.public_key()) is False


def test_two_observations_of_the_same_signal_get_different_ids():
    private_key = Ed25519PrivateKey.generate()
    signal = _sample_signal()

    first = build_and_sign(signal, "node-abc123", private_key)
    second = build_and_sign(signal, "node-abc123", private_key)

    assert first.observation_id != second.observation_id
