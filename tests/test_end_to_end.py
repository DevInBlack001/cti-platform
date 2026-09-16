from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from collection.__main__ import main
from collection.schema import ThreatObservation, verify


def test_a_full_pass_produces_verifiable_observations(
    tmp_path: Path, flod_db_path: Path, monkeypatch
):
    monkeypatch.setenv("CTI_FLOD_DB_PATH", str(flod_db_path))
    sink_path = tmp_path / "observations.ndjson"
    monkeypatch.setenv("CTI_OBSERVATION_SINK", str(sink_path))
    key_dir = tmp_path / "keys"
    monkeypatch.setenv("CTI_KEY_DIR", str(key_dir))

    exit_code = main()

    assert exit_code == 0
    public_key_bytes = (key_dir / "node_public_key.pem").read_bytes()
    public_key = serialization.load_pem_public_key(public_key_bytes)

    lines = sink_path.read_text().splitlines()
    assert len(lines) == 3  # DDoS, Flash Crowd, Anomalous from the fixture

    for line in lines:
        observation = ThreatObservation(**json.loads(line))
        assert verify(observation, public_key) is True

    verdicts = {json.loads(line)["source_verdict"] for line in lines}
    assert verdicts == {"DDoS", "Flash Crowd", "Anomalous"}
