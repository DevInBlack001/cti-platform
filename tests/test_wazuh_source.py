from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from collection.sources.wazuh import SymlinkStateError, WazuhConnector

# A real SCA (compliance check) alert, pulled from a live Wazuh 4.14.7
# indexer. Its data has no srcip at all.
_SCA_ALERT = {
    "agent": {"ip": "172.16.1.5", "name": "Media", "id": "001"},
    "manager": {"name": "Wazuh-Server"},
    "data": {
        "sca": {
            "scan_id": "1535475849",
            "check": {"result": "failed", "id": "33011", "title": "Ensure nodev option set on /tmp partition."},
            "type": "check",
            "policy": "Center for Internet Security Debian Linux 12 Benchmark v1.1.0",
        }
    },
    "rule": {"level": 7, "description": "CIS Debian Linux 12 Benchmark: Ensure nodev option set on /tmp partition.", "id": "19007", "groups": ["sca"]},
    "decoder": {"name": "sca"},
    "@timestamp": "2026-02-01T22:42:06.956Z",
}

# A real SSH alert, rule.level 10, pulled from the same live indexer.
_SSH_ALERT = {
    "agent": {"name": "Wazuh-Server", "id": "000"},
    "manager": {"name": "Wazuh-Server"},
    "data": {"srcip": "172.16.1.215", "dstuser": "root", "srcport": "50770"},
    "rule": {
        "level": 10,
        "description": "Direct root SSH login from 172.16.1.215",
        "id": "100212",
        "groups": ["threat_hunting", "ssh"],
        "mitre": {"technique": ["Local Accounts"], "id": ["T1078.003"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]},
    },
    "decoder": {"name": "sshd"},
    "@timestamp": "2026-09-16T21:15:31.572Z",
}


def _search_response(hits: list[dict]) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "hits": {
            "hits": [
                {"_source": alert, "sort": [i]}
                for i, alert in enumerate(hits)
            ]
        }
    }
    return response


def test_an_sca_alert_with_no_srcip_is_skipped(tmp_path: Path):
    connector = WazuhConnector(
        indexer_url="https://indexer.example",
        user="admin",
        password="a-password",
        state_path=tmp_path / "state.json",
    )
    with patch("collection.sources.wazuh.requests.post") as mock_post:
        mock_post.side_effect = [_search_response([_SCA_ALERT]), _search_response([])]
        signals = list(connector.iter_signals())

    assert signals == []


def test_an_ssh_alert_maps_to_a_raw_signal_with_mitre_evidence(tmp_path: Path):
    connector = WazuhConnector(
        indexer_url="https://indexer.example",
        user="admin",
        password="a-password",
        state_path=tmp_path / "state.json",
    )
    with patch("collection.sources.wazuh.requests.post") as mock_post:
        mock_post.side_effect = [_search_response([_SSH_ALERT]), _search_response([])]
        signals = list(connector.iter_signals())

    assert len(signals) == 1
    signal = signals[0]
    assert signal.source_address == "172.16.1.215"
    assert signal.source_verdict == "Direct root SSH login from 172.16.1.215"
    assert signal.evidence["mitre_tactic"] == ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]
    assert signal.evidence["mitre_technique"] == ["Local Accounts"]
    assert signal.evidence["rule_level"] == 10


def test_no_destination_side_field_ever_reaches_evidence(tmp_path: Path):
    alert_with_dst = dict(_SSH_ALERT)
    alert_with_dst["data"] = dict(_SSH_ALERT["data"])
    alert_with_dst["data"]["dstip"] = "10.0.0.99"

    connector = WazuhConnector(
        indexer_url="https://indexer.example",
        user="admin",
        password="a-password",
        state_path=tmp_path / "state.json",
    )
    with patch("collection.sources.wazuh.requests.post") as mock_post:
        mock_post.side_effect = [_search_response([alert_with_dst]), _search_response([])]
        signals = list(connector.iter_signals())

    assert len(signals) == 1
    evidence_values = str(signals[0].evidence.values())
    assert "10.0.0.99" not in evidence_values
    assert "dstip" not in str(signals[0].evidence.keys())


def test_the_high_water_mark_is_respected_on_a_second_run(tmp_path: Path):
    state_path = tmp_path / "state.json"
    connector = WazuhConnector(
        indexer_url="https://indexer.example",
        user="admin",
        password="a-password",
        state_path=state_path,
    )
    with patch("collection.sources.wazuh.requests.post") as mock_post:
        mock_post.side_effect = [_search_response([_SSH_ALERT]), _search_response([])]
        list(connector.iter_signals())

    assert state_path.exists()
    saved = json.loads(state_path.read_text())
    assert saved["last_seen"] == "2026-09-16T21:15:31.572Z"

    with patch("collection.sources.wazuh.requests.post") as mock_post:
        mock_post.side_effect = [_search_response([])]
        second_run_signals = list(connector.iter_signals())

    assert second_run_signals == []
    query_sent = mock_post.call_args.kwargs["json"]
    assert query_sent["query"]["bool"]["must"][1]["range"]["@timestamp"]["gt"] == "2026-09-16T21:15:31.572Z"


def test_verifies_tls_by_default(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)
    connector = WazuhConnector(
        indexer_url="https://indexer.example",
        user="admin",
        password="a-password",
        state_path=tmp_path / "state.json",
    )
    with patch("collection.sources.wazuh.requests.post") as mock_post:
        mock_post.side_effect = [_search_response([])]
        list(connector.iter_signals())

    assert mock_post.call_args.kwargs["verify"] is True


def test_refuses_to_read_a_symlinked_state_file(tmp_path: Path):
    other_file = tmp_path / "other.json"
    other_file.write_text('{"last_seen": "2026-01-01T00:00:00.000Z"}')
    state_path = tmp_path / "state.json"
    state_path.symlink_to(other_file)

    connector = WazuhConnector(
        indexer_url="https://indexer.example",
        user="admin",
        password="a-password",
        state_path=state_path,
    )

    with pytest.raises(SymlinkStateError):
        list(connector.iter_signals())
