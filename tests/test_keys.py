from __future__ import annotations

from pathlib import Path

from collection.keys import load_or_create_node_key, node_fingerprint


def test_first_call_generates_a_key_pair(tmp_path: Path):
    key_dir = tmp_path / "keys"

    load_or_create_node_key(key_dir)

    assert (key_dir / "node_private_key.pem").exists()
    assert (key_dir / "node_public_key.pem").exists()


def test_private_key_file_is_owner_only(tmp_path: Path):
    key_dir = tmp_path / "keys"

    load_or_create_node_key(key_dir)

    mode = (key_dir / "node_private_key.pem").stat().st_mode & 0o777
    assert mode == 0o600


def test_second_call_reuses_the_same_key(tmp_path: Path):
    key_dir = tmp_path / "keys"

    first_key = load_or_create_node_key(key_dir)
    second_key = load_or_create_node_key(key_dir)

    assert node_fingerprint(first_key) == node_fingerprint(second_key)


def test_fingerprint_is_a_short_hex_string(tmp_path: Path):
    key_dir = tmp_path / "keys"

    key = load_or_create_node_key(key_dir)
    fingerprint = node_fingerprint(key)

    assert len(fingerprint) == 16
    assert all(char in "0123456789abcdef" for char in fingerprint)
