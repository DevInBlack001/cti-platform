from __future__ import annotations

from pathlib import Path

import pytest

from collection.config import (
    ConfigNotFoundError,
    resolve_flod_db_path,
    resolve_key_dir,
    resolve_sink_path,
)


def test_flod_db_path_env_override_wins(monkeypatch, tmp_path: Path):
    db_file = tmp_path / "custom.db"
    db_file.touch()
    monkeypatch.setenv("CTI_FLOD_DB_PATH", str(db_file))

    resolved = resolve_flod_db_path()

    assert resolved.value == db_file
    assert resolved.source == "env:CTI_FLOD_DB_PATH"


def test_flod_db_path_raises_clearly_when_nothing_found(monkeypatch):
    monkeypatch.delenv("CTI_FLOD_DB_PATH", raising=False)
    monkeypatch.setattr("collection.config.glob.glob", lambda pattern: [])

    with pytest.raises(ConfigNotFoundError):
        resolve_flod_db_path()


def test_sink_path_env_override_wins(monkeypatch, tmp_path: Path):
    custom_sink = tmp_path / "custom.ndjson"
    monkeypatch.setenv("CTI_OBSERVATION_SINK", str(custom_sink))

    resolved = resolve_sink_path()

    assert resolved.value == custom_sink


def test_sink_path_has_a_sensible_default(monkeypatch):
    monkeypatch.delenv("CTI_OBSERVATION_SINK", raising=False)

    resolved = resolve_sink_path()

    assert resolved.value == (
        Path.home() / ".local" / "share" / "cti-platform" / "observations.ndjson"
    )


def test_key_dir_env_override_wins(monkeypatch, tmp_path: Path):
    custom_dir = tmp_path / "custom-keys"
    monkeypatch.setenv("CTI_KEY_DIR", str(custom_dir))

    resolved = resolve_key_dir()

    assert resolved.value == custom_dir


def test_key_dir_has_a_sensible_default(monkeypatch):
    monkeypatch.delenv("CTI_KEY_DIR", raising=False)

    resolved = resolve_key_dir()

    assert resolved.value == Path.home() / ".local" / "share" / "cti-platform" / "keys"
