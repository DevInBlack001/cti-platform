from __future__ import annotations

import os
from pathlib import Path

import pytest

from collection.__main__ import main


def test_main_returns_zero_and_writes_observations(
    tmp_path: Path, flod_db_path: Path, monkeypatch, capsys
):
    monkeypatch.setenv("CTI_FLOD_DB_PATH", str(flod_db_path))
    monkeypatch.setenv("CTI_OBSERVATION_SINK", str(tmp_path / "out.ndjson"))
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))

    exit_code = main()

    assert exit_code == 0
    assert (tmp_path / "out.ndjson").exists()
    output = capsys.readouterr().out
    assert "Wrote 3 observation" in output


def test_main_returns_one_when_the_database_cannot_be_found(
    tmp_path: Path, monkeypatch, capsys
):
    monkeypatch.delenv("CTI_FLOD_DB_PATH", raising=False)
    monkeypatch.setattr("collection.config.glob.glob", lambda pattern: [])

    exit_code = main()

    assert exit_code == 1
    error_output = capsys.readouterr().err
    assert "No FLOD database found" in error_output


def test_main_returns_one_with_a_clear_message_when_the_configured_db_file_is_missing(
    tmp_path: Path, monkeypatch, capsys
):
    monkeypatch.setenv("CTI_FLOD_DB_PATH", str(tmp_path / "does_not_exist.db"))
    monkeypatch.setenv("CTI_OBSERVATION_SINK", str(tmp_path / "out.ndjson"))
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))

    exit_code = main()

    assert exit_code == 1
    error_output = capsys.readouterr().err
    assert "No database found" in error_output


def test_main_returns_one_with_a_clear_message_when_the_db_is_a_symlink(
    tmp_path: Path, flod_db_path: Path, monkeypatch, capsys
):
    symlinked_db = tmp_path / "symlinked.db"
    symlinked_db.symlink_to(flod_db_path)
    monkeypatch.setenv("CTI_FLOD_DB_PATH", str(symlinked_db))
    monkeypatch.setenv("CTI_OBSERVATION_SINK", str(tmp_path / "out.ndjson"))
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))

    exit_code = main()

    assert exit_code == 1
    error_output = capsys.readouterr().err
    assert "symlink" in error_output


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permission checks")
def test_main_returns_one_with_a_clear_message_when_the_db_is_unreadable(
    tmp_path: Path, flod_db_path: Path, monkeypatch, capsys
):
    flod_db_path.chmod(0o000)
    try:
        monkeypatch.setenv("CTI_FLOD_DB_PATH", str(flod_db_path))
        monkeypatch.setenv("CTI_OBSERVATION_SINK", str(tmp_path / "out.ndjson"))
        monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))

        exit_code = main()

        assert exit_code == 1
        error_output = capsys.readouterr().err
        assert "not readable" in error_output
    finally:
        flod_db_path.chmod(0o600)
