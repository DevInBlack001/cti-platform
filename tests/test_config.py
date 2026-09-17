from __future__ import annotations

from pathlib import Path

import pytest

from collection.config import (
    ConfigNotFoundError,
    ensure_private_directory,
    resolve_allow_insecure_tls,
    resolve_flod_db_path,
    resolve_key_dir,
    resolve_opencti_token,
    resolve_opencti_url,
    resolve_sink_path,
    resolve_wazuh_api_password,
    resolve_wazuh_api_url,
    resolve_wazuh_api_user,
    resolve_wazuh_indexer_password,
    resolve_wazuh_indexer_url,
    resolve_wazuh_indexer_user,
    resolve_wazuh_min_rule_level,
    resolve_wazuh_state_path,
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


def test_opencti_url_raises_clearly_when_unset(monkeypatch):
    monkeypatch.delenv("CTI_OPENCTI_URL", raising=False)

    with pytest.raises(ConfigNotFoundError):
        resolve_opencti_url()


def test_opencti_url_env_override_wins(monkeypatch):
    monkeypatch.setenv("CTI_OPENCTI_URL", "http://localhost:8080/graphql")

    assert resolve_opencti_url() == "http://localhost:8080/graphql"


def test_opencti_token_raises_clearly_when_unset(monkeypatch):
    monkeypatch.delenv("CTI_OPENCTI_TOKEN", raising=False)

    with pytest.raises(ConfigNotFoundError):
        resolve_opencti_token()


def test_opencti_token_env_override_wins(monkeypatch):
    monkeypatch.setenv("CTI_OPENCTI_TOKEN", "a-real-token")

    assert resolve_opencti_token() == "a-real-token"


def test_wazuh_indexer_url_raises_clearly_when_unset(monkeypatch):
    monkeypatch.delenv("CTI_WAZUH_INDEXER_URL", raising=False)

    with pytest.raises(ConfigNotFoundError):
        resolve_wazuh_indexer_url()


def test_wazuh_indexer_url_env_override_wins(monkeypatch):
    monkeypatch.setenv("CTI_WAZUH_INDEXER_URL", "https://10.0.0.4:9200")

    assert resolve_wazuh_indexer_url() == "https://10.0.0.4:9200"


def test_wazuh_indexer_user_and_password_env_override_wins(monkeypatch):
    monkeypatch.setenv("CTI_WAZUH_INDEXER_USER", "admin")
    monkeypatch.setenv("CTI_WAZUH_INDEXER_PASSWORD", "a-real-password")

    assert resolve_wazuh_indexer_user() == "admin"
    assert resolve_wazuh_indexer_password() == "a-real-password"


def test_wazuh_indexer_user_raises_clearly_when_unset(monkeypatch):
    monkeypatch.delenv("CTI_WAZUH_INDEXER_USER", raising=False)

    with pytest.raises(ConfigNotFoundError):
        resolve_wazuh_indexer_user()


def test_wazuh_api_url_and_credentials_env_override_wins(monkeypatch):
    monkeypatch.setenv("CTI_WAZUH_API_URL", "https://10.0.0.4:55000")
    monkeypatch.setenv("CTI_WAZUH_API_USER", "wazuh")
    monkeypatch.setenv("CTI_WAZUH_API_PASSWORD", "a-real-password")

    assert resolve_wazuh_api_url() == "https://10.0.0.4:55000"
    assert resolve_wazuh_api_user() == "wazuh"
    assert resolve_wazuh_api_password() == "a-real-password"


def test_wazuh_api_url_raises_clearly_when_unset(monkeypatch):
    monkeypatch.delenv("CTI_WAZUH_API_URL", raising=False)

    with pytest.raises(ConfigNotFoundError):
        resolve_wazuh_api_url()


def test_wazuh_min_rule_level_env_override_wins(monkeypatch):
    monkeypatch.setenv("CTI_WAZUH_MIN_RULE_LEVEL", "12")

    assert resolve_wazuh_min_rule_level() == 12


def test_wazuh_min_rule_level_has_a_sensible_default(monkeypatch):
    monkeypatch.delenv("CTI_WAZUH_MIN_RULE_LEVEL", raising=False)

    assert resolve_wazuh_min_rule_level() == 10


def test_wazuh_state_path_env_override_wins(monkeypatch, tmp_path):
    custom = tmp_path / "custom-state.json"
    monkeypatch.setenv("CTI_WAZUH_STATE_PATH", str(custom))

    resolved = resolve_wazuh_state_path()

    assert resolved.value == custom


def test_wazuh_state_path_has_a_sensible_default(monkeypatch):
    monkeypatch.delenv("CTI_WAZUH_STATE_PATH", raising=False)

    resolved = resolve_wazuh_state_path()

    assert resolved.value == (
        Path.home() / ".local" / "share" / "cti-platform" / "wazuh-state.json"
    )


def test_allow_insecure_tls_defaults_to_false(monkeypatch):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)

    assert resolve_allow_insecure_tls() is False


def test_allow_insecure_tls_true_when_explicitly_set(monkeypatch):
    monkeypatch.setenv("CTI_ALLOW_INSECURE_TLS", "true")

    assert resolve_allow_insecure_tls() is True


def test_allow_insecure_tls_warns_when_enabled(monkeypatch):
    monkeypatch.setenv("CTI_ALLOW_INSECURE_TLS", "true")

    with pytest.warns(RuntimeWarning, match="CTI_ALLOW_INSECURE_TLS"):
        resolve_allow_insecure_tls()


def test_allow_insecure_tls_does_not_warn_when_disabled(monkeypatch, recwarn):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)

    resolve_allow_insecure_tls()

    assert len(recwarn) == 0


def test_ensure_private_directory_creates_it_at_0o700(tmp_path: Path):
    target = tmp_path / "nested" / "keys"

    ensure_private_directory(target)

    assert target.is_dir()
    assert (target.stat().st_mode & 0o777) == 0o700


def test_ensure_private_directory_rejects_a_symlink(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    symlinked = tmp_path / "planted"
    symlinked.symlink_to(real_dir)

    with pytest.raises(RuntimeError):
        ensure_private_directory(symlinked)


def test_ensure_private_directory_resets_looser_permissions(tmp_path: Path):
    target = tmp_path / "already-there"
    target.mkdir(mode=0o755)

    ensure_private_directory(target)

    assert (target.stat().st_mode & 0o777) == 0o700


def test_ensure_private_directory_rejects_a_symlinked_ancestor(tmp_path: Path):
    """A symlink planted one level above the leaf still needs to be
    caught: mkdir's own parents=True would otherwise build the rest of
    the tree on top of it without any check ever looking at that
    intermediate directory."""
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    planted_parent = tmp_path / "planted-parent"
    planted_parent.symlink_to(real_parent)
    target = planted_parent / "keys"

    with pytest.raises(RuntimeError):
        ensure_private_directory(target)
