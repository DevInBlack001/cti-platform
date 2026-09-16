"""Resolves every path this component needs.

Each value is resolved the same way: check its environment variable
first, then a short list of real install locations, then report plainly
that it was not found. No other module in this package reads an
environment variable or hardcodes a path directly.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from pathlib import Path


class ConfigNotFoundError(RuntimeError):
    """Raised when a value has no environment override and no candidate matched."""


@dataclass(frozen=True)
class ResolvedValue:
    value: Path
    source: str


def resolve_flod_db_path() -> ResolvedValue:
    env_value = os.environ.get("CTI_FLOD_DB_PATH")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_FLOD_DB_PATH")

    matches = sorted(glob.glob("/var/lib/flod/*.db"))
    if matches:
        return ResolvedValue(Path(matches[0]), "candidate:/var/lib/flod/*.db")

    raise ConfigNotFoundError(
        "No FLOD database found. Set CTI_FLOD_DB_PATH, or install FLOD so "
        "its database appears at /var/lib/flod/*.db."
    )


def resolve_sink_path() -> ResolvedValue:
    env_value = os.environ.get("CTI_OBSERVATION_SINK")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_OBSERVATION_SINK")

    default = Path.home() / ".local" / "share" / "cti-platform" / "observations.ndjson"
    return ResolvedValue(
        default, "candidate:~/.local/share/cti-platform/observations.ndjson"
    )


def resolve_key_dir() -> ResolvedValue:
    env_value = os.environ.get("CTI_KEY_DIR")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_KEY_DIR")

    default = Path.home() / ".local" / "share" / "cti-platform" / "keys"
    return ResolvedValue(default, "candidate:~/.local/share/cti-platform/keys/")


def _require_env(var_name: str, hint: str) -> str:
    value = os.environ.get(var_name)
    if not value:
        raise ConfigNotFoundError(f"No {hint} configured. Set {var_name}.")
    return value


def resolve_opencti_url() -> str:
    return _require_env("CTI_OPENCTI_URL", "OpenCTI GraphQL URL")


def resolve_opencti_token() -> str:
    return _require_env("CTI_OPENCTI_TOKEN", "OpenCTI API token")


def resolve_wazuh_indexer_url() -> str:
    return _require_env("CTI_WAZUH_INDEXER_URL", "Wazuh indexer URL")


def resolve_wazuh_indexer_user() -> str:
    return _require_env("CTI_WAZUH_INDEXER_USER", "Wazuh indexer username")


def resolve_wazuh_indexer_password() -> str:
    return _require_env("CTI_WAZUH_INDEXER_PASSWORD", "Wazuh indexer password")


def resolve_wazuh_api_url() -> str:
    return _require_env("CTI_WAZUH_API_URL", "Wazuh manager API URL")


def resolve_wazuh_api_user() -> str:
    return _require_env("CTI_WAZUH_API_USER", "Wazuh manager API username")


def resolve_wazuh_api_password() -> str:
    return _require_env("CTI_WAZUH_API_PASSWORD", "Wazuh manager API password")


def resolve_wazuh_min_rule_level() -> int:
    value = os.environ.get("CTI_WAZUH_MIN_RULE_LEVEL")
    return int(value) if value else 10


def resolve_wazuh_state_path() -> ResolvedValue:
    env_value = os.environ.get("CTI_WAZUH_STATE_PATH")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_WAZUH_STATE_PATH")

    default = Path.home() / ".local" / "share" / "cti-platform" / "wazuh-state.json"
    return ResolvedValue(
        default, "candidate:~/.local/share/cti-platform/wazuh-state.json"
    )


def resolve_allow_insecure_tls() -> bool:
    return os.environ.get("CTI_ALLOW_INSECURE_TLS", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
