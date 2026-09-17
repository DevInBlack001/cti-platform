"""Resolves every path this component needs.

Each value is resolved the same way: check its environment variable
first, then a short list of real install locations, then report plainly
that it was not found. No other module in this package reads an
environment variable or hardcodes a path directly.
"""

from __future__ import annotations

import glob
import os
import warnings
from dataclasses import dataclass
from pathlib import Path


class ConfigNotFoundError(RuntimeError):
    """Raised when a value has no environment override and no candidate matched."""


@dataclass(frozen=True)
class ResolvedValue:
    """Carries both the resolved path and where it came from.

    The source field indicates whether the value came from an environment
    variable, a glob pattern candidate, or a default fallback.
    """
    value: Path
    source: str


def resolve_flod_db_path() -> ResolvedValue:
    """Locates the FLOD threat intelligence database.

    Checks the CTI_FLOD_DB_PATH environment variable first, then searches
    for *.db files in /var/lib/flod/, then raises if neither succeeds.
    """
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
    """Locates the output file where signed observations are written.

    Checks the CTI_OBSERVATION_SINK environment variable, then defaults
    to ~/.local/share/cti-platform/observations.ndjson.
    """
    env_value = os.environ.get("CTI_OBSERVATION_SINK")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_OBSERVATION_SINK")

    default = Path.home() / ".local" / "share" / "cti-platform" / "observations.ndjson"
    return ResolvedValue(
        default, "candidate:~/.local/share/cti-platform/observations.ndjson"
    )


def resolve_key_dir() -> ResolvedValue:
    """Locates the directory where the node's Ed25519 signing key is stored.

    Checks the CTI_KEY_DIR environment variable, then defaults to
    ~/.local/share/cti-platform/keys/.
    """
    env_value = os.environ.get("CTI_KEY_DIR")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_KEY_DIR")

    default = Path.home() / ".local" / "share" / "cti-platform" / "keys"
    return ResolvedValue(default, "candidate:~/.local/share/cti-platform/keys/")


def _require_env(var_name: str, hint: str) -> str:
    """Retrieves a required environment variable, raising if it is not set.

    Used by functions that have no fallback defaults and must have the
    variable configured to proceed.
    """
    value = os.environ.get(var_name)
    if not value:
        raise ConfigNotFoundError(f"No {hint} configured. Set {var_name}.")
    return value


def resolve_opencti_url() -> str:
    """Returns the OpenCTI GraphQL endpoint URL from CTI_OPENCTI_URL."""
    return _require_env("CTI_OPENCTI_URL", "OpenCTI GraphQL URL")


def resolve_opencti_token() -> str:
    """Returns the OpenCTI API token from CTI_OPENCTI_TOKEN."""
    return _require_env("CTI_OPENCTI_TOKEN", "OpenCTI API token")


def resolve_wazuh_indexer_url() -> str:
    """Returns the Wazuh indexer's own URL from CTI_WAZUH_INDEXER_URL."""
    return _require_env("CTI_WAZUH_INDEXER_URL", "Wazuh indexer URL")


def resolve_wazuh_indexer_user() -> str:
    """Returns the Wazuh indexer username from CTI_WAZUH_INDEXER_USER."""
    return _require_env("CTI_WAZUH_INDEXER_USER", "Wazuh indexer username")


def resolve_wazuh_indexer_password() -> str:
    """Returns the Wazuh indexer password from CTI_WAZUH_INDEXER_PASSWORD."""
    return _require_env("CTI_WAZUH_INDEXER_PASSWORD", "Wazuh indexer password")


def resolve_wazuh_api_url() -> str:
    """Returns the Wazuh manager API URL from CTI_WAZUH_API_URL."""
    return _require_env("CTI_WAZUH_API_URL", "Wazuh manager API URL")


def resolve_wazuh_api_user() -> str:
    """Returns the Wazuh manager API username from CTI_WAZUH_API_USER."""
    return _require_env("CTI_WAZUH_API_USER", "Wazuh manager API username")


def resolve_wazuh_api_password() -> str:
    """Returns the Wazuh manager API password from CTI_WAZUH_API_PASSWORD."""
    return _require_env("CTI_WAZUH_API_PASSWORD", "Wazuh manager API password")


def resolve_wazuh_min_rule_level() -> int:
    """Returns the minimum Wazuh rule severity level to collect.

    Reads from CTI_WAZUH_MIN_RULE_LEVEL, defaults to 10.
    """
    value = os.environ.get("CTI_WAZUH_MIN_RULE_LEVEL")
    return int(value) if value else 10


def resolve_wazuh_state_path() -> ResolvedValue:
    """Locates the file where the high water mark for Wazuh queries is stored.

    Checks the CTI_WAZUH_STATE_PATH environment variable, then defaults to
    ~/.local/share/cti-platform/wazuh-state.json.
    """
    env_value = os.environ.get("CTI_WAZUH_STATE_PATH")
    if env_value:
        return ResolvedValue(Path(env_value), "env:CTI_WAZUH_STATE_PATH")

    default = Path.home() / ".local" / "share" / "cti-platform" / "wazuh-state.json"
    return ResolvedValue(
        default, "candidate:~/.local/share/cti-platform/wazuh-state.json"
    )


def resolve_allow_insecure_tls() -> bool:
    """Reads CTI_ALLOW_INSECURE_TLS and returns True if set to 1, true, or yes.

    Used to disable TLS verification for development and testing only.
    Every call that turns this on emits a runtime warning, so leaving
    it set somewhere it was only meant to be temporary stays visible
    on every run that reads it.
    """
    allowed = os.environ.get("CTI_ALLOW_INSECURE_TLS", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    if allowed:
        warnings.warn(
            "CTI_ALLOW_INSECURE_TLS is set: TLS certificate verification "
            "is disabled for this connection. Meant for development "
            "against a self-signed test server only.",
            RuntimeWarning,
            stacklevel=2,
        )
    return allowed


def _nearest_existing_ancestor(path: Path) -> Path:
    """Walks up from path until it finds a directory that already exists."""
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            return current
        current = parent
    return current


def ensure_private_directory(directory: Path) -> None:
    """Creates a directory for private, node-owned data (signing keys,
    observation state), safely.

    An environment variable like CTI_KEY_DIR can point anywhere, so
    this verifies the directory on every call that uses it. Before
    creating anything, it checks the nearest ancestor that already
    exists: a symlink or wrong ownership there would let mkdir's own
    parents=True flag build the rest of the tree on top of something
    an attacker planted, one level or more above the leaf this
    function ultimately checks directly. It refuses a leaf that turned
    out to be a symlink (which could redirect writes somewhere
    unexpected) or one owned by a different user (which could mean
    another account on a shared machine planted it first), and it
    always resets permissions to 0o700, closing the gap left by
    mkdir's own exist_ok flag, which silently accepts whatever
    permissions a pre-existing directory already had. This checks the
    leaf and its nearest existing ancestor; it does not walk the whole
    chain back to the filesystem root, since several of those higher
    directories (a home directory, a shared parent) are legitimately
    owned by someone else or a system account.
    """
    anchor = _nearest_existing_ancestor(directory)
    if anchor.is_symlink():
        raise RuntimeError(f"{anchor} is a symlink, refusing to build on it")
    if anchor.exists() and anchor.stat().st_uid != os.getuid():
        raise RuntimeError(
            f"{anchor} is not owned by the current user, refusing to build on it"
        )

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink():
        raise RuntimeError(f"{directory} is a symlink, refusing to use it")
    if not directory.is_dir():
        raise RuntimeError(f"{directory} exists and is not a directory")
    if directory.stat().st_uid != os.getuid():
        raise RuntimeError(
            f"{directory} is not owned by the current user, refusing to use it"
        )
    os.chmod(directory, 0o700)
