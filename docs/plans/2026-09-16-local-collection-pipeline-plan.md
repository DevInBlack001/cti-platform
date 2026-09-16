# Local Collection and Intelligence Extraction Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a raw FLOD detection row into a signed Threat Observation, written to a local file, proving the raw-signal-to-signed-observation path works end to end with no OpenCTI or federation dependency yet.

**Architecture:** A small `collection/` Python package: a generic `SourceConnector` interface with one real implementation (`sources/flod.py`, reading a FLOD-shaped SQLite database), a `ThreatObservation` schema with Ed25519 signing, an extractor that ties a connector to a signed NDJSON sink, and a `config.py` module that is the single place every path or setting gets resolved (environment variable first, then a documented candidate location, then a plain "not found" error).

**Tech Stack:** Python 3, the `cryptography` library for Ed25519 signing, `pytest` for tests, stdlib `sqlite3`/`json`/`pathlib` for everything else. No web framework, no network library: nothing in this component talks over a network.

**Spec:** `docs/specs/2026-09-16-local-collection-pipeline-design.md`

## Global Constraints

- No filesystem path is ever hardcoded in application code. Every path goes through `collection/config.py`: environment variable first, then a documented candidate, then a clear "not found" error. (Spec: Configuration and path resolution.)
- No network code anywhere in this component. (Spec: Security.)
- The FLOD database is opened read-only, checked for being a symlink before opening, and its rows are read one at a time via a cursor, never loaded fully into memory. (Spec: Security.)
- "Database not found" and "database found but not readable" are two different, specifically named exceptions (`FileNotFoundError`, `PermissionError`), not one generic failure. (Spec: Security.)
- Ed25519 signing uses the `cryptography` library, nothing hand-rolled. (Spec: Security.)
- No comment, docstring, or line of prose states a choice by contrasting it against a rejected alternative ("X, not Y"; "Y instead of Z"; "Z rather than X"). State the positive reason on its own merits. No em dashes anywhere, including inside strings.
- Git commit messages do not include `Co-Authored-By` or `Claude-Session` trailers. This is a standing global preference, confirmed multiple times this session, and overrides any other instruction on this point.
- Every shell script (`scripts/install.sh`, `scripts/uninstall.sh`, `scripts/update.sh`) follows FLOD's own convention: a banner header comment, `set -euo pipefail`, and colored `info`/`success`/`warn`/`error` helper functions, scaled down to what this component actually needs (no systemd service, since this is not a long-running process).
- Test-driven: for every task with a testable behavior, the failing test is written and run before the implementation, per superpowers:test-driven-development.

---

## Task 1: Package scaffolding and the source connector interface

**Files:**
- Create: `collection/__init__.py`
- Create: `collection/sources/__init__.py`
- Create: `collection/sources/base.py`
- Create: `conftest.py` (repo root)
- Test: `tests/test_source_base.py`

**Interfaces:**
- Produces: `RawSignal` dataclass (fields: `observed_at: float`, `source_address: str`, `indicator_type: str`, `source_verdict: str`, `evidence: dict`) and `SourceConnector` Protocol (`iter_signals(self) -> Iterator[RawSignal]`), both importable as `from collection.sources.base import RawSignal, SourceConnector`.

- [ ] **Step 1: Create the package directories and empty `__init__.py` files**

```bash
mkdir -p collection/sources tests
touch collection/__init__.py collection/sources/__init__.py
```

- [ ] **Step 2: Create the repo-root `conftest.py` so `collection` is importable from tests**

```python
"""Ensures the repo root is on sys.path so `collection` imports cleanly
from any test file, regardless of pytest's own rootdir detection."""
```

Save this as `conftest.py` at the repo root (not inside `tests/`). The
docstring alone is enough: pytest adds the directory containing every
conftest.py it discovers to `sys.path`, which is what makes
`from collection...` imports work during test collection.

- [ ] **Step 3: Write the failing test**

```python
# tests/test_source_base.py
from __future__ import annotations

from typing import Iterator

from collection.sources.base import RawSignal, SourceConnector


def test_raw_signal_holds_its_fields():
    signal = RawSignal(
        observed_at=1_700_000_000.0,
        source_address="10.0.0.6",
        indicator_type="ddos-flood",
        source_verdict="DDoS",
        evidence={"rate": 950.0},
    )
    assert signal.source_address == "10.0.0.6"
    assert signal.evidence["rate"] == 950.0


class _DummyConnector:
    def iter_signals(self) -> Iterator[RawSignal]:
        yield RawSignal(
            observed_at=1.0,
            source_address="1.2.3.4",
            indicator_type="ddos-flood",
            source_verdict="DDoS",
            evidence={},
        )


def test_a_connector_implementing_the_protocol_is_iterable():
    connector: SourceConnector = _DummyConnector()
    signals = list(connector.iter_signals())
    assert len(signals) == 1
    assert signals[0].source_address == "1.2.3.4"
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `pytest tests/test_source_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sources.base'`

- [ ] **Step 5: Write `collection/sources/base.py`**

```python
"""The interface every threat data source implements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Protocol


@dataclass(frozen=True)
class RawSignal:
    observed_at: float
    source_address: str
    indicator_type: str
    source_verdict: str
    evidence: dict = field(default_factory=dict)


class SourceConnector(Protocol):
    def iter_signals(self) -> Iterator[RawSignal]:
        ...
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `pytest tests/test_source_base.py -v`
Expected: PASS (2 tests)

- [ ] **Step 7: Commit**

```bash
git add collection/__init__.py collection/sources/__init__.py collection/sources/base.py conftest.py tests/test_source_base.py
git commit -m "feat: add the source connector interface"
```

---

## Task 2: Configuration and path resolution

**Files:**
- Create: `collection/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `ConfigNotFoundError` exception; `ResolvedValue` dataclass (fields: `value: Path`, `source: str`); `resolve_flod_db_path() -> ResolvedValue` (raises `ConfigNotFoundError` if nothing found); `resolve_sink_path() -> ResolvedValue`; `resolve_key_dir() -> ResolvedValue`. All importable as `from collection.config import ConfigNotFoundError, ResolvedValue, resolve_flod_db_path, resolve_sink_path, resolve_key_dir`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_config.py
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.config'`

- [ ] **Step 3: Write `collection/config.py`**

```python
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add collection/config.py tests/test_config.py
git commit -m "feat: add environment-first path resolution"
```

---

## Task 3: Signing keys

**Files:**
- Create: `collection/keys.py`
- Create: `requirements.txt` (repo root)
- Test: `tests/test_keys.py`

**Interfaces:**
- Consumes: `resolve_key_dir` from `collection.config` (Task 2).
- Produces: `load_or_create_node_key(key_dir: Path | None = None) -> Ed25519PrivateKey`; `node_fingerprint(private_key: Ed25519PrivateKey) -> str`. Both importable as `from collection.keys import load_or_create_node_key, node_fingerprint`.

- [ ] **Step 1: Add the runtime dependency**

Create `requirements.txt` at the repo root:

```
cryptography==50.0.1
```

- [ ] **Step 2: Install it**

```bash
pip install -r requirements.txt
```

- [ ] **Step 3: Write the failing tests**

```python
# tests/test_keys.py
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
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `pytest tests/test_keys.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.keys'`

- [ ] **Step 5: Write `collection/keys.py`**

```python
"""Generates and loads this node's Ed25519 signing key pair."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collection.config import resolve_key_dir

PRIVATE_KEY_FILENAME = "node_private_key.pem"
PUBLIC_KEY_FILENAME = "node_public_key.pem"


def load_or_create_node_key(key_dir: Path | None = None) -> Ed25519PrivateKey:
    """Returns this node's private key, generating one on first use."""
    directory = key_dir if key_dir is not None else resolve_key_dir().value
    directory.mkdir(parents=True, exist_ok=True)
    private_key_path = directory / PRIVATE_KEY_FILENAME

    if private_key_path.exists():
        stored_bytes = private_key_path.read_bytes()
        return serialization.load_pem_private_key(stored_bytes, password=None)

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_path.write_bytes(private_bytes)
    private_key_path.chmod(0o600)

    public_key_path = directory / PUBLIC_KEY_FILENAME
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path.write_bytes(public_bytes)

    return private_key


def node_fingerprint(private_key: Ed25519PrivateKey) -> str:
    """A short, stable identifier for this node, derived from its public key."""
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()[:16]
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_keys.py -v`
Expected: PASS (4 tests)

- [ ] **Step 7: Commit**

```bash
git add collection/keys.py requirements.txt tests/test_keys.py
git commit -m "feat: add node signing key generation and reuse"
```

---

## Task 4: Threat Observation schema and signing

**Files:**
- Create: `collection/schema.py`
- Test: `tests/test_schema.py`

**Interfaces:**
- Consumes: `RawSignal` from `collection.sources.base` (Task 1).
- Produces: `ThreatObservation` frozen dataclass (fields: `observation_id: str`, `reporting_node_id: str`, `observed_at: str`, `indicator_type: str`, `indicator_value: str`, `source_verdict: str`, `evidence: dict`, `severity: str | None`, `confidence: float | None`, `signature: str`), with a `.to_json() -> str` method; `build_and_sign(signal: RawSignal, reporting_node_id: str, private_key: Ed25519PrivateKey) -> ThreatObservation`; `verify(observation: ThreatObservation, public_key: Ed25519PublicKey) -> bool`. All importable as `from collection.schema import ThreatObservation, build_and_sign, verify`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_schema.py
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.schema'`

- [ ] **Step 3: Write `collection/schema.py`**

```python
"""The Threat Observation format this project shares between nodes, and its signing."""

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
        return json.dumps(asdict(self), sort_keys=True)


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
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def build_and_sign(
    signal: RawSignal, reporting_node_id: str, private_key: Ed25519PrivateKey
) -> ThreatObservation:
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_schema.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add collection/schema.py tests/test_schema.py
git commit -m "feat: add the Threat Observation schema and Ed25519 signing"
```

---

## Task 5: FLOD connector, against a fixture built from FLOD's real schema

**Files:**
- Create: `collection/sources/flod.py`
- Create: `tests/conftest.py`
- Test: `tests/test_flod_connector.py`

**Interfaces:**
- Consumes: `RawSignal` from `collection.sources.base` (Task 1).
- Produces: `FlodConnector` class (constructor `FlodConnector(db_path: Path)`, method `iter_signals(self) -> Iterator[RawSignal]`); `SymlinkDatabaseError` exception. Importable as `from collection.sources.flod import FlodConnector, SymlinkDatabaseError`. `iter_signals` also raises the stdlib `FileNotFoundError` and `PermissionError` directly (no custom wrapper types for those two, per the spec's Security section).

- [ ] **Step 1: Write the fixture builder**

```python
# tests/conftest.py
"""Shared pytest fixtures: a FLOD-shaped database for the connector tests.

The logs table below is copied verbatim from FLOD's own
stage2/schema.py (ddos-reduction-system), not assumed from its docs.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

FLOD_LOGS_TABLE = """
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT,
        proto TEXT,
        rate REAL,
        entropy REAL,
        classification TEXT NOT NULL
    )"""

# (timestamp, src_ip, dst_ip, proto, rate, entropy, classification)
FIXTURE_ROWS = [
    (1_700_000_000.0, "10.0.0.5", "10.0.0.1", "TCP", 12.5, 3.9, "Normal"),
    (1_700_000_001.0, "10.0.0.6", "10.0.0.1", "TCP", 950.0, 0.2, "DDoS"),
    (1_700_000_002.0, "10.0.0.7", "10.0.0.1", "TCP", 420.0, 1.1, "Flash Crowd"),
    (1_700_000_003.0, "10.0.0.8", "10.0.0.1", "UDP", 200.0, 4.7, "Anomalous"),
    (1_700_000_004.0, "10.0.0.6", "10.0.0.1", "TCP", None, None, "Blocked"),
    (1_700_000_005.0, "10.0.0.6", "10.0.0.1", "TCP", None, None, "Released"),
]


@pytest.fixture
def flod_db_path(tmp_path: Path) -> Path:
    db_path = tmp_path / "stage2.db"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(FLOD_LOGS_TABLE)
        connection.executemany(
            "INSERT INTO logs "
            "(timestamp, src_ip, dst_ip, proto, rate, entropy, classification) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            FIXTURE_ROWS,
        )
        connection.commit()
    finally:
        connection.close()
    return db_path
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_flod_connector.py
from __future__ import annotations

import os
from pathlib import Path

import pytest

from collection.sources.flod import FlodConnector, SymlinkDatabaseError


def test_normal_rows_produce_no_signal(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    verdicts = [signal.source_verdict for signal in signals]
    assert "Normal" not in verdicts


def test_blocked_and_released_rows_are_skipped(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    verdicts = [signal.source_verdict for signal in signals]
    assert "Blocked" not in verdicts
    assert "Released" not in verdicts


def test_every_detection_verdict_produces_a_signal(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    verdicts = {signal.source_verdict for signal in signals}
    assert verdicts == {"DDoS", "Flash Crowd", "Anomalous"}


def test_signal_carries_evidence_from_the_row(flod_db_path: Path):
    connector = FlodConnector(flod_db_path)

    signals = list(connector.iter_signals())

    ddos_signal = next(s for s in signals if s.source_verdict == "DDoS")
    assert ddos_signal.source_address == "10.0.0.6"
    assert ddos_signal.evidence["rate"] == 950.0
    assert ddos_signal.evidence["entropy"] == 0.2
    assert ddos_signal.evidence["proto"] == "TCP"


def test_symlinked_database_path_is_rejected(tmp_path: Path, flod_db_path: Path):
    symlink_path = tmp_path / "symlinked.db"
    symlink_path.symlink_to(flod_db_path)
    connector = FlodConnector(symlink_path)

    with pytest.raises(SymlinkDatabaseError):
        list(connector.iter_signals())


def test_missing_database_raises_file_not_found(tmp_path: Path):
    connector = FlodConnector(tmp_path / "does_not_exist.db")

    with pytest.raises(FileNotFoundError):
        list(connector.iter_signals())


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permission checks")
def test_unreadable_database_raises_permission_error(flod_db_path: Path):
    flod_db_path.chmod(0o000)
    try:
        connector = FlodConnector(flod_db_path)
        with pytest.raises(PermissionError):
            list(connector.iter_signals())
    finally:
        flod_db_path.chmod(0o600)
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `pytest tests/test_flod_connector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sources.flod'`

- [ ] **Step 4: Write `collection/sources/flod.py`**

```python
"""Reads a FLOD-shaped SQLite database and yields RawSignals.

Table and column layout taken from FLOD's own stage2/schema.py.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Iterator

from collection.sources.base import RawSignal

DETECTION_VERDICTS = {"Flash Crowd", "DDoS", "Anomalous"}


class SymlinkDatabaseError(RuntimeError):
    """Raised when the configured database path is a symlink."""


class FlodConnector:
    def __init__(self, db_path: Path):
        self._db_path = db_path

    def iter_signals(self) -> Iterator[RawSignal]:
        self._check_path_is_safe_to_open()

        connection = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
        try:
            cursor = connection.execute(
                "SELECT timestamp, src_ip, proto, rate, entropy, classification "
                "FROM logs"
            )
            for timestamp, src_ip, proto, rate, entropy, classification in cursor:
                if classification not in DETECTION_VERDICTS:
                    continue
                yield RawSignal(
                    observed_at=timestamp,
                    source_address=src_ip,
                    indicator_type="ddos-flood",
                    source_verdict=classification,
                    evidence={"rate": rate, "entropy": entropy, "proto": proto},
                )
        finally:
            connection.close()

    def _check_path_is_safe_to_open(self) -> None:
        if self._db_path.is_symlink():
            raise SymlinkDatabaseError(
                f"{self._db_path} is a symlink, refusing to open it"
            )
        if not self._db_path.exists():
            raise FileNotFoundError(f"No database found at {self._db_path}")
        if not os.access(self._db_path, os.R_OK):
            raise PermissionError(
                f"{self._db_path} exists but is not readable by this user"
            )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_flod_connector.py -v`
Expected: PASS (6 passed, or 7 passed if not running as root)

- [ ] **Step 6: Commit**

```bash
git add collection/sources/flod.py tests/conftest.py tests/test_flod_connector.py
git commit -m "feat: add the FLOD source connector"
```

---

## Task 6: Extractor

**Files:**
- Create: `collection/extractor.py`
- Test: `tests/test_extractor.py`

**Interfaces:**
- Consumes: `SourceConnector` from `collection.sources.base` (Task 1); `resolve_sink_path` from `collection.config` (Task 2); `load_or_create_node_key`, `node_fingerprint` from `collection.keys` (Task 3); `build_and_sign` from `collection.schema` (Task 4).
- Produces: `run(connector: SourceConnector, sink_path: Path | None = None) -> int` (returns the count of observations written). Importable as `from collection.extractor import run`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_extractor.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from collection.extractor import run
from collection.sources.base import RawSignal


class _StubConnector:
    def __init__(self, signals: list[RawSignal]):
        self._signals = signals

    def iter_signals(self) -> Iterator[RawSignal]:
        yield from self._signals


def _signal(address: str) -> RawSignal:
    return RawSignal(
        observed_at=1_700_000_001.0,
        source_address=address,
        indicator_type="ddos-flood",
        source_verdict="DDoS",
        evidence={"rate": 950.0, "entropy": 0.2, "proto": "TCP"},
    )


def test_run_writes_one_line_per_signal(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"
    connector = _StubConnector([_signal("10.0.0.6"), _signal("10.0.0.7")])

    written = run(connector, sink_path=sink_path)

    assert written == 2
    lines = sink_path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["indicator_value"] == "10.0.0.6"


def test_run_signs_each_observation_with_the_node_key(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"
    connector = _StubConnector([_signal("10.0.0.6")])

    run(connector, sink_path=sink_path)

    written = json.loads(sink_path.read_text().splitlines()[0])
    assert len(written["signature"]) == 128  # hex-encoded 64-byte Ed25519 signature


def test_run_appends_across_two_separate_calls(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "observations.ndjson"

    run(_StubConnector([_signal("10.0.0.6")]), sink_path=sink_path)
    run(_StubConnector([_signal("10.0.0.7")]), sink_path=sink_path)

    lines = sink_path.read_text().splitlines()
    assert len(lines) == 2
    addresses = [json.loads(line)["indicator_value"] for line in lines]
    assert addresses == ["10.0.0.6", "10.0.0.7"]


def test_run_creates_the_sinks_parent_directory(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTI_KEY_DIR", str(tmp_path / "keys"))
    sink_path = tmp_path / "nested" / "dir" / "observations.ndjson"

    run(_StubConnector([_signal("10.0.0.6")]), sink_path=sink_path)

    assert sink_path.exists()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_extractor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.extractor'`

- [ ] **Step 3: Write `collection/extractor.py`**

```python
"""Ties a source connector to the Threat Observation sink."""

from __future__ import annotations

from pathlib import Path

from collection.config import resolve_sink_path
from collection.keys import load_or_create_node_key, node_fingerprint
from collection.schema import build_and_sign
from collection.sources.base import SourceConnector


def run(connector: SourceConnector, sink_path: Path | None = None) -> int:
    """Processes every signal the connector yields, once. Returns the count written."""
    destination = sink_path if sink_path is not None else resolve_sink_path().value
    destination.parent.mkdir(parents=True, exist_ok=True)

    private_key = load_or_create_node_key()
    reporting_node_id = node_fingerprint(private_key)

    written = 0
    with destination.open("a", encoding="utf-8") as sink_file:
        for signal in connector.iter_signals():
            observation = build_and_sign(signal, reporting_node_id, private_key)
            sink_file.write(observation.to_json() + "\n")
            written += 1
    return written
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_extractor.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add collection/extractor.py tests/test_extractor.py
git commit -m "feat: add the extractor tying connector, signing, and sink together"
```

---

## Task 7: A runnable entry point

**Files:**
- Create: `collection/__main__.py`
- Test: `tests/test_main.py`

**Interfaces:**
- Consumes: `ConfigNotFoundError`, `resolve_flod_db_path` from `collection.config` (Task 2); `run` from `collection.extractor` (Task 6); `FlodConnector` from `collection.sources.flod` (Task 5).
- Produces: `main() -> int`, importable as `from collection.__main__ import main`, and runnable as `python -m collection`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_main.py
from __future__ import annotations

from pathlib import Path

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.__main__'`

- [ ] **Step 3: Write `collection/__main__.py`**

```python
"""Runs one pass: FLOD's database in, signed Threat Observations out."""

from __future__ import annotations

import sys

from collection.config import ConfigNotFoundError, resolve_flod_db_path
from collection.extractor import run
from collection.sources.flod import FlodConnector


def main() -> int:
    try:
        db_path = resolve_flod_db_path().value
    except ConfigNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 1

    connector = FlodConnector(db_path)
    written = run(connector)
    print(f"Wrote {written} observation(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_main.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the full test suite to confirm nothing else broke**

Run: `pytest -v`
Expected: PASS (every test from Tasks 1 through 7)

- [ ] **Step 6: Commit**

```bash
git add collection/__main__.py tests/test_main.py
git commit -m "feat: add a runnable entry point for a single collection pass"
```

---

## Task 8: Install, uninstall, and update scripts

**Files:**
- Create: `scripts/install.sh`
- Create: `scripts/uninstall.sh`
- Create: `scripts/update.sh`

**Interfaces:**
- Consumes: `requirements.txt` (Task 3); `collection.keys.load_or_create_node_key`, `collection.keys.node_fingerprint` (Task 3); `collection.config.resolve_flod_db_path`, `resolve_sink_path`, `resolve_key_dir`, `ConfigNotFoundError` (Task 2).
- Produces: nothing other tasks import; these are standalone operator-facing scripts.

- [ ] **Step 1: Write `scripts/install.sh`**

```bash
#!/usr/bin/env bash
# =============================================================================
# install.sh: Local Collection and Extraction Pipeline Installation Script
# =============================================================================
#
# What this script does:
#   1. Checks for Python 3.
#   2. Creates a virtual environment at collection/.venv.
#   3. Installs the pinned dependencies from requirements.txt.
#   4. Generates this node's Ed25519 signing key pair, if one doesn't
#      already exist.
#   5. Prints the resolved paths this component will use.
#
# Usage:
#   bash scripts/install.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_ROOT/collection/.venv"

command -v python3 >/dev/null 2>&1 || error "python3 not found. Install Python 3 first."
info "Using $(python3 --version)"

if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
else
    info "Virtual environment already exists at $VENV_DIR"
fi

info "Installing dependencies from requirements.txt"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$REPO_ROOT/requirements.txt"
success "Dependencies installed"

info "Generating this node's signing key, if needed"
PYTHONPATH="$REPO_ROOT" "$VENV_DIR/bin/python" -c "
from collection.keys import load_or_create_node_key, node_fingerprint
key = load_or_create_node_key()
print('Node fingerprint:', node_fingerprint(key))
"
success "Signing key ready"

info "Resolved configuration:"
PYTHONPATH="$REPO_ROOT" "$VENV_DIR/bin/python" -c "
from collection.config import ConfigNotFoundError, resolve_flod_db_path, resolve_key_dir, resolve_sink_path
checks = [
    ('FLOD database', resolve_flod_db_path),
    ('Observation sink', resolve_sink_path),
    ('Key directory', resolve_key_dir),
]
for name, resolver in checks:
    try:
        resolved = resolver()
        print(f'  {name}: {resolved.value} ({resolved.source})')
    except ConfigNotFoundError as e:
        print(f'  {name}: not found ({e})')
"

success "Install complete"
```

- [ ] **Step 2: Make it executable and run it**

```bash
chmod +x scripts/install.sh
bash scripts/install.sh
```

Expected: prints a Python version, creates `collection/.venv`, installs
`cryptography`, prints a node fingerprint, and prints the resolved FLOD
database / sink / key directory paths (the FLOD database line will say
"not found" unless `/var/lib/flod/*.db` or `CTI_FLOD_DB_PATH` actually
exists on this machine, which is expected and not an error).

- [ ] **Step 3: Write `scripts/uninstall.sh`**

```bash
#!/usr/bin/env bash
# =============================================================================
# uninstall.sh: Local Collection and Extraction Pipeline Uninstall Script
# =============================================================================
#
# Removes collection/.venv. Leaves this node's signing key pair and any
# already-written observations in place unless --remove-keys is passed,
# since a node's signing identity is not something to delete by accident.
#
# Usage:
#   bash scripts/uninstall.sh [--remove-keys]
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_ROOT/collection/.venv"

REMOVE_KEYS=false
for arg in "$@"; do
    case "$arg" in
        --remove-keys) REMOVE_KEYS=true ;;
        *) error "Unknown option: $arg" ;;
    esac
done

if [ -d "$VENV_DIR" ]; then
    rm -rf "$VENV_DIR"
    success "Removed $VENV_DIR"
else
    info "No virtual environment found at $VENV_DIR, nothing to remove"
fi

if [ "$REMOVE_KEYS" = true ]; then
    KEY_DIR="$(PYTHONPATH="$REPO_ROOT" python3 -c "
from collection.config import resolve_key_dir
print(resolve_key_dir().value)
")"
    if [ -n "$KEY_DIR" ] && [ -d "$KEY_DIR" ]; then
        rm -rf "$KEY_DIR"
        warn "Removed $KEY_DIR. This node will generate a new identity next run."
    else
        info "No key directory found at $KEY_DIR, nothing to remove"
    fi
else
    info "Leaving the signing key and any written observations in place"
    info "Pass --remove-keys to also delete this node's signing identity"
fi

success "Uninstall complete"
```

- [ ] **Step 4: Make it executable**

```bash
chmod +x scripts/uninstall.sh
```

- [ ] **Step 5: Write `scripts/update.sh`**

```bash
#!/usr/bin/env bash
# =============================================================================
# update.sh: Local Collection and Extraction Pipeline Update Script
# =============================================================================
#
# Reinstalls dependencies from requirements.txt into the existing virtual
# environment. Does not touch keys, config, or already-written output.
#
# Usage:
#   bash scripts/update.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_ROOT/collection/.venv"

[ -d "$VENV_DIR" ] || error "No virtual environment found at $VENV_DIR. Run scripts/install.sh first."

info "Updating dependencies from requirements.txt"
"$VENV_DIR/bin/pip" install --quiet --upgrade -r "$REPO_ROOT/requirements.txt"
success "Update complete"
```

- [ ] **Step 6: Make it executable and verify the uninstall/reinstall cycle**

```bash
chmod +x scripts/update.sh
bash scripts/uninstall.sh
bash scripts/install.sh
bash scripts/uninstall.sh --remove-keys
```

Expected: the venv is removed and recreated cleanly each time; the
final `--remove-keys` run also removes the key directory it just
created and says so.

- [ ] **Step 7: Commit**

```bash
git add scripts/install.sh scripts/uninstall.sh scripts/update.sh
git commit -m "feat: add install, uninstall, and update scripts"
```

---

## Task 9: End-to-end verification against a real fixture

**Files:**
- Test: `tests/test_end_to_end.py`

**Interfaces:**
- Consumes: `flod_db_path` fixture (Task 5); `main` from `collection.__main__` (Task 7); `verify` from `collection.schema` (Task 4); `load_or_create_node_key` from `collection.keys` (Task 3).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_end_to_end.py
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
```

- [ ] **Step 2: Run the test to verify it fails or passes for the right reason**

Run: `pytest tests/test_end_to_end.py -v`
Expected: this test should PASS immediately, since every piece it
exercises already exists from Tasks 1 through 7. If it fails, the
failure points at an integration gap between two already-implemented
modules, not a missing module. Diagnose and fix that gap before
proceeding; do not add new production code speculatively.

- [ ] **Step 3: Run the entire test suite one final time**

Run: `pytest -v`
Expected: every test across all nine tasks passes.

- [ ] **Step 4: Commit**

```bash
git add tests/test_end_to_end.py
git commit -m "test: add an end-to-end verification of a full collection pass"
```

---

## Manual verification (not a task, a final check)

After Task 9, confirm the roadmap's own week 3-4 deliverable claim
("working single-node pipeline: raw signal to signed observation") is
true against real data, not just the fixture:

1. If a real FLOD database is reachable (for example, by setting
   `CTI_FLOD_DB_PATH` to a copy of one), run `python -m collection`
   directly and inspect `~/.local/share/cti-platform/observations.ndjson`
   (or wherever `CTI_OBSERVATION_SINK` points) by eye.
2. Confirm the printed "Wrote N observation(s)" count matches the
   number of `DDoS`/`Flash Crowd`/`Anomalous` rows actually in that
   database.
3. If no real FLOD database is reachable from this machine at plan
   execution time, say so explicitly. The fixture-based tests in Task 9
   cover the parts that do not need real data; this step needs it.
