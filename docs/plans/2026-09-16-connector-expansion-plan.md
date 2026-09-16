# Connector Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `SinkConnector` interface, an OpenCTI sink, a Wazuh source connector, and a Wazuh sink (active-response) to the already-built `collection/` package.

**Architecture:** Four new modules on top of the existing package: `collection/sinks/base.py` (the sink interface), `collection/sinks/opencti.py`, `collection/sources/wazuh.py`, `collection/sinks/wazuh.py`. `collection/config.py` grows nine new resolver functions, one per credential/URL/setting these need, following its existing env-first pattern exactly.

**Tech Stack:** Python 3, `requests` (new dependency, this package's first network code), `cryptography` (already present), `pytest`.

**Spec:** `docs/specs/2026-09-16-connector-expansion-design.md`

## Global Constraints

- No filesystem path, URL, or credential is ever hardcoded in application code. Every one goes through `collection/config.py`. (Spec: Configuration.)
- No comment, docstring, or line of prose states a choice by contrasting it against a rejected alternative ("X, not Y"; "Y instead of Z"; "Z rather than X"). State the positive reason on its own merits. No em dashes anywhere, including inside strings.
- Git commit messages do not include `Co-Authored-By` or `Claude-Session` trailers. Standing global preference, overrides any other instruction on this point.
- TLS verification defaults on for every HTTPS call this component makes; it turns off only when `CTI_ALLOW_INSECURE_TLS` is explicitly set, never silently.
- Credentials are read from environment variables at call time and held only in memory. Never written to a file, never logged, never included in an exception message's text.
- Destination-side fields (a target IP, hostname, or similar) never reach a `RawSignal`'s `evidence` or a `ThreatObservation` sent to a sink. Only source/attacker-side and attack-characteristic fields are shareable.
- Sensitive local file reads (the Wazuh state file) are checked for being a symlink before opening, and opened via `os.open` with `O_NOFOLLOW`, matching the pattern already established in `collection/keys.py`.
- Bounded reads everywhere: no unbounded HTTP pagination (a fixed page size, looped only while a page is full), no unbounded local file read.
- Test-driven: for every task with a testable behavior, the failing test is written and run before the implementation, per superpowers:test-driven-development.
- This plan's real external systems were verified while writing it, not guessed: OpenCTI's `indicatorAdd` mutation and `IndicatorAddInput` fields come from the real `opencti-platform/opencti` repository at tag `7.260914.0` (the exact version this project's `deploy/.env.example` pins), file `opencti-platform/opencti-graphql/src/modules/indicator/indicator.graphql`. Wazuh's `/active-response` endpoint and `ActiveResponseBody` shape come from the real `wazuh/wazuh` repository at tag `v4.14.7`, file `api/api/spec/spec.yaml`. The active-response command name `firewall-drop600` was confirmed against the real homelab server's own `/var/ossec/etc/shared/ar.conf`. Real Wazuh alert shapes (an SCA compliance alert and three SSH `rule.level: 10` alerts) were pulled from the real indexer and are used as this plan's test fixtures.

---

## Task 1: Sink connector interface

**Files:**
- Create: `collection/sinks/__init__.py`
- Create: `collection/sinks/base.py`
- Test: `tests/test_sink_base.py`

**Interfaces:**
- Consumes: `ThreatObservation` from `collection.schema` (already built).
- Produces: `SinkConnector` Protocol (`send(self, observation: ThreatObservation) -> None`), importable as `from collection.sinks.base import SinkConnector`.

- [ ] **Step 1: Create the package directory and empty `__init__.py`**

```bash
mkdir -p collection/sinks
touch collection/sinks/__init__.py
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_sink_base.py
from __future__ import annotations

from collection.schema import ThreatObservation
from collection.sinks.base import SinkConnector


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="10.0.0.6",
        source_verdict="DDoS",
        evidence={"rate": 950.0},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


class _RecordingSink:
    def __init__(self) -> None:
        self.received: list[ThreatObservation] = []

    def send(self, observation: ThreatObservation) -> None:
        self.received.append(observation)


def test_a_sink_implementing_the_protocol_receives_the_observation():
    sink: SinkConnector = _RecordingSink()
    observation = _sample_observation()

    sink.send(observation)

    assert sink.received == [observation]
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `pytest tests/test_sink_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sinks.base'`

- [ ] **Step 4: Write `collection/sinks/base.py`**

```python
"""The interface every believed-observation destination implements."""

from __future__ import annotations

from typing import Protocol

from collection.schema import ThreatObservation


class SinkConnector(Protocol):
    def send(self, observation: ThreatObservation) -> None: ...
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/test_sink_base.py -v`
Expected: PASS (1 test)

- [ ] **Step 6: Commit**

```bash
git add collection/sinks/__init__.py collection/sinks/base.py tests/test_sink_base.py
git commit -m "feat: add the sink connector interface"
```

---

## Task 2: Configuration for OpenCTI and Wazuh

**Files:**
- Modify: `collection/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `resolve_opencti_url() -> str`, `resolve_opencti_token() -> str`, `resolve_wazuh_indexer_url() -> str`, `resolve_wazuh_indexer_user() -> str`, `resolve_wazuh_indexer_password() -> str`, `resolve_wazuh_api_url() -> str`, `resolve_wazuh_api_user() -> str`, `resolve_wazuh_api_password() -> str`, `resolve_wazuh_min_rule_level() -> int`, `resolve_wazuh_state_path() -> ResolvedValue`, `resolve_allow_insecure_tls() -> bool`. All importable as `from collection.config import ...` alongside the existing names.

- [ ] **Step 1: Write the failing tests**

```python
# Append to tests/test_config.py
from collection.config import (
    resolve_allow_insecure_tls,
    resolve_opencti_token,
    resolve_opencti_url,
    resolve_wazuh_api_password,
    resolve_wazuh_api_url,
    resolve_wazuh_api_user,
    resolve_wazuh_indexer_password,
    resolve_wazuh_indexer_url,
    resolve_wazuh_indexer_user,
    resolve_wazuh_min_rule_level,
    resolve_wazuh_state_path,
)


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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ImportError` naming the new functions

- [ ] **Step 3: Add the new resolvers to `collection/config.py`**

Append to the existing file (keep everything already there unchanged):

```python
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
```

`_require_env` is a private helper shared by the eight identically-shaped
required-credential resolvers above it; each public function keeps its
own name and error hint, matching the existing one-purpose-per-function
style already used for `resolve_flod_db_path` and friends.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS (all tests, existing and new)

- [ ] **Step 5: Commit**

```bash
git add collection/config.py tests/test_config.py
git commit -m "feat: add config resolution for OpenCTI and Wazuh"
```

---

## Task 3: OpenCTI sink connector

**Files:**
- Modify: `requirements.txt`
- Create: `collection/sinks/opencti.py`
- Test: `tests/test_opencti_sink.py`

**Interfaces:**
- Consumes: `ThreatObservation` from `collection.schema` (Task 4 of the Local Collection plan); `resolve_opencti_token`, `resolve_opencti_url`, `resolve_allow_insecure_tls` from `collection.config` (Task 2 of this plan).
- Produces: `OpenCtiSinkConnector` class (constructor `OpenCtiSinkConnector(url: str | None = None, token: str | None = None)`, method `send(self, observation: ThreatObservation) -> None`), importable as `from collection.sinks.opencti import OpenCtiSinkConnector`.

- [ ] **Step 1: Add the `requests` dependency**

Add to `requirements.txt`:

```
requests==2.34.2
```

Install it:

```bash
pip install -r requirements.txt
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_opencti_sink.py
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from collection.schema import ThreatObservation
from collection.sinks.opencti import OpenCtiSinkConnector


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="203.0.113.5",
        source_verdict="DDoS",
        evidence={"rate": 950.0, "entropy": 0.2},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


def test_send_posts_a_valid_indicator_add_mutation():
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    mock_post.assert_called_once()
    call = mock_post.call_args
    assert call.args[0] == "http://localhost:8080/graphql"
    assert call.kwargs["headers"]["Authorization"] == "Bearer a-token"
    body = call.kwargs["json"]
    assert "indicatorAdd" in body["query"]
    variables = body["variables"]["input"]
    assert variables["pattern_type"] == "stix"
    assert variables["pattern"] == "[ipv4-addr:value = '203.0.113.5']"
    assert variables["name"] == "ddos-flood: 203.0.113.5"
    assert variables["indicator_types"] == ["ddos-flood"]
    mock_response.raise_for_status.assert_called_once()


def test_send_escapes_a_single_quote_in_the_indicator_value():
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = ThreatObservation(
        observation_id="22222222-2222-2222-2222-222222222222",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="fake-value-with-a-'-quote",
        source_verdict="DDoS",
        evidence={},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    pattern = mock_post.call_args.kwargs["json"]["variables"]["input"]["pattern"]
    assert pattern == "[ipv4-addr:value = 'fake-value-with-a-\\'-quote']"


def test_send_raises_when_opencti_returns_graphql_errors():
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"errors": [{"message": "bad input"}]}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response):
        with pytest.raises(RuntimeError, match="bad input"):
            connector.send(observation)


def test_send_verifies_tls_by_default(monkeypatch):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)
    connector = OpenCtiSinkConnector(url="http://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    assert mock_post.call_args.kwargs["verify"] is True


def test_send_skips_tls_verification_only_when_explicitly_allowed(monkeypatch):
    monkeypatch.setenv("CTI_ALLOW_INSECURE_TLS", "true")
    connector = OpenCtiSinkConnector(url="https://localhost:8080/graphql", token="a-token")
    observation = _sample_observation()
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"indicatorAdd": {"id": "abc"}}}

    with patch("collection.sinks.opencti.requests.post", return_value=mock_response) as mock_post:
        connector.send(observation)

    assert mock_post.call_args.kwargs["verify"] is False
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `pytest tests/test_opencti_sink.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sinks.opencti'`

- [ ] **Step 4: Write `collection/sinks/opencti.py`**

```python
"""Writes a believed observation into OpenCTI as a STIX indicator.

The indicatorAdd mutation and IndicatorAddInput fields used below come
from OpenCTI's own real schema, opencti-platform/opencti-graphql/src/
modules/indicator/indicator.graphql at tag 7.260914.0, the exact
release deploy/.env.example pins.
"""

from __future__ import annotations

import requests

from collection.config import (
    resolve_allow_insecure_tls,
    resolve_opencti_token,
    resolve_opencti_url,
)
from collection.schema import ThreatObservation

_INDICATOR_ADD_MUTATION = """
mutation IndicatorAdd($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) {
    id
  }
}
"""


class OpenCtiSinkConnector:
    def __init__(self, url: str | None = None, token: str | None = None):
        self._url = url if url is not None else resolve_opencti_url()
        self._token = token if token is not None else resolve_opencti_token()
        self._verify_tls = not resolve_allow_insecure_tls()

    def send(self, observation: ThreatObservation) -> None:
        escaped_value = observation.indicator_value.replace("'", "\\'")
        pattern = f"[ipv4-addr:value = '{escaped_value}']"
        description = (
            f"Reported by node {observation.reporting_node_id} at "
            f"{observation.observed_at}. Source verdict: "
            f"{observation.source_verdict}. Evidence: {observation.evidence}."
        )

        variables = {
            "input": {
                "pattern_type": "stix",
                "pattern": pattern,
                "name": f"{observation.indicator_type}: {observation.indicator_value}",
                "description": description,
                "indicator_types": [observation.indicator_type],
                "x_opencti_detection": True,
            }
        }

        response = requests.post(
            self._url,
            json={"query": _INDICATOR_ADD_MUTATION, "variables": variables},
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30,
            verify=self._verify_tls,
        )
        response.raise_for_status()
        body = response.json()
        if body.get("errors"):
            raise RuntimeError(f"OpenCTI rejected the indicator: {body['errors']}")
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_opencti_sink.py -v`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add requirements.txt collection/sinks/opencti.py tests/test_opencti_sink.py
git commit -m "feat: add the OpenCTI sink connector"
```

---

## Task 4: Wazuh source connector

**Files:**
- Create: `collection/sources/wazuh.py`
- Test: `tests/test_wazuh_source.py`

**Interfaces:**
- Consumes: `RawSignal` from `collection.sources.base` (Task 1 of the Local Collection plan); `resolve_wazuh_indexer_url`, `resolve_wazuh_indexer_user`, `resolve_wazuh_indexer_password`, `resolve_wazuh_min_rule_level`, `resolve_wazuh_state_path` from `collection.config` (Task 2 of this plan).
- Produces: `WazuhConnector` class (constructor `WazuhConnector(indexer_url: str | None = None, user: str | None = None, password: str | None = None, min_rule_level: int | None = None, state_path: Path | None = None)`, method `iter_signals(self) -> Iterator[RawSignal]`); `SymlinkStateError` exception. Importable as `from collection.sources.wazuh import WazuhConnector, SymlinkStateError`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_wazuh_source.py
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_wazuh_source.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sources.wazuh'`

- [ ] **Step 3: Write `collection/sources/wazuh.py`**

```python
"""Reads Wazuh's own alerts (via its indexer) and yields RawSignals.

The /wazuh-alerts-*/_search query shape and field names below were
confirmed against a real, live Wazuh 4.14.7 indexer, not assumed from
documentation. Two real alert shapes exist depending on which rule and
decoder fired: a Security Configuration Assessment alert has no srcip
at all (data.sca.*), an SSH alert has data.srcip/dstuser/srcport.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import requests

from collection.config import (
    resolve_allow_insecure_tls,
    resolve_wazuh_indexer_password,
    resolve_wazuh_indexer_url,
    resolve_wazuh_indexer_user,
    resolve_wazuh_min_rule_level,
    resolve_wazuh_state_path,
)
from collection.sources.base import RawSignal

_PAGE_SIZE = 500
_EPOCH_ISO = "1970-01-01T00:00:00.000Z"
_MAX_STATE_FILE_BYTES = 1_000_000


class SymlinkStateError(RuntimeError):
    """Raised when the Wazuh high-water-mark state file path is a symlink."""


class WazuhConnector:
    def __init__(
        self,
        indexer_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        min_rule_level: int | None = None,
        state_path: Path | None = None,
    ):
        self._indexer_url = (
            indexer_url if indexer_url is not None else resolve_wazuh_indexer_url()
        )
        self._user = user if user is not None else resolve_wazuh_indexer_user()
        self._password = (
            password if password is not None else resolve_wazuh_indexer_password()
        )
        self._min_rule_level = (
            min_rule_level
            if min_rule_level is not None
            else resolve_wazuh_min_rule_level()
        )
        self._state_path = (
            state_path if state_path is not None else resolve_wazuh_state_path().value
        )
        self._verify_tls = not resolve_allow_insecure_tls()

    def iter_signals(self) -> Iterator[RawSignal]:
        since = self._load_high_water_mark()
        newest_seen = since
        search_after = None

        while True:
            query: dict = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": self._min_rule_level}}},
                            {"range": {"@timestamp": {"gt": since}}},
                        ]
                    }
                },
                "sort": [{"@timestamp": "asc"}],
                "size": _PAGE_SIZE,
            }
            if search_after is not None:
                query["search_after"] = search_after

            response = requests.post(
                f"{self._indexer_url}/wazuh-alerts-*/_search",
                json=query,
                auth=(self._user, self._password),
                timeout=30,
                verify=self._verify_tls,
            )
            response.raise_for_status()
            hits = response.json()["hits"]["hits"]
            if not hits:
                break

            for hit in hits:
                alert = hit["_source"]
                timestamp = alert.get("@timestamp", since)
                if timestamp > newest_seen:
                    newest_seen = timestamp
                signal = self._to_signal(alert)
                if signal is not None:
                    yield signal
                search_after = hit["sort"]

            if len(hits) < _PAGE_SIZE:
                break

        if newest_seen != since:
            self._save_high_water_mark(newest_seen)

    def _to_signal(self, alert: dict) -> RawSignal | None:
        data = alert.get("data", {})
        source_address = data.get("srcip")
        if not source_address:
            return None

        rule = alert.get("rule", {})
        mitre = rule.get("mitre", {})
        groups = rule.get("groups", [])

        return RawSignal(
            observed_at=self._parse_timestamp(alert.get("@timestamp")),
            source_address=source_address,
            indicator_type=groups[0] if groups else "wazuh-alert",
            source_verdict=rule.get("description", "unknown"),
            evidence={
                "rule_level": rule.get("level"),
                "rule_id": rule.get("id"),
                "mitre_tactic": mitre.get("tactic"),
                "mitre_technique": mitre.get("technique"),
                "decoder": alert.get("decoder", {}).get("name"),
            },
        )

    @staticmethod
    def _parse_timestamp(value: str | None) -> float:
        if not value:
            return datetime.now(tz=timezone.utc).timestamp()
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

    def _load_high_water_mark(self) -> str:
        if not self._state_path.exists():
            return _EPOCH_ISO
        if self._state_path.is_symlink():
            raise SymlinkStateError(
                f"{self._state_path} is a symlink, refusing to read it"
            )
        fd = os.open(str(self._state_path), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r") as f:
            contents = f.read(_MAX_STATE_FILE_BYTES)
        return json.loads(contents).get("last_seen", _EPOCH_ISO)

    def _save_high_water_mark(self, timestamp: str) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._state_path.exists():
            self._state_path.unlink()
        fd = os.open(
            str(self._state_path),
            os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_NOFOLLOW,
            mode=0o600,
        )
        with os.fdopen(fd, "w") as f:
            json.dump({"last_seen": timestamp}, f)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_wazuh_source.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add collection/sources/wazuh.py tests/test_wazuh_source.py
git commit -m "feat: add the Wazuh source connector"
```

---

## Task 5: Wazuh sink connector (active response)

**Files:**
- Create: `collection/sinks/wazuh.py`
- Test: `tests/test_wazuh_sink.py`

**Interfaces:**
- Consumes: `ThreatObservation` from `collection.schema`; `resolve_wazuh_api_url`, `resolve_wazuh_api_user`, `resolve_wazuh_api_password` from `collection.config` (Task 2 of this plan).
- Produces: `WazuhSinkConnector` class (constructor `WazuhSinkConnector(api_url: str | None = None, user: str | None = None, password: str | None = None, command: str = "firewall-drop600")`, method `send(self, observation: ThreatObservation) -> None`), importable as `from collection.sinks.wazuh import WazuhSinkConnector`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_wazuh_sink.py
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from collection.schema import ThreatObservation
from collection.sinks.wazuh import WazuhSinkConnector


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="203.0.113.5",
        source_verdict="DDoS",
        evidence={},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


def test_send_authenticates_then_triggers_the_configured_active_response_command():
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000", user="wazuh", password="a-password"
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 0}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response) as mock_auth, \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response) as mock_put:
        connector.send(observation)

    mock_auth.assert_called_once()
    assert mock_auth.call_args.kwargs["auth"] == ("wazuh", "a-password")

    mock_put.assert_called_once()
    put_call = mock_put.call_args
    assert put_call.args[0] == "https://wazuh.example:55000/active-response"
    assert put_call.kwargs["headers"]["Authorization"] == "Bearer a-jwt-token"
    body = put_call.kwargs["json"]
    assert body["command"] == "firewall-drop600"
    assert body["alert"]["data"]["srcip"] == "203.0.113.5"
    ar_response.raise_for_status.assert_called_once()


def test_send_uses_a_custom_command_when_configured():
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000",
        user="wazuh",
        password="a-password",
        command="firewall-drop3600",
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 0}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response), \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response) as mock_put:
        connector.send(observation)

    assert mock_put.call_args.kwargs["json"]["command"] == "firewall-drop3600"


def test_send_raises_when_wazuh_reports_an_error():
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000", user="wazuh", password="a-password"
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 1, "message": "invalid command"}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response), \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response):
        with pytest.raises(RuntimeError, match="invalid command"):
            connector.send(observation)


def test_send_verifies_tls_by_default(monkeypatch):
    monkeypatch.delenv("CTI_ALLOW_INSECURE_TLS", raising=False)
    connector = WazuhSinkConnector(
        api_url="https://wazuh.example:55000", user="wazuh", password="a-password"
    )
    observation = _sample_observation()

    auth_response = MagicMock()
    auth_response.json.return_value = {"data": {"token": "a-jwt-token"}}
    ar_response = MagicMock()
    ar_response.json.return_value = {"error": 0}

    with patch("collection.sinks.wazuh.requests.post", return_value=auth_response) as mock_post, \
         patch("collection.sinks.wazuh.requests.put", return_value=ar_response) as mock_put:
        connector.send(observation)

    assert mock_post.call_args.kwargs["verify"] is True
    assert mock_put.call_args.kwargs["verify"] is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_wazuh_sink.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sinks.wazuh'`

- [ ] **Step 3: Write `collection/sinks/wazuh.py`**

```python
"""Writes a believed observation into Wazuh's active-response mechanism.

The /active-response endpoint and ActiveResponseBody shape below come
from Wazuh's own real API spec, api/api/spec/spec.yaml in the
wazuh/wazuh repository at tag v4.14.7. The default command name,
firewall-drop600, was confirmed against a real homelab server's own
configured /var/ossec/etc/shared/ar.conf, not assumed from generic
Wazuh documentation.
"""

from __future__ import annotations

import requests

from collection.config import (
    resolve_allow_insecure_tls,
    resolve_wazuh_api_password,
    resolve_wazuh_api_url,
    resolve_wazuh_api_user,
)
from collection.schema import ThreatObservation

_DEFAULT_COMMAND = "firewall-drop600"


class WazuhSinkConnector:
    def __init__(
        self,
        api_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        command: str = _DEFAULT_COMMAND,
    ):
        self._api_url = api_url if api_url is not None else resolve_wazuh_api_url()
        self._user = user if user is not None else resolve_wazuh_api_user()
        self._password = (
            password if password is not None else resolve_wazuh_api_password()
        )
        self._command = command
        self._verify_tls = not resolve_allow_insecure_tls()

    def send(self, observation: ThreatObservation) -> None:
        token = self._authenticate()
        body = {
            "command": self._command,
            "arguments": ["-"],
            "alert": {"data": {"srcip": observation.indicator_value}},
        }
        response = requests.put(
            f"{self._api_url}/active-response",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
            verify=self._verify_tls,
        )
        response.raise_for_status()
        result = response.json()
        if result.get("error"):
            raise RuntimeError(
                f"Wazuh rejected the active-response command: {result.get('message', result)}"
            )

    def _authenticate(self) -> str:
        response = requests.post(
            f"{self._api_url}/security/user/authenticate",
            auth=(self._user, self._password),
            timeout=30,
            verify=self._verify_tls,
        )
        response.raise_for_status()
        return response.json()["data"]["token"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_wazuh_sink.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add collection/sinks/wazuh.py tests/test_wazuh_sink.py
git commit -m "feat: add the Wazuh sink connector"
```

---

## Task 6: Full suite check and fan-out helper

**Files:**
- Create: `collection/sinks/dispatch.py`
- Test: `tests/test_sink_dispatch.py`

**Interfaces:**
- Consumes: `SinkConnector` from `collection.sinks.base` (Task 1); `ThreatObservation` from `collection.schema`.
- Produces: `send_to_all(observation: ThreatObservation, sinks: list[SinkConnector]) -> list[Exception]` (returns the exceptions raised by any failing sinks, empty list if all succeeded), importable as `from collection.sinks.dispatch import send_to_all`.

This is the one piece of actual fan-out logic the spec requires: a node
configures several sinks, and one sink failing must not stop the others
from being tried.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_sink_dispatch.py
from __future__ import annotations

from collection.schema import ThreatObservation
from collection.sinks.dispatch import send_to_all


def _sample_observation() -> ThreatObservation:
    return ThreatObservation(
        observation_id="11111111-1111-1111-1111-111111111111",
        reporting_node_id="node-abc123",
        observed_at="2026-09-16T00:00:00+00:00",
        indicator_type="ddos-flood",
        indicator_value="203.0.113.5",
        source_verdict="DDoS",
        evidence={},
        severity=None,
        confidence=None,
        signature="a" * 128,
    )


class _RecordingSink:
    def __init__(self) -> None:
        self.received: list[ThreatObservation] = []

    def send(self, observation: ThreatObservation) -> None:
        self.received.append(observation)


class _FailingSink:
    def send(self, observation: ThreatObservation) -> None:
        raise RuntimeError("this sink is down")


def test_send_to_all_reaches_every_configured_sink():
    sink_a = _RecordingSink()
    sink_b = _RecordingSink()
    observation = _sample_observation()

    errors = send_to_all(observation, [sink_a, sink_b])

    assert errors == []
    assert sink_a.received == [observation]
    assert sink_b.received == [observation]


def test_a_failing_sink_does_not_block_the_others():
    good_sink = _RecordingSink()
    bad_sink = _FailingSink()
    observation = _sample_observation()

    errors = send_to_all(observation, [bad_sink, good_sink])

    assert len(errors) == 1
    assert "this sink is down" in str(errors[0])
    assert good_sink.received == [observation]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_sink_dispatch.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'collection.sinks.dispatch'`

- [ ] **Step 3: Write `collection/sinks/dispatch.py`**

```python
"""Fans a believed observation out to every configured sink."""

from __future__ import annotations

from collection.schema import ThreatObservation
from collection.sinks.base import SinkConnector


def send_to_all(
    observation: ThreatObservation, sinks: list[SinkConnector]
) -> list[Exception]:
    """Calls send() on every sink. One sink failing does not stop the rest."""
    errors: list[Exception] = []
    for sink in sinks:
        try:
            sink.send(observation)
        except Exception as exc:
            errors.append(exc)
    return errors
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_sink_dispatch.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the entire test suite**

Run: `pytest -v`
Expected: every test across this plan and the Local Collection plan passes.

- [ ] **Step 6: Commit**

```bash
git add collection/sinks/dispatch.py tests/test_sink_dispatch.py
git commit -m "feat: add sink fan-out, one failing sink does not block the rest"
```

---

## Manual verification (not a task, a final check)

The automated tests above use mocked HTTP calls and real fixture data
pulled from live systems; they do not themselves prove the connectors
work against those systems today. Before this work is considered done:

1. **OpenCTI.** With `CTI_OPENCTI_URL` and `CTI_OPENCTI_TOKEN` set to the
   real running VM instance's own values (read them from the VM's own
   `deploy/.env`, never copy them into this repository or any command
   history), call `OpenCtiSinkConnector().send()` with a real
   `ThreatObservation` and confirm the indicator appears in OpenCTI's
   own UI.
2. **Wazuh source.** With `CTI_WAZUH_INDEXER_URL`,
   `CTI_WAZUH_INDEXER_USER`, `CTI_WAZUH_INDEXER_PASSWORD` set to the real
   homelab server's own values (credentials supplied via environment
   variable at execution time only, never written into any file this
   plan or its commits touch), call `WazuhConnector().iter_signals()`
   and confirm real alerts come back shaped as expected, with no
   destination-side field anywhere in the output.
3. **Wazuh sink.** With `CTI_WAZUH_API_URL`, `CTI_WAZUH_API_USER`,
   `CTI_WAZUH_API_PASSWORD` set the same way, call
   `WazuhSinkConnector().send()` against a real but harmless test
   address (not a real production host) and confirm the active-response
   command actually fires, via `journalctl` or Wazuh's own
   `active-responses.log` on the server.
4. If any real system is unreachable at execution time, state that
   plainly in the report, the same standard already held for the Local
   Collection Layer's own real-FLOD-data
   verification.
