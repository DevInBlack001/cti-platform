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
