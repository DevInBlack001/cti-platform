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
