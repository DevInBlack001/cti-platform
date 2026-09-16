"""Writes signed observations to OpenCTI as STIX indicators.

Implements the SinkConnector protocol to deliver Threat Observations to an
OpenCTI GraphQL endpoint, creating STIX indicators with a pattern describing
the observed indicator type and value. Handles TLS verification and includes
evidence in the indicator's description.
"""

from __future__ import annotations

import requests

from collection.config import (
    resolve_allow_insecure_tls,
    resolve_opencti_token,
    resolve_opencti_url,
)
from collection.schema import ThreatObservation

# GraphQL mutation to add an indicator to OpenCTI. Comes from the OpenCTI
# schema at opencti-platform/opencti-graphql/src/modules/indicator/
# indicator.graphql at tag 7.260914.0.
_INDICATOR_ADD_MUTATION = """
mutation IndicatorAdd($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) {
    id
  }
}
"""


class OpenCtiSinkConnector:
    """Sends signed observations to OpenCTI as STIX indicators."""

    def __init__(self, url: str | None = None, token: str | None = None):
        """Initializes the connector with OpenCTI credentials.

        Takes optional URL and token for testing; defaults to resolving from
        environment variables. TLS verification is enabled by default, disabled
        only if CTI_ALLOW_INSECURE_TLS is set.
        """
        self._url = url if url is not None else resolve_opencti_url()
        self._token = token if token is not None else resolve_opencti_token()
        self._verify_tls = not resolve_allow_insecure_tls()

    def send(self, observation: ThreatObservation) -> None:
        """Sends an observation to OpenCTI as a STIX indicator.

        Creates an indicator with a STIX pattern matching the observation's
        indicator type and value, and includes evidence in the description.
        Raises RuntimeError if OpenCTI accepts the request but reports a
        GraphQL-level error; an HTTP-level failure (a non-2xx response)
        raises whatever requests.raise_for_status() itself raises.
        """
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
