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

# Default active-response command to trigger on a source IP address.
# Confirmed against the real homelab server's own ar.conf, which lists
# entries as "<name> - <executable> - <timeout>": firewall-drop600 maps
# to the firewall-drop executable with a 600-second timeout, and that
# server's ossec.conf confirms firewall-drop has timeout_allowed set,
# so the trailing number is a real, active timeout in seconds.
_DEFAULT_COMMAND = "firewall-drop600"


class WazuhSinkConnector:
    """Sends ThreatObservation indicators to Wazuh's active-response system.

    This connector authenticates against Wazuh's security API and submits
    active-response requests to take defensive actions (such as firewall
    blocks) on source IP addresses identified in threat observations.
    """

    def __init__(
        self,
        api_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        command: str = _DEFAULT_COMMAND,
    ):
        """Initialize the Wazuh sink connector with API credentials and settings.

        Args:
            api_url: Base URL of the Wazuh API (e.g., https://wazuh.example:55000).
                     Resolved from CTI_WAZUH_API_URL config if not provided.
            user: Username for Wazuh API authentication.
                  Resolved from CTI_WAZUH_API_USER config if not provided.
            password: Password for Wazuh API authentication.
                      Resolved from CTI_WAZUH_API_PASSWORD config if not provided.
            command: Name of the active-response command to execute.
                     Defaults to firewall-drop600, a 600-second firewall
                     block, confirmed against a real server's own ar.conf.
        """
        self._api_url = api_url if api_url is not None else resolve_wazuh_api_url()
        self._user = user if user is not None else resolve_wazuh_api_user()
        self._password = (
            password if password is not None else resolve_wazuh_api_password()
        )
        self._command = command
        # TLS certificate verification is disabled only if CTI_ALLOW_INSECURE_TLS
        # environment variable is set to a truthy value; defaults to True (verify).
        self._verify_tls = not resolve_allow_insecure_tls()

    def send(self, observation: ThreatObservation) -> None:
        """Send a threat observation to Wazuh as an active-response request.

        Authenticates with the Wazuh API, constructs an active-response body
        with the source IP from the observation, and submits it to trigger
        a configured defense action (firewall block, etc.). Raises RuntimeError
        if Wazuh reports an error in the response.

        Args:
            observation: The threat observation to submit, containing the
                         indicator_value (source IP) to be blocked.

        Raises:
            RuntimeError: If Wazuh accepts the HTTP request but reports an
                          error in the response body.
            requests.RequestException: If authentication or the HTTP request
                                       itself fails (a non-2xx response).
        """
        token = self._authenticate()
        # Build the active-response request body with the command, placeholder
        # arguments, and the source IP extracted from the observation's indicator.
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
        # Check the error field in the response; non-zero error values indicate failure.
        if result.get("error"):
            raise RuntimeError(
                f"Wazuh rejected the active-response command: {result.get('message', result)}"
            )

    def _authenticate(self) -> str:
        """Authenticate with Wazuh's security API and return a JWT token.

        Uses HTTP Basic authentication (username and password) to request
        a JWT token from Wazuh's /security/user/authenticate endpoint.

        Returns:
            JWT token string for use in subsequent Wazuh API requests.

        Raises:
            requests.RequestException: If authentication fails or the API
                                       returns an HTTP error status.
        """
        response = requests.post(
            f"{self._api_url}/security/user/authenticate",
            auth=(self._user, self._password),
            timeout=30,
            verify=self._verify_tls,
        )
        response.raise_for_status()
        return response.json()["data"]["token"]
