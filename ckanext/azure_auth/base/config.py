"""
Shared abstract base classes for Azure auth provider configuration.
"""
from abc import ABC, abstractmethod


class BaseProviderConfig(ABC):
    """Abstract base class for provider configuration."""

    authorization_endpoint = None
    """URL of the OAuth2/OIDC authorization endpoint."""

    token_endpoint = None
    """URL of the token exchange endpoint."""

    end_session_endpoint = None
    """URL for ending the user's SSO session."""

    issuer = None
    """Expected token issuer (iss claim value)."""

    session = None
    """HTTP session used for requests to the identity provider."""

    @abstractmethod
    def load_config(self):
        """Load the provider configuration (endpoints, keys, etc.)."""
        pass

    @abstractmethod
    def build_authorization_endpoint(self):
        """Return the authorization URL to redirect the user to."""
        pass
