"""
Shared abstract base classes for Azure auth provider configuration.
"""

from abc import ABC, abstractmethod

from ckan.common import config

from ckanext.azure_auth.constants import (
    ATTR_SERVICE_DOMAIN,
    ATTR_SERVICE_ID,
    ATTR_TENANT_ID,
    ATTR_POLICY,
    ATTR_CLIENT_ID,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_SCOPE,
    ATTR_RESPONSE_TYPE,
    DEFAULT_CALLBACK_PATH,
)


class BaseProviderConfig:
    """Abstract base class for provider configuration."""

    def __init__(self, ckan_config):
        self.service_domain = ckan_config.get(ATTR_SERVICE_DOMAIN)
        self.tenant_id = ckan_config.get(ATTR_TENANT_ID)
        self.policy = ckan_config.get(ATTR_POLICY)
        self.client_id = ckan_config.get(ATTR_CLIENT_ID)
        # optional settings
        self.service_id = ckan_config.get(ATTR_SERVICE_ID, None)
        self.scope = ckan_config.get(ATTR_SCOPE, "openid")
        self.response_type = ckan_config.get(ATTR_RESPONSE_TYPE, "id_token")
        self.auth_callback_path = ckan_config.get(ATTR_AUTH_CALLBACK_PATH, DEFAULT_CALLBACK_PATH)

    def load_remote_config(self):
        """Load the provider configuration (endpoints, keys, etc.)."""
        raise NotImplementedError()

    def build_authorization_endpoint(self):
        """Return the authorization URL to redirect the user to."""
        raise NotImplementedError()

    def get_redirect_url(self):
        return config["ckan.site_url"] + self.auth_callback_path
