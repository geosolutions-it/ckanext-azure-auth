"""
Shared abstract base class for Azure auth backends.
"""
import logging
import re
from abc import ABC, abstractmethod

from ckan.lib.munge import substitute_ascii_equivalents
from ckan.plugins import toolkit

from ckanext.azure_auth.base.config import BaseProviderConfig

log = logging.getLogger(__name__)


class BaseAuthBackend(ABC):
    """Abstract base class for authentication backends."""

    provider_config: BaseProviderConfig

    def __init__(self, provider_config):
        self.provider_config = provider_config

    @staticmethod
    def _get_fixed_user_schema():
        """Returns the default user schema but with an optional password."""
        from ckan.logic.schema import default_user_schema

        schema = default_user_schema()

        ignore_missing = toolkit.get_validator('ignore_missing')
        user_password_validator = toolkit.get_validator('user_password_validator')
        user_password_not_empty = toolkit.get_validator('user_password_not_empty')
        unicode_safe = toolkit.get_validator('unicode_safe')

        schema['password'] = [
            ignore_missing,
            user_password_validator,
            user_password_not_empty,
            unicode_safe
        ]
        return schema

    @staticmethod
    def sanitize_username(tag: str):
        """Normalise a raw display name into a valid CKAN username.

        Converts Unicode characters to ASCII equivalents, lowercases the
        result, strips leading/trailing whitespace, removes any character
        that is not alphanumeric or a hyphen, and replaces spaces with
        hyphens.
        """
        tag = substitute_ascii_equivalents(tag)
        tag = tag.lower().strip()
        tag = re.sub(r'[^a-zA-Z0-9\- ]', '', tag).replace(' ', '-')
        return tag

    @abstractmethod
    def get_or_create_user(self, claims):
        """Create or retrieve a CKAN user from token claims."""
        pass

    @abstractmethod
    def process_access_token(self, *args, **kwargs):
        """Validate a token and return the corresponding CKAN user."""
        pass
