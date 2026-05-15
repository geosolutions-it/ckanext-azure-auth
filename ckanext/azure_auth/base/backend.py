"""
Shared abstract base class for Azure auth backends.
"""
import logging
import re
from abc import ABC, abstractmethod

from ckan.common import config
from ckan.lib.munge import substitute_ascii_equivalents
from ckan.plugins import toolkit

from ckanext.azure_auth.constants import ATTR_USER_ID_TEMPLATE, ATTR_MAIL_CLAIMS, ATTR_AUTH_CALLBACK_PATH

log = logging.getLogger(__name__)


class BaseAuthBackend(ABC):
    """Abstract base class for authentication backends."""

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

    def _build_user_id(self, claims: dict):
        user_id_template = config.get(ATTR_USER_ID_TEMPLATE)
        if not user_id_template:
            raise RuntimeError("User ID template not configured")
        try:
            external_id = user_id_template.format_map(claims)
            return external_id.strip('"').lower()
        except KeyError as e:
            log.error(f"Missing required claim {e}")
            raise PermissionError

    def _discover_mail(self, claims: dict):
        mail_claims_cfg = config.get(ATTR_MAIL_CLAIMS, "email") or "email"
        mail_claim_list = [c.strip() for c in mail_claims_cfg.split(",") if c.strip()]

        for claim_name in mail_claim_list:
            value = claims.get(claim_name)
            if value:
                return value
        return None

