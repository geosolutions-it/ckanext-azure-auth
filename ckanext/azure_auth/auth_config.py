"""
Compatibility shim — all symbols have moved to their canonical locations.
Import from ckanext.azure_auth.constants and ckanext.azure_auth.{adfs,b2c}.config instead.
"""
from ckanext.azure_auth.constants import (  # noqa: F401
    _EXTNAME,
    AZURE_AD_SERVER_URL,
    ADFS_SESSION_PREFIX,
    ATTR_AUTH_SERVICE,
    ATTR_MODE,
    ATTR_AD_SERVER,
    ATTR_WT_REALM,
    ATTR_METADATA_URL,
    ATTR_HELP_TEXT,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_TENANT_ID,
    ATTR_CLIENT_ID,
    ATTR_SERVICE_DOMAIN,
    ATTR_SERVICE_ID,
    ATTR_ADSF_AUDIENCE,
    ATTR_CLIENT_SECRET,
    ATTR_FORCE_MFA,
    ATTR_DISABLE_SSO,
    ATTR_USER_ID_TEMPLATE,
    ATTR_POLICY,
    ATTR_MAIL_CLAIMS,
    ATTR_SPIDL,
    ATTR_REDIRECT_URL,
    ATTR_CREATE_USER,
    ATTR_LOGIN_LABEL,
    ATTR_LOGIN_BUTTON,
    RENDERABLE_ATTRS,
    TIMEOUT,
)
from ckanext.azure_auth.base.config import BaseProviderConfig  # noqa: F401
from ckanext.azure_auth.adfs.config import AdfsProviderConfig as ProviderConfig  # noqa: F401
from ckanext.azure_auth.b2c.config import B2CProviderConfig  # noqa: F401
