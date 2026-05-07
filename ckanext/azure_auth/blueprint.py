"""
Compatibility shim — blueprints have moved to ckanext.azure_auth.{adfs,b2c}.blueprint.
"""
from ckanext.azure_auth.adfs.blueprint import (  # noqa: F401
    adfs_auth_blueprint as azure_auth_blueprint,
    azure_admin_blueprint,
    login_callback,
)
from ckanext.azure_auth.adfs.config import AdfsProviderConfig

def get_auth_backend():
    """Deprecated helper kept for back-compat. Creates an ADFS backend."""
    from ckanext.azure_auth.adfs.backend import AdfsAuthBackend
    provider_config = AdfsProviderConfig()
    provider_config.load_config()
    return AdfsAuthBackend(provider_config=provider_config)
