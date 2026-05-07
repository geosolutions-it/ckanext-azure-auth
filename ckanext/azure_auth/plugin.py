"""
Compatibility shim — use azure_auth_adfs or azure_auth_b2c plugins instead.

The monolithic AzureAuthPlugin is kept here as a deprecated alias so that
existing deployments that still have ``azure_auth`` in ckan.plugins continue
to load (pointing to the ADFS plugin).  Switch to ``azure_auth_adfs`` or
``azure_auth_b2c`` at your earliest convenience.
"""
import warnings

from ckanext.azure_auth.adfs.plugin import AzureAdfsPlugin  # noqa: F401

warnings.warn(
    "The 'azure_auth' plugin entry-point is deprecated. "
    "Use 'azure_auth_adfs' or 'azure_auth_b2c' in ckan.plugins instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Keep the old name importable
AzureAuthPlugin = AzureAdfsPlugin
