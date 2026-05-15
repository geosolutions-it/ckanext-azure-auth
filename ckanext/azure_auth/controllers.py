"""
Compatibility shim — controllers have moved to the adfs/b2c blueprint modules.
"""

from ckanext.azure_auth.adfs.blueprint import login_callback  # noqa: F401
