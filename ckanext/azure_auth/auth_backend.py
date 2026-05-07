"""
Compatibility shim — backend classes have moved to ckanext.azure_auth.{adfs,b2c}.backend.
"""
from ckanext.azure_auth.base.backend import BaseAuthBackend  # noqa: F401
from ckanext.azure_auth.adfs.backend import AdfsAuthBackend  # noqa: F401
from ckanext.azure_auth.b2c.backend import B2CAuthBackend  # noqa: F401
