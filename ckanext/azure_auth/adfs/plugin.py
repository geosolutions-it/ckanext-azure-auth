import logging

from ckan.common import config as ckan_config
from ckan.common import g, session
from ckan.exceptions import CkanConfigurationException
from ckan.logic import get_action, NotAuthorized
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.azure_auth.adfs.blueprint import adfs_auth_blueprint, azure_admin_blueprint
from ckanext.azure_auth.adfs.config import AdfsProviderConfig
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_AD_SERVER,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_DISABLE_SSO,
    ATTR_FORCE_MFA,
    ATTR_LOGIN_BUTTON,
    ATTR_LOGIN_LABEL,
    ATTR_METADATA_URL,
    ATTR_TENANT_ID,
    AZURE_AD_SERVER_URL,
    RENDERABLE_ATTRS,
    _EXTNAME,
)

log = logging.getLogger(__name__)


class AzureAdfsPlugin(plugins.SingletonPlugin):
    """Microsoft Azure ADFS / Azure AD authentication plugin."""

    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        toolkit.add_template_directory(config, "../templates")
        toolkit.add_public_directory(config, "../public")

        toolkit.add_ckan_admin_tab(config, "azure_admin.azure_auth_config", "ADFS", icon="windows")

        if ATTR_TENANT_ID in config:
            if ATTR_AD_SERVER in config:
                msg = f"The {ATTR_AD_SERVER} should not be set when {ATTR_TENANT_ID} is set."
                raise CkanConfigurationException(msg)
            config[ATTR_AD_SERVER] = AZURE_AD_SERVER_URL

        if ATTR_TENANT_ID not in config and ATTR_AD_SERVER not in config:
            msg = f"Exactly one of the settings {ATTR_TENANT_ID} or {ATTR_AD_SERVER} must be set"
            raise CkanConfigurationException(msg)
        elif ATTR_TENANT_ID not in config:
            config[ATTR_TENANT_ID] = "adfs"

        azure_auth_plugin_defaults = (
            (ATTR_METADATA_URL, "https://login.microsoftonline.com/"),
            (ATTR_AUTH_CALLBACK_PATH, "/oauth2/callback"),
            (ATTR_FORCE_MFA, False),
            (ATTR_DISABLE_SSO, False),
            (f"{_EXTNAME}.config_reload_interval", 24),
            (f"{_EXTNAME}.ca_bundle", True),
            (f"{_EXTNAME}.retry", 5),
            (f"{_EXTNAME}.jwt_leeway", 0),
        )
        for k, d in azure_auth_plugin_defaults:
            config.setdefault(k, d)

    def update_config_schema(self, schema):
        unicode_safe = toolkit.get_validator("unicode_safe")
        ignore_missing = toolkit.get_validator("ignore_missing")

        schema.update(
            {
                ATTR_LOGIN_LABEL: [ignore_missing, unicode_safe],
                ATTR_LOGIN_BUTTON: [ignore_missing, unicode_safe],
            }
        )
        return schema

    def get_helpers(self):
        def is_azure_user(user_id):
            from ckan import model

            if not user_id:
                return False
            try:
                user_obj = model.User.get(user_id)
                return user_obj and "azure_auth" in user_obj.plugin_extras
            except Exception:
                return False

        def get_attrib(key):
            if key not in RENDERABLE_ATTRS:
                raise NotAuthorized("Attribute is not accessible")
            return get_action("config_option_show")({"ignore_auth": True}, {"key": key})

        try:
            provider_config = AdfsProviderConfig(ckan_config)
            provider_config.load_remote_config()
            adfs_authentication_endpoint_error = ""
            adfs_authentication_endpoint = provider_config.build_authorization_endpoint()
        except RuntimeError as err:
            log.critical(err)
            adfs_authentication_endpoint = False
            adfs_authentication_endpoint_error = str(err)

        return {
            "is_azure_user": is_azure_user,
            "adfs_authentication_endpoint": adfs_authentication_endpoint,
            "adfs_authentication_endpoint_error": adfs_authentication_endpoint_error,
            "adfs_get_attrib": get_attrib,
        }

    def get_blueprint(self):
        return [adfs_auth_blueprint, azure_admin_blueprint]

    # IAuthenticator
    def identify(self):
        user = session.get(f"{ADFS_SESSION_PREFIX}user")
        if user:
            g.user = user

    def login(self):
        pass

    def logout(self):
        if f"{ADFS_SESSION_PREFIX}tokens" in session:
            del session[f"{ADFS_SESSION_PREFIX}tokens"]

        keys_to_delete = [key for key in session if key.startswith(ADFS_SESSION_PREFIX)]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()

    def abort(self, status_code, detail, headers, comment):
        return status_code, detail, headers, comment

    def authenticate(self, identity):
        return None
