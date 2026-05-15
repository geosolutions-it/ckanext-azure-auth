import logging

from ckan.common import g, session
from ckan.logic import get_action, NotAuthorized
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.azure_auth.b2c.blueprint import b2c_auth_blueprint, azure_admin_blueprint
from ckanext.azure_auth.b2c.config import b2c_config
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_LOGIN_BUTTON,
    ATTR_LOGIN_LABEL,
    RENDERABLE_ATTRS,
)

log = logging.getLogger(__name__)


class AzureB2CPlugin(plugins.SingletonPlugin):
    '''Microsoft Azure B2C (MyIdentity) authentication plugin.'''

    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        toolkit.add_template_directory(config, '../templates')
        toolkit.add_public_directory(config, '../public')

        toolkit.add_ckan_admin_tab(config, 'azure_admin.azure_auth_config', 'Azure B2C', icon='windows')

    def update_config_schema(self, schema):
        unicode_safe = toolkit.get_validator('unicode_safe')
        ignore_missing = toolkit.get_validator('ignore_missing')

        schema.update(
            {
                ATTR_LOGIN_LABEL: [ignore_missing, unicode_safe],
                ATTR_LOGIN_BUTTON: [ignore_missing, unicode_safe],
            }
        )
        return schema

    def get_helpers(self):
        from ckan import model

        def is_azure_user(user_id):
            if not user_id:
                return False
            try:
                user_obj = model.User.get(user_id)
                return user_obj and 'azure_auth' in user_obj.plugin_extras
            except Exception:
                return False

        def get_attrib(key):
            if key not in RENDERABLE_ATTRS:
                raise NotAuthorized('Attribute is not accessible')
            return get_action('config_option_show')({'ignore_auth': True}, {'key': key})

        try:
            adfs_authentication_endpoint_error = ''
            adfs_authentication_endpoint = b2c_config.build_authorization_endpoint()
        except RuntimeError as err:
            log.critical(err)
            adfs_authentication_endpoint = False
            adfs_authentication_endpoint_error = str(err)

        return {
            'is_azure_user': is_azure_user,
            'adfs_authentication_endpoint': adfs_authentication_endpoint,
            'adfs_authentication_endpoint_error': adfs_authentication_endpoint_error,
            'adfs_get_attrib': get_attrib,
        }

    def get_blueprint(self):
        return [b2c_auth_blueprint, azure_admin_blueprint]

    # IAuthenticator
    def identify(self):
        user = session.get(f'{ADFS_SESSION_PREFIX}user')
        if user:
            g.user = user

    def login(self):
        pass

    def logout(self):
        if f'{ADFS_SESSION_PREFIX}tokens' in session:
            del session[f'{ADFS_SESSION_PREFIX}tokens']

        keys_to_delete = [
            key for key in session if key.startswith(ADFS_SESSION_PREFIX)
        ]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()

    def abort(self, status_code, detail, headers, comment):
        return status_code, detail, headers, comment

    def authenticate(self, identity):
        return None
