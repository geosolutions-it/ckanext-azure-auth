import logging

import requests
from flask import Blueprint

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import _, config, g, session
from ckan.exceptions import CkanConfigurationException
from ckanext.azure_auth import controllers
from ckanext.azure_auth.auth_config import (
    ADFS_CREATE_USER,
    ADFS_SESSION_PREFIX,
    ATTR_ADSF_AUDIENCE,
    ATTR_AD_SERVER,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_CLIENT_ID,
    ATTR_CLIENT_SECRET,
    ATTR_DISABLE_SSO,
    ATTR_FORCE_MFA,
    ATTR_HELP_TEXT,
    ATTR_METADATA_URL,
    ATTR_REDIRECT_URL,
    ATTR_TENANT_ID,
    ATTR_WT_REALM,
    AZURE_AD_SERVER_URL,
    ProviderConfig,
)

log = logging.getLogger(__name__)
requests.packages.urllib3.add_stderr_logger()


class AzureAuthPlugin(plugins.SingletonPlugin):
    '''
    Microsoft Azure auth service connector
    '''

    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        '''
        Add our templates to CKAN's search path
        '''
        toolkit.add_template_directory(config, 'templates')

        if ATTR_TENANT_ID in config:
            # If a tenant ID was set, switch to Azure AD mode
            if ATTR_AD_SERVER in config:
                msg = f'The {ATTR_AD_SERVER} should not be set when {ATTR_TENANT_ID} is set.'
                raise CkanConfigurationException(msg)
            config[ATTR_AD_SERVER] = AZURE_AD_SERVER_URL

        # Validate required settings
        if not config[ATTR_TENANT_ID] and not config[ATTR_AD_SERVER]:
            msg = f'Exactly one of the settings {ATTR_TENANT_ID} or {ATTR_AD_SERVER} must be set'
            raise CkanConfigurationException(msg)
        elif config[ATTR_TENANT_ID] is None:
            # For on premises ADFS, the tenant ID is set to adfs
            # On AzureAD the adfs part in the URL happens to be replace by the tenant ID.
            config[ATTR_TENANT_ID] = 'adfs'

        # Set plugin defaults
        azure_auth_plugin_defaults = (
            (ATTR_METADATA_URL, 'https://login.microsoftonline.com/'),
            (ATTR_AUTH_CALLBACK_PATH, '/oauth2/callback'),
            (ATTR_REDIRECT_URL, config['ckan.site_url'] + config[ATTR_AUTH_CALLBACK_PATH]),
            (ATTR_FORCE_MFA, False),
            (ATTR_DISABLE_SSO, False),
            ('ckanext.azure_auth.config_reload_interval', 24),  # in hours
            ('ckanext.azure_auth.ca_bundle', True),
            ('ckanext.azure_auth.retry', 5),
            ('ckanext.azure_auth.jwt_leeway', 0),
        )
        for k, d in azure_auth_plugin_defaults:
            config.setdefault(k, d)

    def update_config_schema(self, schema):
        not_empty = toolkit.get_validator('not_empty')
        unicode_safe = toolkit.get_validator('unicode_safe')
        ignore_missing = toolkit.get_validator('ignore_missing')
        boolean_validator = toolkit.get_validator('boolean_validator')

        schema.update(
            {
                ATTR_WT_REALM: [not_empty, unicode_safe],
                ATTR_METADATA_URL: [not_empty, unicode_safe],
                ATTR_HELP_TEXT: [ignore_missing, unicode_safe],
                ATTR_REDIRECT_URL: [not_empty, unicode_safe],
                ATTR_TENANT_ID: [not_empty, unicode_safe],
                ATTR_CLIENT_ID: [not_empty, unicode_safe],
                ATTR_CLIENT_SECRET: [not_empty, unicode_safe],
                ATTR_FORCE_MFA: [ignore_missing, boolean_validator],
                ATTR_DISABLE_SSO: [ignore_missing, boolean_validator],
                ATTR_AD_SERVER: [ignore_missing, unicode_safe],
                ADFS_CREATE_USER: [not_empty, boolean_validator],
                ATTR_ADSF_AUDIENCE: [not_empty, unicode_safe],
            }
        )
        return schema

    def get_helpers(self):
        def is_adfs_user():
            return bool(session.get(f'{ADFS_SESSION_PREFIX}user'))
        try:
            provider_config = ProviderConfig()
            adfs_authentication_endpoint_error = ''
            adfs_authentication_endpoint = (
                provider_config.build_authorization_endpoint()
            )
        except RuntimeError as err:
            log.critical(err)
            adfs_authentication_endpoint = False
            adfs_authentication_endpoint_error = str(err)
        return dict(
            is_adfs_user=is_adfs_user,
            adfs_authentication_endpoint=adfs_authentication_endpoint,
            adfs_authentication_endpoint_error=adfs_authentication_endpoint_error,
            adfs_sign_in_btn=_('{} Sign In').format(
                config.get('ckan.site_title')
            ),
        )

    def get_blueprint(self):
        '''Return a Flask Blueprint object to be registered by the app.'''
        blueprint = Blueprint(self.name, self.__module__)
        blueprint.template_folder = 'templates'
        blueprint.add_url_rule(
            rule=config[ATTR_AUTH_CALLBACK_PATH],
            endpoint='login',
            view_func=controllers.login_callback,
        )
        return blueprint

    def identify(self):
        '''
        Called to identify the user.
        '''
        user = session.get(f'{ADFS_SESSION_PREFIX}user')
        if user:
            g.user = user

    def login(self):
        '''
        Called at login.
        '''
        pass

    def logout(self):
        '''
        Called at logout.
        '''
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
        '''
        Called on abort.  This allows aborts due to authorization issues
        to be overriden.
        '''
        return status_code, detail, headers, comment
