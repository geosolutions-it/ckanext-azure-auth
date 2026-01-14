'''
Plugin for ADFS authentication
'''
import base64
import logging

import requests

import ckan.plugins.toolkit as toolkit
from ckan.common import _, g, request, session
from ckan.common import config as ckan_config
from ckan.lib import base, helpers
from ckan.model import State
from ckanext.azure_auth.auth_backend import AdfsAuthBackend, B2CAuthBackend
from ckanext.azure_auth.auth_config import (
    ADFS_SESSION_PREFIX, 
    ProviderConfig, 
    B2CProviderConfig
)
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)
requests.packages.urllib3.add_stderr_logger()


def login_callback():
    code = request.params.get('code')
    state = request.params.get('state')

    tenant_id = ckan_config.get('ckanext.azure_auth.tenant_id')
    client_id = ckan_config.get('ckanext.azure_auth.client_id')

    if tenant_id and tenant_id != 'adfs':
        # Azure B2C mode
        service_domain = ckan_config.get('ckanext.azure_auth.service_domain')
        policy = ckan_config.get('ckanext.azure_auth.policy')
        redirect_uri = ckan_config.get('ckanext.azure_auth.redirect_uri')
        provider = B2CProviderConfig(
            service_domain=service_domain,
            tenant_id=tenant_id,
            policy=policy,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )

        auth_backend = B2CAuthBackend(provider_config=provider)
    else:
        # Classic ADFS
        provider = ProviderConfig()
        auth_backend = AdfsAuthBackend(provider_config=provider)

    provider.load_config()

    try:
        user = auth_backend.authenticate_with_code(authorization_code=code)
    except MFARequiredException:
        return toolkit.redirect(provider.build_authorization_endpoint())
    except CreateUserException as e:
        base.abort(403, str(e))
    except Exception as e:
        base.abort(400, str(e))

    if user and user['state'] == State.ACTIVE:
        g.user = user['name']
        session[f'{ADFS_SESSION_PREFIX}user'] = user['name']
        session.save()

        # Decode state safely
        if state:
            redirect_to = base64.urlsafe_b64decode(state.encode()).decode()
            return toolkit.redirect_to(redirect_to)
        else:
            return toolkit.redirect_to(controller='user', action='dashboard')
    else:
        base.abort(401, 'Login failed or account disabled')