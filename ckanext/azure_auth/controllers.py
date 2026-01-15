'''
Plugin for ADFS and B2C authentication
'''
import base64
import logging

import requests

import ckan.plugins.toolkit as toolkit
from ckan.common import _, g, request, session
from ckan.common import config
from ckan.lib import base, helpers
from ckan.model import State
from ckanext.azure_auth.auth_backend import AdfsAuthBackend
from ckanext.azure_auth.auth_config import (
    ADFS_SESSION_PREFIX, 
    ProviderConfig, 
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
    """
    Handle login callback for both Azure B2C (implicit flow) and classic ADFS (authorization code flow).
    """

    tenant_id = config.get('ckanext.azure_auth.tenant_id')

    import pdb; pdb.set_trace()

    # B2C implicit flow
    if tenant_id and tenant_id != 'adfs':
        # Just render the page with JS that posts id_token to /azure/token
        return base.render('user/get_token.html')

    # Classic ADFS code flow
    code = request.params.get('code')
    if not code:
        # No code received, nothing to do
        log.debug('No authorization code received for ADFS login')
        base.abort(401, _('Login failed or account disabled'))

    # Load ADFS backend
    provider = ProviderConfig()
    auth_backend = AdfsAuthBackend(provider_config=provider)
    provider.load_config()

    try:
        user = auth_backend.authenticate_with_code(code)
    except MFARequiredException:
        return toolkit.redirect(provider.build_authorization_endpoint())
    except CreateUserException as e:
        base.abort(403, str(e))
    except Exception as e:
        base.abort(400, str(e))

    if user and user.get('state') == State.ACTIVE:
        g.user = user['name']
        session[f'{ADFS_SESSION_PREFIX}user'] = user['name']
        session.save()

        # Decode state safely
        state = request.params.get('state')
        if state:
            try:
                redirect_to = base64.urlsafe_b64decode(state.encode()).decode()
                return toolkit.redirect_to(redirect_to)
            except Exception:
                log.exception('Failed to decode state parameter')
                return toolkit.redirect_to(controller='user', action='dashboard')
        else:
            return toolkit.redirect_to(controller='user', action='dashboard')
    else:
        base.abort(401, _('Login failed or account disabled'))