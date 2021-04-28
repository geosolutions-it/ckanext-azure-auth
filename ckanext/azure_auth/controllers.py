'''
Plugin for our ADFS
'''
import base64
import logging

import requests

import ckan.plugins.toolkit as toolkit
from ckan.common import _, g, request, session
from ckan.lib import base, helpers
from ckan.model import State
from ckanext.azure_auth.auth_backend import AdfsAuthBackend
from ckanext.azure_auth.auth_config import ADFS_SESSION_PRREFIX, ProviderConfig
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)
requests.packages.urllib3.add_stderr_logger()


def login_callback():
    '''
    Handles ADGS callback
    received auth code or auth tokens
    '''
    code = request.params.get('code')
    provider_config = ProviderConfig()
    auth_backend = AdfsAuthBackend(provider_config=provider_config)

    try:
        user = auth_backend.authenticate_with_code(authorization_code=code)
    except MFARequiredException:
        return helpers.redirect_to(
            provider_config.build_authorization_endpoint(
                request, force_mfa=True
            )
        )
    except CreateUserException as e:
        log.debug(str(e))
        base.abort(403, str(e))
    except (AzureReloginRequiredException, RuntimeIssueException) as e:
        log.debug(str(e))
        base.abort(403, str(e))
    except Exception as e:
        log.debug(str(e))
        base.abort(400, 'No authorization code was provided.')

    if user:
        if user['state'] == State.ACTIVE:
            g.user = user['name']
            session[f'{ADFS_SESSION_PRREFIX}user'] = user['name']
            session.save()

            # Redirect to the "after login" page.
            # Because we got redirected from ADFS, we can't know where the
            # user came from.

            redirect_to = request.params.get('state')
            if redirect_to:
                redirect_to = base64.urlsafe_b64decode(
                    redirect_to.encode()
                ).decode()
            else:
                toolkit.redirect_to(controller='user', action='dashboard')

            # TODO: validate URL
            return toolkit.redirect_to(redirect_to)
        else:
            # Return a 'disabled account' error message
            base.abort(403, 'Your account is disabled.')
    else:
        # Return an 'invalid login' error message
        base.abort(401, 'Login failed.')
