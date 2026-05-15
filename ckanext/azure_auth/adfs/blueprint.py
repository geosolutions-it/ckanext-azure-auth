# encoding: utf-8
"""
Flask blueprint for ADFS / Azure AD authorization-code flow.
"""
import base64
import logging
from functools import partial

from flask import Blueprint, request, session

from ckan.lib import base, helpers
from ckan.common import config, g, _
from ckan.logic import get_action
from ckan.model import State
import ckan.model as model
from ckan import logic
import ckan.plugins.toolkit as toolkit

from ckanext.azure_auth.adfs.backend import AdfsAuthBackend
from ckanext.azure_auth.adfs.config import AdfsProviderConfig
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_LOGIN_LABEL,
    ATTR_LOGIN_BUTTON,
    DEFAULT_CALLBACK_PATH,
)
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Admin blueprint (shared with B2C — but registered by whichever plugin is
# active; we define it here and re-export it so both plugins can import it).
# ---------------------------------------------------------------------------

azure_admin_blueprint = Blueprint('azure_admin', __name__)


@azure_admin_blueprint.before_request
def check_for_sysadmin():
    try:
        context = dict(model=model, user=g.user, auth_user_obj=g.userobj)
        logic.check_access('sysadmin', context)
    except logic.NotAuthorized:
        base.abort(403, _('Need to be system administrator to administer'))


@azure_admin_blueprint.route('/ckan-admin/azure_auth', methods=['POST', 'GET'])
def azure_auth_config():
    configurable_keys = (ATTR_LOGIN_LABEL, ATTR_LOGIN_BUTTON,)

    if request.method == "POST":
        values = {k: request.values.get(k) for k in configurable_keys if k in request.values}
        get_action('config_option_update')({}, values)

    elif request.method == "GET":
        get = partial(get_action('config_option_show'), {})
        values = {k: get({'key': k}) for k in configurable_keys}
        values = {k: values[k] for k in configurable_keys if values[k]}

    return base.render(
        'admin/azure_auth_config.html',
        extra_vars={
            'data': values,
            'errors': {},
            'title': 'ADFS configuration',
        }
    )


# ---------------------------------------------------------------------------
# ADFS auth blueprint
# ---------------------------------------------------------------------------

adfs_auth_blueprint = Blueprint('azure_auth', __name__)


@adfs_auth_blueprint.route('/user/_logout')
def logout():
    toolkit.logout_user()
    return toolkit.redirect_to('/')


def login_callback():
    """Handle the OAuth2 authorization-code callback from ADFS / Azure AD."""
    code = request.params.get('code')
    provider_config = AdfsProviderConfig(config)
    auth_backend = AdfsAuthBackend(provider_config=provider_config)

    try:
        user = auth_backend.authenticate_with_code(authorization_code=code)
    except MFARequiredException:
        return helpers.redirect_to(
            provider_config.build_authorization_endpoint()
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
            session[f'{ADFS_SESSION_PREFIX}user'] = user['name']
            session.save()

            redirect_to = request.params.get('state')
            if redirect_to:
                redirect_to = base64.urlsafe_b64decode(
                    redirect_to.encode()
                ).decode()
            else:
                toolkit.redirect_to(controller='user', action='dashboard')

            return toolkit.redirect_to(redirect_to)
        else:
            base.abort(403, 'Your account is disabled.')
    else:
        base.abort(401, 'Login failed.')


adfs_auth_blueprint.add_url_rule(
    rule=config.get(ATTR_AUTH_CALLBACK_PATH, DEFAULT_CALLBACK_PATH),
    view_func=login_callback
)
