# encoding: utf-8
"""
Flask blueprint for Azure B2C implicit (id_token) flow.
"""
import logging
from functools import partial

from flask import Blueprint, request, session
from ckan.lib.helpers import flash_error

from ckan.lib import base
from ckan.common import config, g, _
from ckan.logic import get_action
import ckan.model as model
from ckan import logic
import ckan.plugins.toolkit as toolkit

from ckanext.azure_auth.b2c.backend import B2CAuthBackend
from ckanext.azure_auth.b2c.config import B2CProviderConfig
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_CLIENT_ID,
    ATTR_LOGIN_BUTTON,
    ATTR_LOGIN_LABEL,
    ATTR_POLICY,
    ATTR_REDIRECT_URL,
    ATTR_SERVICE_DOMAIN,
    ATTR_SERVICE_ID,
    ATTR_SPIDL,
    ATTR_TENANT_ID,
)
from ckanext.azure_auth.exceptions import CreateUserException

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Admin blueprint
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
            'title': 'Azure B2C configuration',
        }
    )


# ---------------------------------------------------------------------------
# B2C auth blueprint
# ---------------------------------------------------------------------------

b2c_auth_blueprint = Blueprint('azure_auth', __name__)


def _get_auth_backend():
    provider_config = B2CProviderConfig(
        service_domain=config.get(ATTR_SERVICE_DOMAIN),
        service_id=config.get(ATTR_SERVICE_ID),
        tenant_id=config.get(ATTR_TENANT_ID),
        policy=config.get(ATTR_POLICY),
        client_id=config.get(ATTR_CLIENT_ID),
        redirect_uri=config.get(ATTR_REDIRECT_URL),
        spidl=config.get(ATTR_SPIDL),
    )
    provider_config.load_config()
    return B2CAuthBackend(provider_config=provider_config)


@b2c_auth_blueprint.route('/azure/login', methods=['POST'], endpoint='login')
def token_login():
    try:
        id_token = request.form.get('id_token')
        if not id_token:
            flash_error("No token found")
            return base.render("user/login.html")

        user_dict = _get_auth_backend().process_access_token(id_token)

        user_obj = model.User.get(user_dict['name'])
        if not user_obj:
            flash_error("User not found")
            return base.render("user/login.html")

        toolkit.login_user(user_obj)

        session[f'{ADFS_SESSION_PREFIX}user'] = user_dict['name']
        session.save()

        return toolkit.redirect_to('/')

    except Exception as e:
        user_msg = str(e)
        log.exception(f"Azure Login process failed: {user_msg}")
        flash_error(user_msg)
        return base.render("user/login.html", {})


@b2c_auth_blueprint.route('/user/_logout')
def logout():
    userobj = getattr(g, 'userobj', None)

    if userobj and userobj.name.startswith(('adfs-', 'b2c-')):
        log.info(f"Azure logout for {userobj.name}")
        toolkit.logout_user()
        backend = _get_auth_backend()
        azure_logout_url = backend.provider_config.build_logout_endpoint()
        return toolkit.redirect_to(azure_logout_url)

    toolkit.logout_user()
    return toolkit.redirect_to('/')


def login_callback():
    """B2C implicit flow: render the page that posts the id_token to /azure/login."""
    return base.render('user/get_token.html')


b2c_auth_blueprint.add_url_rule(
    rule=config[ATTR_AUTH_CALLBACK_PATH],
    view_func=login_callback
)
