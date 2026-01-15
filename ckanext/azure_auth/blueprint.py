# encoding: utf-8
from functools import partial
import logging

from flask import Blueprint, request, session
from ckan.plugins import toolkit

from ckan import logic
from ckan.common import config, g, _
import ckan.lib.base as base
import ckan.lib.helpers as helpers
from ckan.logic import get_action
import ckan.model as model

import ckanext.azure_auth.controllers as controllers
from ckanext.azure_auth.auth_config import (
    ATTR_AUTH_CALLBACK_PATH,
    ATTR_LOGIN_LABEL,
    ATTR_LOGIN_BUTTON,
)
from ckanext.azure_auth.auth_backend import B2CAuthBackend
from ckanext.azure_auth.auth_config import B2CProviderConfig

# Initialize logger
log = logging.getLogger(__name__)

azure_admin_blueprint = Blueprint(u'azure_admin', __name__)


def build_extra_admin_nav():
    u'''Return results of helpers.build_extra_admin_nav for testing.'''
    return helpers.build_extra_admin_nav()

def get_auth_backend():
    tenant_id = config.get('ckanext.azure_auth.tenant_id')
    client_id = config.get('ckanext.azure_auth.client_id')
    service_domain = config.get('ckanext.azure_auth.service_domain')
    policy = config.get('ckanext.azure_auth.policy')
    redirect_uri = config.get('ckanext.azure_auth.redirect_uri')

    provider_config = B2CProviderConfig(
        service_domain=service_domain,
        tenant_id=tenant_id,
        policy=policy,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )

    provider_config.load_config()

    return B2CAuthBackend(provider_config=provider_config)


azure_admin_blueprint.add_url_rule(
    u'/build_extra_admin_nav',
    view_func=build_extra_admin_nav
)


@azure_admin_blueprint.before_request
def check_for_sysadmin():
    try:
        context = dict(model=model, user=g.user, auth_user_obj=g.userobj)
        logic.check_access(u'sysadmin', context)
    except logic.NotAuthorized:
        base.abort(403, _(u'Need to be system administrator to administer'))


@azure_admin_blueprint.route(u'/ckan-admin/azure_auth', methods=['POST', 'GET'])
def azure_auth_config():
    configurable_keys = (ATTR_LOGIN_LABEL, ATTR_LOGIN_BUTTON, )

    if request.method == "POST":
        values = {k: request.values.get(k) for k in configurable_keys if k in request.values}
        get_action('config_option_update')({}, values)

    elif request.method == "GET":
        get = partial(get_action('config_option_show'), {})
        values = {k: get({'key': k}) for k in configurable_keys}
        values = {k: values[k] for k in configurable_keys if values[k]}

    return base.render(
        u'admin/azure_auth_config.html',
        extra_vars={
            'data': values,
            'errors': {},
            'title': u'ADFS configuration'}
    )

azure_auth_blueprint = Blueprint(u'azure_auth', __name__)

@azure_auth_blueprint.route('/azure/token', methods=['POST'])
def token_login():
    data = request.get_json()
    id_token = data.get('id_token')
    
    try:
        auth_backend = get_auth_backend()
        user_dict = auth_backend.process_access_token(id_token)
        
        user_obj = model.User.get(user_dict['name'])
        
        if not user_obj:
            return "User not found in CKAN database", 404
            
        toolkit.login_user(user_obj)
        
        return "", 200
    except Exception as e:
        log.exception("Failed to process id_token")
        return str(e), 400

azure_auth_blueprint.add_url_rule(
    rule=config[ATTR_AUTH_CALLBACK_PATH],
    view_func=controllers.login_callback
)
