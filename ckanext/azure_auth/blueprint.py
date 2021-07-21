# encoding: utf-8
from functools import partial

from flask import Blueprint, request

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

azure_admin_blueprint = Blueprint(u'azure_admin', __name__)


def build_extra_admin_nav():
    u'''Return results of helpers.build_extra_admin_nav for testing.'''
    return helpers.build_extra_admin_nav()


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

azure_auth_blueprint.add_url_rule(
    rule=config[ATTR_AUTH_CALLBACK_PATH],
    view_func=controllers.login_callback
)
