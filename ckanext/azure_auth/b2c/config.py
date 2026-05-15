"""
Azure B2C provider configuration.
"""
import base64
import logging
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode

import requests

from ckan.common import config
from ckanext.azure_auth.base.config import BaseProviderConfig
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_SPIDL
)

log = logging.getLogger(__name__)


class OIDCDiscoverCfg:
    def __init__(self, authorization_endpoint, token_endpoint, end_session_endpoint, issuer, jwks_uri):
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.end_session_endpoint = end_session_endpoint
        self.issuer = issuer
        self.jwks_uri = jwks_uri


class B2CProviderConfig(BaseProviderConfig):
    def __init__(self, ckan_config):
        super().__init__(ckan_config)

        self.spidl = ckan_config.get(ATTR_SPIDL, '2')

        self.oidc_config = None
        self.last_load = None

    def get_remote_config(self):
        log.debug("Request loading of Azure B2C configuration")

        datetime_now = datetime.now()
        if self.last_load and (datetime_now - self.last_load) < timedelta(minutes=5):
            log.debug("Skipping loading of Azure B2C configuration (last load is %s)", self.last_load)
            return self.oidc_config  # return cached config

        config_url = (
            f"https://{self.service_domain}/"
            f"{self.tenant_id}/v2.0/.well-known/openid-configuration?p={self.policy}"
        )
        log.debug("Loading Azure B2C configuration - URL: %s -- Last load %s", config_url, self.last_load)

        session = requests.Session()
        resp = session.get(config_url, timeout=120)
        resp.raise_for_status()
        cfg = resp.json()

        log.debug("Received Azure B2C configuration: %s", cfg)

        self.oidc_config = OIDCDiscoverCfg(
            authorization_endpoint=cfg['authorization_endpoint'],
            token_endpoint=cfg['token_endpoint'],
            end_session_endpoint=cfg['end_session_endpoint'],
            issuer=cfg['issuer'],
            jwks_uri=cfg['jwks_uri'])

        # reset the timer
        self.last_load = datetime_now
        return self.oidc_config

    def build_authorization_endpoint(self, redirect_to_path='/'):
        """Build the authorization URL for B2C login."""
        oidc_cfg = self.get_remote_config()

        state = base64.urlsafe_b64encode(redirect_to_path.encode()).decode()

        query = {
            'client_id': self.client_id,
            'redirect_uri': self.get_redirect_url(),
            'response_type': self.response_type,
            'scope': self.scope,
            'state': state,
            'prompt': 'login',
        }
        if self.service_id:
            query['serviceId'] = self.service_id

        from flask import has_request_context, session

        if has_request_context():
            nonce = secrets.token_urlsafe(16)
            session[f"{ADFS_SESSION_PREFIX}nonce"] = nonce
        else:
            nonce = 'defaultNonce'

        query['nonce'] = nonce

        if self.spidl:
            query['spidl'] = self.spidl

        url = f"{oidc_cfg.authorization_endpoint}&{urlencode(query)}"
        log.info(f"B2C authorization URL: {url}")
        return url

    def build_logout_endpoint(self):
        """Construct the B2C logout URL dynamically."""
        params = {
            'post_logout_redirect_uri': config.get('ckan.site_url').rstrip('/')
        }

        from flask import session as flask_session
        id_token = flask_session.get(f'{ADFS_SESSION_PREFIX}id_token')
        if id_token:
            params['id_token_hint'] = id_token

        oidc_cfg = self.get_remote_config()
        separator = '&' if '?' in oidc_cfg.end_session_endpoint else '?'
        return f"{oidc_cfg.end_session_endpoint}{separator}{urlencode(params)}"


b2c_config = B2CProviderConfig(config)
