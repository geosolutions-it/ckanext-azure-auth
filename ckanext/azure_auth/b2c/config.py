"""
Azure B2C (MyIdentity) provider configuration.
"""
import base64
import logging
import secrets
from urllib.parse import urlencode

import requests

from ckan.common import config
from ckanext.azure_auth.base.config import BaseProviderConfig
from ckanext.azure_auth.constants import ADFS_SESSION_PREFIX

log = logging.getLogger(__name__)


class B2CProviderConfig(BaseProviderConfig):
    def __init__(self, service_domain, service_id, tenant_id, policy, client_id, redirect_uri, spidl='2'):
        self.service_domain = service_domain
        self.service_id = service_id
        self.tenant_id = tenant_id
        self.policy = policy
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.spidl = spidl
        self.session = requests.Session()

        self.authorization_endpoint = None
        self.token_endpoint = None
        self.end_session_endpoint = None
        self.issuer = None
        self.jwks_uri = None

    def load_config(self):
        """Load OpenID Connect configuration from Azure B2C (MyIdentity)."""
        config_url = (
            f"https://{self.service_domain}/"
            f"{self.tenant_id}/v2.0/.well-known/openid-configuration?p={self.policy}"
        )

        resp = self.session.get(config_url, timeout=120)
        resp.raise_for_status()
        cfg = resp.json()

        self.authorization_endpoint = cfg['authorization_endpoint']
        self.token_endpoint = cfg['token_endpoint']
        self.end_session_endpoint = cfg.get('end_session_endpoint')
        self.issuer = cfg['issuer']
        self.jwks_uri = cfg['jwks_uri']

    def build_authorization_endpoint(self, redirect_to_path='/'):
        """Build the authorization URL for B2C login."""
        self.load_config()

        state = base64.urlsafe_b64encode(redirect_to_path.encode()).decode()

        query = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'id_token',
            'scope': 'openid',
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

        url = f"{self.authorization_endpoint}&{urlencode(query)}"
        log.info(f"B2C authorization URL: {url}")
        return url

    def build_logout_endpoint(self):
        """Construct the B2C logout URL dynamically."""
        if not self.end_session_endpoint:
            self.load_config()

        post_logout_uri = config.get('ckan.site_url').rstrip('/')

        params = {
            'post_logout_redirect_uri': post_logout_uri
        }

        from flask import session as flask_session
        id_token = flask_session.get(f'{ADFS_SESSION_PREFIX}id_token')
        if id_token:
            params['id_token_hint'] = id_token

        separator = '&' if '?' in self.end_session_endpoint else '?'
        return f"{self.end_session_endpoint}{separator}{urlencode(params)}"
