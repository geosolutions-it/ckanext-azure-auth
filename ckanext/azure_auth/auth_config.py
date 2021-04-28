import base64
import logging
from datetime import datetime, timedelta
from urllib.parse import urlencode
from xml.etree import ElementTree

import requests
import requests.adapters
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.x509 import load_der_x509_certificate
from urllib3.util.retry import Retry

from ckan.common import asbool, config
from ckanext.azure_auth.exceptions import ConfigLoadErrorException

_EXTNAME = 'ckanext.azure_auth'

AZURE_AD_SERVER_URL = 'https://login.microsoftonline.com'

AUTH_SERVICE = 'adfs'
ADFS_SESSION_PREFIX = 'adfs-'

# Config keys
ATTR_AD_SERVER = f'{_EXTNAME}.ad_server'
ATTR_WT_REALM = f'{_EXTNAME}.wtrealm'
ATTR_METADATA_URL = f'{_EXTNAME}.metadata_url'
ATTR_HELP_TEXT = f'{_EXTNAME}.login_help_text'
ATTR_AUTH_CALLBACK_PATH = f'{_EXTNAME}.auth_callback_path'
ATTR_TENANT_ID = f'{_EXTNAME}.tenant_id'
ATTR_CLIENT_ID = f'{_EXTNAME}.client_id'
ATTR_ADSF_AUDIENCE = f'{_EXTNAME}.audience'
ATTR_CLIENT_SECRET = f'{_EXTNAME}.client_secret'
ATTR_FORCE_MFA = f'{_EXTNAME}.force_mfa'
ATTR_DISABLE_SSO = f'{_EXTNAME}.disable_sso'

# Config keys: Configured at runtime
ATTR_REDIRECT_URL = f'{_EXTNAME}.redirect_uri'
ADFS_CREATE_USER = f'{_EXTNAME}.allow_create_users'

XML_CERT_SECTIONS = (
    './{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor'
    "[@{http://www.w3.org/2001/XMLSchema-instance}type='fed:SecurityTokenServiceType']"
    "/{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor[@use='signing']"
    '/{http://www.w3.org/2000/09/xmldsig#}KeyInfo'
    '/{http://www.w3.org/2000/09/xmldsig#}X509Data'
    '/{http://www.w3.org/2000/09/xmldsig#}X509Certificate'
)

log = logging.getLogger(__name__)

# TODO: get from the settings
TIMEOUT = 120


class ProviderConfig(object):
    _config_timestamp = None
    _mode = None

    authorization_endpoint = None
    signing_keys = None
    token_endpoint = None
    end_session_endpoint = None
    issuer = None

    # http_session
    session = None

    def __init__(self):
        method_whitelist = frozenset(
            ['HEAD', 'GET', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'POST']
        )
        retries = config[f'{_EXTNAME}.retry']
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=0.3,
            method_whitelist=method_whitelist,
        )

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=retry)
        self.session.mount('https://', adapter)
        self.session.verify = config[f'{_EXTNAME}.ca_bundle']

    def load_config(self):
        # If loaded data is too old, reload it again
        refresh_time = datetime.now() - timedelta(
            hours=config[f'{_EXTNAME}.config_reload_interval']
        )
        if (
            self._config_timestamp is None
            or self._config_timestamp < refresh_time
        ):
            log.debug('Loading ADFS ID Provider configuration.')
            try:
                # skipped
                # raise ConfigLoadErrorException()
                loaded = self._load_openid_config()
                self._mode = 'openid_connect'
            except ConfigLoadErrorException:
                loaded = self._load_federation_metadata()
                self._mode = 'oauth2'

            if not loaded:
                if self._config_timestamp is None:
                    msg = (
                        'Could not load any data from ADFS server. '
                        'Authentication against ADFS is not possible. '
                    )
                    log.critical(msg)
                    raise RuntimeError(msg)
                else:
                    # We got data from the previous time. Log a message, but
                    # don't abort.
                    log.warning(
                        'Could not load any data from ADFS server.'
                        ' Keeping previous configurations'
                    )
            self._config_timestamp = datetime.now()

            log.info('Loaded settings from ADFS server.')
            log.info('operating mode:         %s', self._mode)
            log.info('authorization endpoint: %s', self.authorization_endpoint)
            log.info('token endpoint:         %s', self.token_endpoint)
            log.info('end session endpoint:   %s', self.end_session_endpoint)
            log.info('issuer:                 %s', self.issuer)

    def _load_openid_config(self):
        config_url = '{}/{}/.well-known/openid-configuration?appid={}'.format(
            config[ATTR_AD_SERVER],
            config[ATTR_TENANT_ID],
            config[ATTR_CLIENT_ID],
        )

        try:
            log.info('Trying to get OpenID Connect config from %s', config_url)
            response = self.session.get(config_url, timeout=TIMEOUT)
            response.raise_for_status()
            openid_cfg = response.json()

            response = self.session.get(
                openid_cfg['jwks_uri'], timeout=TIMEOUT
            )
            response.raise_for_status()
            signing_certificates = [
                x['x5c'][0]
                for x in response.json()['keys']
                if x.get('use', 'sig') == 'sig'
            ]
            #                               ^^^
            # https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.7
            # The PKIX certificate containing the key value MUST be the first
            # certificate
        except requests.HTTPError:
            raise ConfigLoadErrorException

        self._load_keys(signing_certificates)
        try:
            self.authorization_endpoint = openid_cfg['authorization_endpoint']
            self.token_endpoint = openid_cfg['token_endpoint']
            self.end_session_endpoint = openid_cfg['end_session_endpoint']
            if config[ATTR_TENANT_ID] != 'adfs':
                self.issuer = openid_cfg['issuer']
            else:
                self.issuer = openid_cfg['access_token_issuer']
        except KeyError:
            raise ConfigLoadErrorException
        return True

    def _load_federation_metadata(self):
        server_url = config[ATTR_AD_SERVER]
        base_url = '{}/{}'.format(server_url, config[ATTR_TENANT_ID])
        if config[ATTR_TENANT_ID] == 'adfs':
            adfs_config_url = (
                f'{server_url}/FederationMetadata/2007-06/FederationMetadata.xml'
            )
        else:
            adfs_config_url = (
                f'{base_url}/FederationMetadata/2007-06/FederationMetadata.xml'
            )

        try:
            log.info(f'Trying to get ADFS Metadata file {adfs_config_url}')
            response = self.session.get(adfs_config_url, timeout=TIMEOUT)
            response.raise_for_status()
        except requests.HTTPError:
            raise ConfigLoadErrorException

        # Extract token signing certificates
        xml_tree = ElementTree.fromstring(response.content)
        cert_nodes = xml_tree.findall(XML_CERT_SECTIONS)
        signing_certificates = [node.text for node in cert_nodes]

        self._load_keys(signing_certificates)
        self.issuer = xml_tree.get('entityID')
        self.authorization_endpoint = f'{base_url}/oauth2/authorize'
        self.token_endpoint = f'{base_url}/oauth2/token'
        self.end_session_endpoint = f'{base_url}/ls/?wa=wsignout1.0'
        return True

    def _load_keys(self, certificates):
        new_keys = []
        for cert in certificates:
            log.debug(f'Loading public key from certificate: {cert}')
            cert_obj = load_der_x509_certificate(
                base64.b64decode(cert), backend
            )
            new_keys.append(cert_obj.public_key())
        self.signing_keys = new_keys

    def build_authorization_endpoint(self):
        '''
        This function returns the ADFS authorization URL.

        Args:
            request(django.http.request.HttpRequest): A django Request object

        Returns:
            str: The redirect URI

        '''
        self.load_config()
        redirect_to = '/'
        redirect_to = base64.urlsafe_b64encode(redirect_to.encode()).decode()
        query = {}
        query.update(
            {
                'response_type': 'code',
                'client_id': config[ATTR_CLIENT_ID],
                'redirect_uri': config[ATTR_REDIRECT_URL],
                'state': redirect_to,
            }
        )

        if self._mode == 'openid_connect':
            query['scope'] = 'openid'
            if asbool(config[ATTR_DISABLE_SSO]):
                query['prompt'] = 'login'
            if asbool(config[ATTR_FORCE_MFA]):
                query['amr_values'] = 'ngcmfa'
        return '{0}?{1}'.format(self.authorization_endpoint, urlencode(query))

    def build_end_session_endpoint(self):
        '''
        This function returns the ADFS end session URL to log a user out.

        Returns:
            str: The redirect URI

        '''
        self.load_config()
        return self.end_session_endpoint
