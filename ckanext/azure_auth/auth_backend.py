import logging
import uuid

import jwt

from ckan.common import _, config, session
from ckan.logic import NotFound
from ckan.plugins import toolkit
from ckanext.azure_auth.auth_config import (
    ADFS_CREATE_USER,
    ADFS_SESSION_PREFIX,
    ATTR_ADSF_AUDIENCE,
    ATTR_CLIENT_ID,
    ATTR_CLIENT_SECRET,
    ATTR_REDIRECT_URL,
    AUTH_SERVICE,
    TIMEOUT,
    ProviderConfig,
)
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)


class AdfsAuthBackend(object):
    provider_config: ProviderConfig

    def __init__(self, provider_config):
        self.provider_config = provider_config

    def exchange_auth_code(self, authorization_code):
        log.debug('Received authorization code: %s', authorization_code)
        data = {
            'grant_type': 'authorization_code',
            'client_id': config[ATTR_CLIENT_ID],
            'redirect_uri': config[ATTR_REDIRECT_URL],
            'code': authorization_code,
        }
        if config[ATTR_CLIENT_SECRET]:
            data['client_secret'] = config[ATTR_CLIENT_SECRET]

        log.debug(
            'Getting access token at: %s', self.provider_config.token_endpoint
        )
        response = self.provider_config.session.post(
            self.provider_config.token_endpoint, data, timeout=TIMEOUT
        )
        # 200 = valid token received
        # 400 = 'something' is wrong in our request
        if response.status_code == 400:
            error_description = response.json().get('error_description', '')
            if error_description.startswith('AADSTS50076'):
                raise MFARequiredException

            # AADSTS54005 - expired  (TODO: an issue)
            # AADSTS70008 - already provided. Needs relogin
            if error_description.startswith('AADSTS54005') or \
                    error_description.startswith('AADSTS70008'):
                raise AzureReloginRequiredException(
                    _('Please re-sign in on the Microsoft Azure side')
                )
            log.error(f'ADFS server returned an error: {error_description}')
            raise RuntimeIssueException(error_description)

        if response.status_code != 200:
            log.error(
                'Unexpected ADFS response: %s', response.content.decode()
            )
            raise PermissionError

        adfs_response = response.json()
        session[f'{ADFS_SESSION_PREFIX}tokens'] = adfs_response
        session.save()
        return adfs_response

    def validate_access_token(self, access_token):
        for idx, key in enumerate(self.provider_config.signing_keys):
            try:
                # Explicitly define the verification option.
                # The list below is the default the jwt module uses.
                # Explicit is better then implicit and it protects against
                # changes in the defaults the jwt module uses.
                options = {
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_nbf': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True,
                    'require_exp': False,
                    'require_iat': False,
                    'require_nbf': False,
                }
                # Validate token and return claims
                return jwt.decode(
                    access_token,
                    key=key,
                    algorithms=['RS256', 'RS384', 'RS512'],
                    audience=config[ATTR_ADSF_AUDIENCE],
                    issuer=self.provider_config.issuer,
                    options=options,
                    leeway=config['ckanext.azure_auth.jwt_leeway'],
                )
            except jwt.ExpiredSignatureError as error:
                log.info('Signature has expired: {error}')
                raise PermissionError
            except jwt.DecodeError as error:
                # If it's not the last certificate in the list, skip to the
                # next one
                if idx < len(self.provider_config.signing_keys) - 1:
                    continue
                else:
                    log.info(f'Error decoding signature: {error}')
                    raise PermissionError
            except jwt.InvalidTokenError as error:
                log.info(str(error))
                raise PermissionError

    def process_access_token(self, access_token, adfs_response=None):
        if not access_token:
            raise PermissionError

        log.debug(f'Received access token: {access_token}')
        claims = self.validate_access_token(adfs_response['id_token'])
        if not claims:
            raise PermissionError

        user = self.create_user(claims)
        return user

    def create_user(self, claims):
        '''
        Create the user if it doesn't exist yet

        Args:
            claims (dict): claims from the access token

        Returns:
            django.contrib.auth.models.User: A Django user
        '''
        user_id = claims.get("oid")
        if not user_id:
            log.error(
                "User claim's doesn't have the claim '%s' in his claims: %s"
                % ('oid', claims)
            )
            raise PermissionError

        email = claims.get('unique_name')
        ckan_id = f'{AUTH_SERVICE}-{user_id}'

        try:
            user = toolkit.get_action('user_show')(data_dict={'id': ckan_id})
        except NotFound:
            if config[ADFS_CREATE_USER]:
                user = toolkit.get_action('user_create')(
                    context={'ignore_auth': True},
                    data_dict={
                        'id': ckan_id,
                        'name': ckan_id,
                        'fullname': claims['name'],
                        'password': str(uuid.uuid4()),
                        'email': email,
                        'plugin_extras': {
                            'azure_auth':  user_id,
                        }
                    },
                )
                log.debug(f"User with email '{email}' has been created.")
            else:
                msg = (
                    f"User with email '{email}' doesn't exist and creating"
                    f' users is disabled.'
                )
                log.debug(msg)
                raise CreateUserException(msg)
        return user

    def authenticate_with_code(self, authorization_code=None, **kwargs):
        '''
        Authentication backend to allow authenticating users against a
        Microsoft ADFS server with an authorization code.

        :param authorization_code:
        :param kwargs:
        :return:
        '''
        self.provider_config.load_config()

        # If there's no token or code, we pass control to the next
        # authentication backend
        if not bool(authorization_code):
            log.debug('No authorization code was received')
            return

        adfs_response = self.exchange_auth_code(authorization_code)
        access_token = adfs_response['access_token']
        user = self.process_access_token(access_token, adfs_response)
        return user

    def authenticate_with_token(self, access_token=None, **kwargs):
        '''
        Authentication backend to allow authenticating users against a
        Microsoft ADFS server with an access token retrieved by the client.
        :param access_token:
        :param kwargs:
        :return:
        '''
        self.provider_config.load_config()

        # If there's no token or code, we pass control to the next
        # authentication backend
        if not bool(access_token):
            log.debug('No authorization code was received')
            return

        access_token = access_token.decode()
        user = self.process_access_token(access_token)
        return user
