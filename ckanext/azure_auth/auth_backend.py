import logging
import uuid
import re

import jwt
from jwt import decode, PyJWKClient
from jwt.exceptions import InvalidTokenError

from ckan.common import _, config, session, asbool
from ckan.lib.munge import substitute_ascii_equivalents
from ckan.logic import NotFound
from ckan.logic import get_action
from ckan.plugins import toolkit

from ckanext.azure_auth.auth_config import (
    ATTR_CREATE_USER,
    ADFS_SESSION_PREFIX,
    ATTR_ADSF_AUDIENCE,
    ATTR_CLIENT_ID,
    ATTR_CLIENT_SECRET,
    ATTR_REDIRECT_URL,
    ATTR_AUTH_SERVICE,
    ATTR_USER_ID_TEMPLATE,
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
                log.info(f'Signature has expired: {error}')
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

        log.debug(f'Decoded claims: {claims}')
        return self.get_or_create_user(claims)

    def get_or_create_user(self, claims):
        '''
        Create the user if it doesn't exist yet

        Args:
            claims (dict): claims from the access token

        Returns:
            django.contrib.auth.models.User: A Django user
        '''
        # Get the auth service type
        auth_service_type = config.get(ATTR_AUTH_SERVICE)

        user_id = claims.get("oid")
        if not user_id:
            log.error(f"User claim's doesn't have the claim 'oid' in his claims: {claims}")
            raise PermissionError

        email = claims.get('unique_name')
        ckan_id = f'{auth_service_type}-{user_id}'
        username = self.sanitize_username(claims.get('name', ckan_id))
        fullname = f'{claims["given_name"]} {claims["family_name"]}'

        try:
            user = toolkit.get_action('user_show')(data_dict={'id': ckan_id})
            log.debug(f"User found --> {user}")
            dirty = False
            if user['name'] != username:
                # in ckan we cannot update the username, a warning will suffice
                log.warning(f"Username not aligned:  CKAN:[{user['name']}]  ADFS:[{username}]")
            if user['fullname'] != fullname:
                log.info(f"Resetting fullname from [{user['fullname']}] to [{fullname}]")
                user['fullname'] = fullname
                dirty = True
            if dirty:
                # set some fields required when saving
                user['email'] = email
                toolkit.get_action('user_update')(
                    context={'ignore_auth': True},
                    data_dict=user)
        except NotFound:
            if config[ATTR_CREATE_USER]:
                user = toolkit.get_action('user_create')(
                    context={'ignore_auth': True},
                    data_dict={
                        'id': ckan_id,
                        'name': username,
                        'fullname': fullname,
                        'email': email,
                        'plugin_extras': {
                            'azure_auth':  user_id,
                        }
                    },
                )
                log.debug(f"User created --> {user}")
            else:
                msg = (
                    f"User with email '{email}' doesn't exist and creating"
                    f' users is disabled.'
                )
                log.debug(msg)
                raise CreateUserException(msg)
        return user

    @staticmethod
    def sanitize_username(tag: str):
        tag = substitute_ascii_equivalents(tag)
        tag = tag.lower().strip()
        tag = re.sub(r'[^a-zA-Z0-9\- ]', '', tag).replace(' ', '-')
        return tag

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


class B2CAuthBackend(AdfsAuthBackend):
    """
    Authentication backend for Azure B2C (MyIdentity) using implicit flow (id_token).
    Inherits from AdfsAuthBackend to reuse token validation and CKAN user creation.
    """

    def process_access_token(self, id_token):
        """
        Process an Azure B2C id_token directly.
        """
        if not id_token:
            raise PermissionError("No id_token provided")

        log.debug(f'Received id_token: {id_token}')

        # Validate and decode the token
        claims = self.execute_token_validation(id_token)
        
        if not claims:
            raise PermissionError("Invalid id_token")

        log.debug(f'Decoded claims: {claims}')

        # Get or create CKAN user from token claims
        return self.get_or_create_user(claims)
    
    def authenticate_with_id_token(self, id_token: str):
        """
        Authenticate a user using the id_token returned by Azure B2C implicit flow.

        :param id_token: JWT token received in the redirect from Azure B2C
        :return: CKAN user dict
        """
        if not id_token:
            log.debug("No id_token received from Azure B2C")
            return None

        # Start token validation process
        claims = self.execute_token_validation(id_token)
        
        if not claims:
            raise PermissionError("Invalid id_token received")

        log.debug(f"Decoded claims from id_token: {claims}")

        # Create or update the CKAN user based on claims
        user = self.get_or_create_user(claims)
        return user
    
    def validate_access_token(self, id_token: str, expected_nonce: str):
        """
        Fully compliant Azure B2C ID token validation using PyJWKClient.

        :param id_token: JWT received from the frontend
        :param expected_nonce: Nonce stored in session
        :return: Decoded claims dict if valid
        """
        if not id_token:
            raise PermissionError("No id_token provided")

        # Use the JWKS URI from your provider config
        jwk_client = PyJWKClient(self.provider_config.jwks_uri)

        try:
            # Select the correct signing key automatically using `kid`
            signing_key = jwk_client.get_signing_key_from_jwt(id_token).key

            # Decode and validate token
            claims = decode(
                id_token,
                key=signing_key,
                algorithms=["RS256"],
                audience=self.provider_config.client_id,
                issuer=self.provider_config.issuer,
                options={
                    "require": ["exp", "iss", "aud", "nonce"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
                leeway=60  # allow 1 min clock skew
            )

        except InvalidTokenError as e:
            log.info(f"ID token validation failed: {e}")
            raise PermissionError("Invalid id_token")

        # Validate nonce
        expected_nonce = session.get(f"{ADFS_SESSION_PREFIX}nonce", 'defaultNonce')
        if claims.get("nonce") != expected_nonce:
            raise PermissionError("Invalid nonce in id_token")

        # Validate policy / user flow (tfp claim)
        token_policy = claims.get('acr') or claims.get('tfp')
        if not token_policy:
            log.warning("No policy claim found in token")
        else:
            # normalize case to avoid mismatch
            if token_policy.lower() != self.provider_config.policy.lower():
                raise PermissionError("ID token issued under wrong policy")

        return claims
            
    def execute_token_validation(self, id_token):
        from flask import has_request_context, session

        if has_request_context():
            expected_nonce = session.get(f"{ADFS_SESSION_PREFIX}nonce")
        else:
            expected_nonce = None  # fallback for CLI/testing or non-request context

        claims = self.validate_access_token(id_token, expected_nonce)

        return claims
    
    def get_or_create_user(self, claims):
        """
        Create or update a CKAN user from Azure B2C claims.

        Args:
            claims (dict): JWT claims from B2C id_token

        Returns:
            dict: CKAN user dict
        """
        
        # Get the auth service type and the user id template
        auth_service_type = config.get(ATTR_AUTH_SERVICE)
        user_id_template = config.get(ATTR_USER_ID_TEMPLATE)

        if not user_id_template:
            raise RuntimeError("User ID template not configured")

        try:
            external_id = user_id_template.format_map(claims)
            external_id = external_id.strip('"').lower()
        except KeyError as e:
            log.error(f"Missing required claim {e}")
            raise PermissionError
        
        email = claims.get("email")
        if not email:
            raise PermissionError("Missing email claim")

        username = f"{external_id}"

        fullname = f"{claims.get('given_name', '')} {claims.get('family_name', '')}".strip()
        if not fullname:
            fullname = username

        try:
            user = get_action("user_show")(
                {"ignore_auth": True},
                {"id": username}
            )

            dirty = False
            if user.get("fullname") != fullname:
                user["fullname"] = fullname
                dirty = True
            if user.get("email") != email:
                user["email"] = email
                dirty = True

            if dirty:
                get_action("user_update")(
                    {"ignore_auth": True},
                    user
                )

        except NotFound:
            if asbool(config.get(ATTR_CREATE_USER, False)):
                user = get_action("user_create")(
                    {"ignore_auth": True},
                    {
                        "name": username,
                        "fullname": fullname,
                        "email": email,
                        "plugin_extras": {
                            "azure_auth": external_id
                        }
                    }
                )
                log.debug(f"User created --> {user['id']}")
            else:
                msg = (
                    f"User '{username}' does not exist and "
                    f"user auto-creation is disabled"
                )
                log.error(msg)
                raise CreateUserException(msg)

        return user