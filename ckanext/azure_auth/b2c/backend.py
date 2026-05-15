"""
Azure B2C (MyIdentity) authentication backend.
"""
import importlib
import logging

from jwt import decode, PyJWKClient
from jwt.exceptions import InvalidTokenError

from ckan.common import config, session, asbool
from ckan.logic import NotFound, get_action
from ckanext.azure_auth.b2c.config import B2CProviderConfig

from ckanext.azure_auth.base.backend import BaseAuthBackend
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_CREATE_USER,
    ATTR_CUSTOM_USER_FUNC,
)
from ckanext.azure_auth.exceptions import CreateUserException

log = logging.getLogger(__name__)


class B2CAuthBackend(BaseAuthBackend):
    """Authentication backend for Azure B2C using implicit flow (id_token)."""

    provider_config: B2CProviderConfig

    def __init__(self, provider_config:B2CProviderConfig):
        self.provider_config = provider_config

    def process_tokens(self, id_token, access_token=None):
        """Process an Azure B2C id_token directly."""
        if not id_token:
            raise PermissionError("No id_token provided")

        claims = self.decode_id_token(id_token)

        if not claims:
            raise PermissionError("Invalid id_token")

        log.debug(f'Decoded claims: {claims}')
        return self.get_or_create_user(claims, access_token)

    def decode_id_token(self, id_token: str) -> dict:
        """Validate an Azure B2C ID token using PyJWKClient."""
        if not id_token:
            raise PermissionError("No id_token provided")

        oidc_cfg = self.provider_config.get_remote_config()
        jwk_client = PyJWKClient(oidc_cfg.jwks_uri)

        try:
            signing_key = jwk_client.get_signing_key_from_jwt(id_token).key

            claims = decode(
                id_token,
                key=signing_key,
                algorithms=["RS256"],
                audience=self.provider_config.client_id,
                issuer=oidc_cfg.issuer,
                options={
                    "require": ["exp", "iss", "aud", "nonce"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
                leeway=60
            )

        except InvalidTokenError as e:
            log.warning(f"ID token validation failed: {e}")
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
            if token_policy.lower() != self.provider_config.policy.lower():
                raise PermissionError("ID token issued under wrong policy")

        return claims

    def get_or_create_user(self, claims, access_token=None):
        """Create or update a CKAN user from Azure B2C claims."""

        ckan_id = username = self._build_user_id(claims)
        email = self._discover_mail(claims)

        fullname = f"{claims.get('given_name', '')} {claims.get('family_name', '')}".strip() or username

        try:
            user = get_action("user_show")(
                {"ignore_auth": True},
                {"id": username}
            )

            dirty = False
            if user.get("fullname") != fullname:
                user["fullname"] = fullname
                dirty = True
            if email and user.get("email") != email:
                user["email"] = email
                dirty = True

            if dirty:
                get_action("user_update")(
                    {
                        "ignore_auth": True,
                        "schema": self._get_fixed_user_schema()
                    },
                    user)

            return user

        except NotFound:
            return self.create_user(claims, username, fullname, email, access_token)

    def create_user(self, claims, username, fullname, email, access_token=None):
            if not asbool(config.get(ATTR_CREATE_USER, False)):
                msg = f"User auto-creation is disabled. Authenticated user '{username}' will not be created."
                log.warning(msg)
                raise CreateUserException(msg)

            user_dict = {
                    "name": username,
                    "fullname": fullname,
                    "email": email,
                    "plugin_extras": {
                        "azure_auth": username
                    }
                }

            # hook to update user info if needed (e.g. call backend services to fill in missing email or other info)
            self.customize_user_data(user_dict, claims, access_token)

            if not user_dict["email"]:
                msg = f"Missing email claim for user '{username}'. User cannot be created."
                log.error(msg)
                raise PermissionError(msg)

            user = get_action("user_create")(
                { # context
                    "ignore_auth": True,
                    "schema": self._get_fixed_user_schema()
                },
                user_dict
            )
            log.debug(f"User created --> {user['id']}")
            return user

    def customize_user_data(self, user_dict: dict, claims: dict, access_token: str):
        custom_user_func = config.get(ATTR_CUSTOM_USER_FUNC, None)
        if not custom_user_func:
            return

        log.debug(f"Running user data custom function {custom_user_func}...")
        module_path, function_name = custom_user_func.rsplit('.', 1)
        module = importlib.import_module(module_path)
        func = getattr(module, function_name)
        try:
            func(user_dict, claims, access_token)
        except PermissionError as e:
            # This is the only expected exception, its message will be flashed on the UI
            raise
        except Exception as e:
            msg = f"Error running custom user function: {e}"
            log.error(msg, exc_info=True)
            raise PermissionError(msg)
