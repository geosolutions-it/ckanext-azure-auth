"""
Azure B2C (MyIdentity) authentication backend.
"""
import logging

from jwt import decode, PyJWKClient
from jwt.exceptions import InvalidTokenError

from ckan.common import config, session, asbool
from ckan.logic import NotFound, get_action

from ckanext.azure_auth.base.backend import BaseAuthBackend
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_CREATE_USER,
    ATTR_MAIL_CLAIMS,
    ATTR_USER_ID_TEMPLATE,
)
from ckanext.azure_auth.exceptions import CreateUserException

log = logging.getLogger(__name__)


class B2CAuthBackend(BaseAuthBackend):
    """Authentication backend for Azure B2C using implicit flow (id_token)."""

    def process_access_token(self, id_token):
        """Process an Azure B2C id_token directly."""
        if not id_token:
            raise PermissionError("No id_token provided")

        log.debug(f'Received id_token: {id_token}')

        claims = self.execute_token_validation(id_token)

        if not claims:
            raise PermissionError("Invalid id_token")

        log.debug(f'Decoded claims: {claims}')
        return self.get_or_create_user(claims)

    def authenticate_with_id_token(self, id_token: str):
        """Authenticate a user using the id_token from Azure B2C implicit flow."""
        if not id_token:
            log.debug("No id_token received from Azure B2C")
            return None

        claims = self.execute_token_validation(id_token)

        if not claims:
            raise PermissionError("Invalid id_token received")

        log.debug(f"Decoded claims from id_token: {claims}")
        return self.get_or_create_user(claims)

    def validate_id_token(self, id_token: str, expected_nonce: str):
        """Validate an Azure B2C ID token using PyJWKClient."""
        if not id_token:
            raise PermissionError("No id_token provided")

        jwk_client = PyJWKClient(self.provider_config.jwks_uri)

        try:
            signing_key = jwk_client.get_signing_key_from_jwt(id_token).key

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
                leeway=60
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
            if token_policy.lower() != self.provider_config.policy.lower():
                raise PermissionError("ID token issued under wrong policy")

        return claims

    def execute_token_validation(self, id_token):
        from flask import has_request_context, session as flask_session

        if has_request_context():
            expected_nonce = flask_session.get(f"{ADFS_SESSION_PREFIX}nonce")
        else:
            expected_nonce = None

        return self.validate_id_token(id_token, expected_nonce)

    def get_or_create_user(self, claims):
        """Create or update a CKAN user from Azure B2C claims."""
        user_id_template = config.get(ATTR_USER_ID_TEMPLATE)

        if not user_id_template:
            raise RuntimeError("User ID template not configured")

        try:
            external_id = user_id_template.format_map(claims)
            external_id = external_id.strip('"').lower()
        except KeyError as e:
            log.error(f"Missing required claim {e}")
            raise PermissionError

        mail_claims_cfg = config.get(ATTR_MAIL_CLAIMS, "email") or "email"
        mail_claim_list = [c.strip() for c in mail_claims_cfg.split(",") if c.strip()]

        email = None
        for claim_name in mail_claim_list:
            value = claims.get(claim_name)
            if value:
                email = value
                break

        username = f"{external_id}"
        fullname = f"{claims.get('given_name', '')} {claims.get('family_name', '')}".strip()
        if not fullname:
            fullname = username

        custom_context = {
            "ignore_auth": True,
            "schema": self._get_fixed_user_schema()
        }

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
                get_action("user_update")(custom_context, user)

        except NotFound:
            if asbool(config.get(ATTR_CREATE_USER, False)):
                if not email:
                    msg = (
                        f"User '{username}' doesn't exist and "
                        f"email claim is missing, cannot create user."
                    )
                    log.error(msg)
                    raise PermissionError(msg)
                user = get_action("user_create")(
                    custom_context,
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
