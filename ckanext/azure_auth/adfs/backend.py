"""
ADFS / Azure AD authentication backend.
"""

import logging

import jwt

from ckan.common import _, config, session, asbool
from ckan.logic import NotFound
from ckan.plugins import toolkit
from ckanext.azure_auth.adfs.config import AdfsProviderConfig

from ckanext.azure_auth.base.backend import BaseAuthBackend
from ckanext.azure_auth.constants import (
    ADFS_SESSION_PREFIX,
    ATTR_ADSF_AUDIENCE,
    ATTR_CLIENT_ID,
    ATTR_CLIENT_SECRET,
    ATTR_CREATE_USER,
    TIMEOUT,
)
from ckanext.azure_auth.exceptions import (
    AzureReloginRequiredException,
    CreateUserException,
    MFARequiredException,
    RuntimeIssueException,
)

log = logging.getLogger(__name__)


class AdfsAuthBackend(BaseAuthBackend):
    provider_config: AdfsProviderConfig

    def __init__(self, provider_config: AdfsProviderConfig):
        self.provider_config = provider_config

    def exchange_auth_code(self, authorization_code):
        log.debug("Received authorization code: %s", authorization_code)
        data = {
            "grant_type": "authorization_code",
            "client_id": config[ATTR_CLIENT_ID],
            "redirect_uri": self.provider_config.get_redirect_url(),
            "code": authorization_code,
        }
        if config[ATTR_CLIENT_SECRET]:
            data["client_secret"] = config[ATTR_CLIENT_SECRET]

        log.debug("Getting access token at: %s", self.provider_config.token_endpoint)
        response = self.provider_config.session.post(self.provider_config.token_endpoint, data, timeout=TIMEOUT)
        # 200 = valid token received
        # 400 = 'something' is wrong in our request
        if response.status_code == 400:
            error_description = response.json().get("error_description", "")
            if error_description.startswith("AADSTS50076"):
                raise MFARequiredException

            # AADSTS54005 - expired  (TODO: an issue)
            # AADSTS70008 - already provided. Needs relogin
            if error_description.startswith("AADSTS54005") or error_description.startswith("AADSTS70008"):
                raise AzureReloginRequiredException(_("Please re-sign in on the Microsoft Azure side"))
            log.error(f"ADFS server returned an error: {error_description}")
            raise RuntimeIssueException(error_description)

        if response.status_code != 200:
            log.error("Unexpected ADFS response: %s", response.content.decode())
            raise PermissionError

        adfs_response = response.json()
        session[f"{ADFS_SESSION_PREFIX}tokens"] = adfs_response
        session.save()
        return adfs_response

    def validate_access_token(self, access_token):
        for idx, key in enumerate(self.provider_config.signing_keys):
            try:
                options = {
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require_exp": False,
                    "require_iat": False,
                    "require_nbf": False,
                }
                return jwt.decode(
                    access_token,
                    key=key,
                    algorithms=["RS256", "RS384", "RS512"],
                    audience=config[ATTR_ADSF_AUDIENCE],
                    issuer=self.provider_config.issuer,
                    options=options,
                    leeway=config["ckanext.azure_auth.jwt_leeway"],
                )
            except jwt.ExpiredSignatureError as error:
                log.info(f"Signature has expired: {error}")
                raise PermissionError
            except jwt.DecodeError as error:
                if idx < len(self.provider_config.signing_keys) - 1:
                    continue
                else:
                    log.info(f"Error decoding signature: {error}")
                    raise PermissionError
            except jwt.InvalidTokenError as error:
                log.info(str(error))
                raise PermissionError

        log.warning(f"No valid signature found")
        raise PermissionError("No valid signature found")

    def process_access_token(self, access_token, adfs_response=None):
        if not access_token:
            raise PermissionError

        log.debug(f"Received access token: {access_token}")
        claims = self.validate_access_token(adfs_response["id_token"])
        if not claims:
            raise PermissionError

        log.debug(f"Decoded claims: {claims}")
        return self.get_or_create_user(claims)

    def get_or_create_user(self, claims):
        """Create the user if it doesn't exist yet."""
        user_id = claims.get("oid")
        if not user_id:
            log.error(f"User claims don't have the claim 'oid' in their claims: {claims}")
            raise PermissionError

        email = self._discover_mail(claims)
        ckan_id = self._build_user_id(claims)
        username = self.sanitize_username(claims.get("name", ckan_id))
        fullname = f"{claims['given_name']} {claims['family_name']}"

        context = {"ignore_auth": True, "schema": self._get_fixed_user_schema()}
        try:
            user = toolkit.get_action("user_show")({"ignore_auth": True}, {"id": ckan_id})
            log.debug(f"User found --> {user}")
            dirty = False
            if user["name"] != username:
                log.warning(f"Username not aligned:  CKAN:[{user['name']}]  ADFS:[{username}]")
            if user["fullname"] != fullname:
                log.info(f"Resetting fullname from [{user['fullname']}] to [{fullname}]")
                user["fullname"] = fullname
                dirty = True
            if dirty:
                if email:
                    user["email"] = email
                toolkit.get_action("user_update")(context, user)
        except NotFound:
            if asbool(config.get(ATTR_CREATE_USER, False)):
                if not email:
                    msg = f"User with id '{ckan_id}' doesn't exist and email claim is missing, cannot create user."
                    log.error(msg)
                    raise PermissionError(msg)
                user = toolkit.get_action("user_create")(
                    context,
                    {
                        "id": ckan_id,
                        "name": username,
                        "fullname": fullname,
                        "email": email,
                        "plugin_extras": {
                            "azure_auth": user_id,
                        },
                    },
                )
                log.debug(f"User created --> {user}")
            else:
                msg = f"User with email '{email}' doesn't exist and creating users is disabled."
                log.debug(msg)
                raise CreateUserException(msg)
        return user

    def authenticate_with_code(self, authorization_code=None, **kwargs):
        """Authenticate using an authorization code from ADFS."""
        self.provider_config.load_remote_config()

        if not bool(authorization_code):
            log.debug("No authorization code was received")
            return

        adfs_response = self.exchange_auth_code(authorization_code)
        access_token = adfs_response["access_token"]
        user = self.process_access_token(access_token, adfs_response)
        return user

    def authenticate_with_token(self, access_token=None, **kwargs):
        """Authenticate using an access token retrieved by the client."""
        self.provider_config.load_remote_config()

        if not bool(access_token):
            log.debug("No authorization code was received")
            return

        access_token = access_token.decode()
        user = self.process_access_token(access_token)
        return user
