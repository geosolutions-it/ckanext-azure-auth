"""
Shared constants for the azure_auth extension.
"""

_EXTNAME = "ckanext.azure_auth"

AZURE_AD_SERVER_URL = "https://login.microsoftonline.com"

ADFS_SESSION_PREFIX = "adfs-"

# Config keys
ATTR_AD_SERVER = f"{_EXTNAME}.ad_server"
ATTR_WT_REALM = f"{_EXTNAME}.wtrealm"
ATTR_METADATA_URL = f"{_EXTNAME}.metadata_url"
ATTR_HELP_TEXT = f"{_EXTNAME}.login_help_text"
ATTR_AUTH_CALLBACK_PATH = f"{_EXTNAME}.auth_callback_path"
ATTR_TENANT_ID = f"{_EXTNAME}.tenant_id"
ATTR_CLIENT_ID = f"{_EXTNAME}.client_id"
ATTR_SERVICE_DOMAIN = f"{_EXTNAME}.service_domain"
ATTR_SERVICE_ID = f"{_EXTNAME}.service_id"
ATTR_ADSF_AUDIENCE = f"{_EXTNAME}.audience"
ATTR_CLIENT_SECRET = f"{_EXTNAME}.client_secret"
ATTR_FORCE_MFA = f"{_EXTNAME}.force_mfa"
ATTR_DISABLE_SSO = f"{_EXTNAME}.disable_sso"
ATTR_USER_ID_TEMPLATE = f"{_EXTNAME}.user_id_template"
ATTR_POLICY = f"{_EXTNAME}.policy"
ATTR_SCOPE = f"{_EXTNAME}.scope"
ATTR_RESPONSE_TYPE = f"{_EXTNAME}.response_type"
ATTR_CUSTOM_USER_FUNC = f"{_EXTNAME}.custom_user_func"
ATTR_MAIL_CLAIMS = f"{_EXTNAME}.claim.mail"

# SPID level
ATTR_SPIDL = f"{_EXTNAME}.spidl"

ATTR_CREATE_USER = f"{_EXTNAME}.allow_create_users"

ATTR_LOGIN_TITLE = f"{_EXTNAME}.login_title"
ATTR_LOGIN_BUTTON = f"{_EXTNAME}.login_button"
ATTR_LOGIN_LABEL = f"{_EXTNAME}.login_label"

RENDERABLE_ATTRS = (ATTR_LOGIN_TITLE, ATTR_LOGIN_BUTTON, ATTR_LOGIN_LABEL)

DEFAULT_CALLBACK_PATH = "/azure/signin"

# Kept for convenience — also available at ckanext.azure_auth.adfs.config.TIMEOUT
TIMEOUT = 120
