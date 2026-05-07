"""
Shared constants for the azure_auth extension.
"""

_EXTNAME = 'ckanext.azure_auth'

AZURE_AD_SERVER_URL = 'https://login.microsoftonline.com'

ADFS_SESSION_PREFIX = 'adfs-'

# Config keys
ATTR_AUTH_SERVICE = f'{_EXTNAME}.auth_service_type'
ATTR_MODE = f'{_EXTNAME}.mode'
ATTR_AD_SERVER = f'{_EXTNAME}.ad_server'
ATTR_WT_REALM = f'{_EXTNAME}.wtrealm'
ATTR_METADATA_URL = f'{_EXTNAME}.metadata_url'
ATTR_HELP_TEXT = f'{_EXTNAME}.login_help_text'
ATTR_AUTH_CALLBACK_PATH = f'{_EXTNAME}.auth_callback_path'
ATTR_TENANT_ID = f'{_EXTNAME}.tenant_id'
ATTR_CLIENT_ID = f'{_EXTNAME}.client_id'
ATTR_SERVICE_DOMAIN = f'{_EXTNAME}.service_domain'
ATTR_SERVICE_ID = f'{_EXTNAME}.service_id'
ATTR_ADSF_AUDIENCE = f'{_EXTNAME}.audience'
ATTR_CLIENT_SECRET = f'{_EXTNAME}.client_secret'
ATTR_FORCE_MFA = f'{_EXTNAME}.force_mfa'
ATTR_DISABLE_SSO = f'{_EXTNAME}.disable_sso'
ATTR_USER_ID_TEMPLATE = f'{_EXTNAME}.user_id_template'
ATTR_POLICY = f'{_EXTNAME}.policy'

# Config key for mail claim(s)
ATTR_MAIL_CLAIMS = f'{_EXTNAME}.claim.mail'

# SPID level
ATTR_SPIDL = f'{_EXTNAME}.spidl'

# Config keys: Configured at runtime
ATTR_REDIRECT_URL = f'{_EXTNAME}.redirect_uri'
ATTR_CREATE_USER = f'{_EXTNAME}.allow_create_users'

ATTR_LOGIN_LABEL = f'{_EXTNAME}.login_label'
ATTR_LOGIN_BUTTON = f'{_EXTNAME}.login_button'

RENDERABLE_ATTRS = (ATTR_LOGIN_LABEL, ATTR_LOGIN_BUTTON)

# Kept for convenience — also available at ckanext.azure_auth.adfs.config.TIMEOUT
TIMEOUT = 120
