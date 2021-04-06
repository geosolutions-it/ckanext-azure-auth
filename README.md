ckanext-azure-auth
==================

A CKAN extension. Adds authentication using Microsoft ADFS and Azure AD


Features
--------
* Integrates ckan with Active Directory on Windows 2012 R2, 2016 or Azure AD in the cloud.
* Provides seamless single sign on (SSO) for ckan project on intranet environments.
* Can auto create users.
* Stores inside user session access tokens for the future usees.



Requires python packages:  M2Crypto, jwt, xml_python

Linux packages::

   apt install \
       build-essential \
       python3-dev \
       libssl-dev \
       swig \

What is ADFS?
-------------

Azure Active Directory (Azure AD) is Microsoft’s enterprise cloud-based identity
and access management (IAM) solution. Azure AD is the backbone of the Office 365
system, and it can sync with on-premise Active Directory and provide authentication
to other cloud-based systems via OAuth or OpenId.

If you merely want to test this extension you can take out a free trial at the
Azure website (although you'll need to provide credit card details to prove
you're not a bot).

Configure:
-------------

1. Configure ADFS
* Register Azure APP
** Single tenant (example based on this config)
Follow the documentation for this plugin [django-auth-adfs configuration](https://django-auth-adfs.readthedocs.io/en/latest/azure_ad_config_guide.html)


On the machine hosting your instance of CKAN:

Ensure all the requirements are installed (see `requirements.txt` for further
details).

In your CKAN's settings.ini file add inside the [app:main] section `azure_auth` into a `ckan.plugins`:

    [app:main]
    ckan.plugins = stats text_view image_view recline_view azure_auth

And these settings:

    [app:main]

    ckan.plugins = stats text_view image_view recline_view azure_auth

    ckanext.azure_auth.wtrealm = <..uuid..>
    ckanext.azure_auth.ad_server = https://login.microsoftonline.com
    ckanext.azure_auth.tenant_id = <..uuid..>
    ckanext.azure_auth.client_id = <..uuid..>
    ckanext.azure_auth.audience = <..uuid..>
    ckanext.azure_auth.client_secret = <.. client secret ..>

    # Allow plugin to create new users
    ckanext.azure_auth.allow_create_users = True
    # Force Multi-Factor Authentication usage
    ckanext.azure_auth.force_mfa = False
    # Whether to disable single sign-on and force the ADFS server to show a login prompt.
    ckanext.azure_auth.disable_sso = False


* ad_server - link to https://login.microsoftonline.com or company AD directory
* client_secret is located on Certificates & secrets page


*A WORD OF WARNING* Microsoft appears to change its UI in the Azure website
quite often so you may need to poke around to find the correct settings. It has
been our experience that their otherwise excellent documentation doesn't
always stay up-to-date and/or Google doesn't point to the most current version
of the documentation. YMMV.

Development Environment:
------------------------

Create a Python [virtual environment](https://virtualenv.pypa.io/en/latest/) (virtualenv).
Activate and install requirements with the `pip` command:

    $ python3 -m .venv
    $ . .venv/bin/activate
    (foo)$ pip install -r requirements.txt




Alternatively, make sure you've installed the requirements in CKAN's own
virtualenv.

To run the test suite type::

    $ python -m unittest discover

All the heavy lifting for checking the response is done in the `validation`
module.

