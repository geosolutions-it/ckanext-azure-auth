from setuptools import find_packages, setup

setup(
    name='ckanext-azure-auth',
    version='0.9.9',
    description='ADFS Authentication',
    long_description="""
    Integrates with ADFS Authentication
    """,
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[],
    keywords='',
    author='https://github.com/geosolutions-it/ckanext-azure-auth/graphs/contributors',
    author_email='info@geo-solutions.it',
    url='https://github.com/geosolutions-it/ckanext-azure-auth',
    packages=find_packages(exclude=['ez_setup', 'tests']),
    namespace_packages=['ckanext', 'ckanext.azure_auth'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
        'xml_python',
        'pyjwt',
    ],
    entry_points="""
        [ckan.plugins]
        azure_auth=ckanext.azure_auth.plugin:AzureAuthPlugin
        azure_auth_adfs=ckanext.azure_auth.adfs.plugin:AzureAdfsPlugin
        azure_auth_b2c=ckanext.azure_auth.b2c.plugin:AzureB2CPlugin
    """,
)
