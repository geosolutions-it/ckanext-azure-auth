from setuptools import find_packages, setup

setup(
    name='ckanext-azure-auth',
    version='0.0.1',
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
        'm2crypto',
    ],
    entry_points="""
        [ckan.plugins]
        # Add plugins here, e.g.
        azure_auth=ckanext.azure_auth.plugin:AzureAuthPlugin
    """,
)
