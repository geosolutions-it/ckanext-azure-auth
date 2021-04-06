from setuptools import find_packages, setup

setup(
    name='ckanext-azure-auth',
    version='0.0.1',
    description='AFDS Authentications',
    long_description="""
    """,
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[],
    keywords='',
    author='https://github.com/ckan/ckan/graphs/contributors',
    author_email='info@ckan.org',
    url='http://ckan.org/',
    packages=find_packages(exclude=['ez_setup', 'tests']),
    namespace_packages=['ckanext', 'ckanext.azure_auth'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
        'xml_python',
        'jwt',
        'm2crypto',
    ],
    entry_points="""
        [ckan.plugins]
        # Add plugins here, e.g.
        azure_auth=ckanext.azure_auth.plugin:AzureAuthPlugin
    """,
)
