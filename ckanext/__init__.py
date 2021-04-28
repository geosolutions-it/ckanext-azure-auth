# encoding: utf-8

__version__ = '0.0.1'
__description__ = 'ADFS Authentication'
__long_description__ = '''
'''
__license__ = 'AGPL'

# The packaging system relies on this import, please do not remove it
import sys; sys.path.insert(0, __path__[0])


# this is a namespace package
try:
    import pkg_resources

    pkg_resources.declare_namespace(__name__)
except ImportError:
    import pkgutil

    __path__ = pkgutil.extend_path(__path__, __name__)
