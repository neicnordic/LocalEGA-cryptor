# -*- coding: utf-8 -*-
# __init__ is here so that we don't collapse in sys.path with another module

"""The legacryptor package contains code to encrypt file using OpenPGP, given the different LocalEGA PGP public keys."""

__title__ = 'Local EGA Cryptor'
__version__ = VERSION = '0.1'
__author__ = 'Frédéric Haziza <daz@nbis.se>'
#__license__ = 'Apache 2.0'
__copyright__ = __title__ + ' @ NBIS Sweden'

# Set default logging handler to avoid "No handler found" warnings.
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

