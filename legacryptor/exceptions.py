# -*- coding: utf-8 -*-
"""Exceptions"""

from . import __version__

class InvalidFormatError(Exception):
    def __str__(self): # Informal description
        return 'Not a CRYPT4GH formatted file'
    def __repr__(self): # Technical description
        return str(self)

class VersionError(Exception):
    def __init__(self, v):
        self.version = v
    def __str__(self): # Informal description
        return 'Invalid CRYPT4GH version'
    def __repr__(self): # Technical description
        return f'{self!s} | File using {self.v} | Expecting {__version__}'

class MDCError(Exception):
    def __init__(self, mdc, expected):
        self.mdc = mdc
        self.expected = expected
    def __str__(self): # Informal description
        return 'Invalid MDC'
    def __repr__(self): # Technical description
        return f'{self!s} | Computed {self.mdc} | Expecting {self.expected}'
