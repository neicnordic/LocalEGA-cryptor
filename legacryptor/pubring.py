# -*- coding: utf-8 -*-

import os
import logging

from terminaltables import DoubleTable
from pgpy import PGPKeyring

LOG = logging.getLogger(__name__)

#################################################################
##
##           OpenPGP Pubring
##
#################################################################

# Patching the PGPy code
# See: https://github.com/SecurityInnovation/PGPy/issues/240
class LegaKeyring(PGPKeyring):
    def __iter__(self):
        for pgpkey in self._keys.values():
            yield pgpkey


class Pubring():
    def __init__(self, p):
        self._path = p
        pubringpath = os.path.abspath(p)
        LOG.debug("Loading ring %s", pubringpath)
        self._store = LegaKeyring(pubringpath)
        if not self._store: # empty (len = 0)
            raise ValueError(f'The public ring "{p}" was empty or not found')

    def __iter__(self):
        for k in self._store:
            for i in k.userids:
                yield (k.fingerprint.keyid, i.name, i.email, i.comment)

    def __getitem__(self, recipient):
        try:
            with self._store.key(recipient) as k:
                return k
        except:
            raise PGPError(f'No public key found for {recipient}')

    def __bool__(self):
        return len(self._store) > 0

    def __str__(self):
        return f'<Pubring from {self._path}>'

    def __repr__(self):
        list_data = [ ('Key ID','User Name','User Email','User Comment') ]
        for k in self._store:
            for i in k.userids:
                list_data.append( (k.fingerprint.keyid, i.name, i.email, i.comment) )
        table = DoubleTable(list_data)
        return f'''\
Available keys from {self._path}
{table.table}
The first substring that matches the requested recipient will be used as the encryption key
Alternatively, you can use the KeyID itself'''
