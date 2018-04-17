import os
import logging

from terminaltables import DoubleTable

from .utils import PGPError
from .packet import parse_next_packet

LOG = logging.getLogger(__name__)

class Pubring():
    def __init__(self, p):
        self._path = p
        pubringpath = os.path.abspath(p)
        LOG.debug("Loading ring %s", pubringpath)
        self._store = {}
        with open(pubringpath, 'rb') as stream:
            pubkey = None
            while True:
                packet = parse_next_packet(stream)
                if packet is None:
                    break
                packet.parse(stream)
                if packet.tag == 6:
                    pubkey = packet
                elif packet.tag == 13: # packet 13 must be after a tag 6
                    LOG.debug('Loading Key "%s" (Key ID %s)', packet.info, pubkey.key_id)
                    self._store[packet.info] = pubkey # packet.info is a str
        if not self._store: # empty
            raise ValueError(f'The public ring "{p}" was empty or not found')


    def __getitem__(self, recipient):
        for info, key in self._store.items():
            #LOG.debug('Recipient "%s" | Info "%s"', recipient, info)
            if recipient == key.key_id or recipient in info:
                return key
        # else:
        raise PGPError(f'No public key found for {recipient}')

    def __bool__(self):
        return len(self._store) > 0

    def __repr__(self):
        list_data = [ ('Key ID','User Info') ]
        for name,key in self._store.items():
            list_data.append( (key.key_id, name) )
        table = DoubleTable(list_data)
        return f'''\
Available keys from {self._path}
{table.table}
The first substring that matches the requested recipient will be used as the encryption key
Alternatively, you can use the KeyID itself'''
