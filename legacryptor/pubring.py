import logging

from terminaltables import DoubleTable

from .utils import PGPError
from .packet import parse_next_packet

LOG = logging.getLogger(__name__)

class Pubring():
    def __init__(self, pubringpath):
        self._store = {}
        with open(pubringpath, 'rb') as stream:
            pubkey = None
            while True:
                packet = parse_next_packet(stream)
                if packet is None:
                    break
                packet.parse()
                if packet.tag == 6:
                    pubkey = packet
                elif packet.tag == 13: # packet 13 must be after a tag 6
                    LOG.debug('Loading Key "%s" (Key ID %s)', packet.info, pubkey.key_id)
                    self._store[packet.info] = pubkey # packet.info is a str
        if not _store: # empty
            raise ValueError(f'The public ring "{pubringpath}" was empty or not found')


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
        return table.table


