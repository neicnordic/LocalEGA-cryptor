# -*- coding: utf-8 -*-

import sys
import logging
import argparse
import io
from datetime import datetime
import hashlib

from terminaltables import DoubleTable

from .constants import lookup_pub_algorithm, lookup_sym_algorithm, lookup_hash_algorithm, lookup_s2k, lookup_tag
from .utils import (make_rsa_key, make_dsa_key, make_elg_key,
                    PGPError, read_1_byte, get_mpi, read_4_bytes,
                    encode_length, parse_header,
                    chunker, compressor, encryptor)

LOG = logging.getLogger(__name__)

class Packet(object):
    '''The base packet object containing various fields pulled from the packet
    header as well as a slice of the packet data.'''
    def __init__(self, tag, length, partial, data=None):
        self.tag = tag
        self.length = length # just for printing
        self.partial = partial
        self.data = data # open file
        self.start_pos = data.tell() if data else 0
        self.name = lookup_tag(self.tag)

    def parse(self):
        if self.data:
            self.data.seek( self.length , io.SEEK_CUR )

    def __bytes__(self):
        # new format only 0xC0 = 0x80 | 0x40 = b11000000
        tag = (0xC0 | self.tag).to_bytes(1,'big')
        length = encode_length(self.length, self.partial)
        return tag+length

    def __str__(self):
        return "#tag {:2} | {:4} bytes | {}".format(self.tag,
                                                    self.length,
                                                    self.name)

    def __repr__(self):
        return str(self)

class PublicKeyPacket(Packet):

    def parse(self):
        assert( not self.partial )
        assert( self.data is not None )
        self.pubkey_version = read_1_byte(self.data)
        if self.pubkey_version in (2,3):
            raise PGPError("Warning: version 3 keys are deprecated")
        elif self.pubkey_version != 4:
            raise PGPError(f"Unsupported public key packet, version {self.pubkey_version}")

        self.raw_creation_time = read_4_bytes(self.data)
        self.creation_time = datetime.utcfromtimestamp(self.raw_creation_time)
        # No validity, moved to Signature

        self.raw_pub_algorithm = read_1_byte(self.data)
        if self.raw_pub_algorithm in (1, 2, 3):
            # n, e
            n = get_mpi(self.data)
            e = get_mpi(self.data)
            self._key = make_rsa_key(n, e)
        elif self.raw_pub_algorithm == 17:
            # p, q, g, y
            p = get_mpi(self.data)
            q = get_mpi(self.data)
            g = get_mpi(self.data)
            y = get_mpi(self.data)
            self._key = make_dsa_key(p, q, g, y)
        elif self.raw_pub_algorithm in (16, 20):
            # p, g, y
            p = get_mpi(self.data)
            g = get_mpi(self.data)
            y = get_mpi(self.data)
            self._key = None #make_elg_key(p, g, y)
        elif 100 <= self.raw_pub_algorithm <= 110:
            # Private/Experimental algorithms, just move on
            self._key = None
        else:
            raise PGPError(f"Unsupported public key algorithm {raw_pub_algorithm}")

        # Hashing only the public part (differs from self.length for private key packets)
        size = self.data.tell() - self.start_pos
        sha1 = hashlib.sha1()
        sha1.update(bytearray( (0x99, (size >> 8) & 0xff, size & 0xff) )) # 0x99 and the 2-octet length
        self.data.seek(self.start_pos, io.SEEK_SET) # rewind
        sha1.update(self.data.read(size))
        self.fingerprint = sha1.hexdigest().upper()
        self.key_id = self.fingerprint[-16:] # lower 64 bits

    def __repr__(self):
        s = super().__repr__()
        return f"{s} | {self.creation_time} | KeyID {self.key_id} (ver 4)({lookup_pub_algorithm(self.raw_pub_algorithm)[0]})"

    # Since we ignore the Signature for the moment, we don't have
    # a way to find the user's preference for the compression or
    # the symmetric encryption algorithm.
    #
    # These 2 methods should be placed in the Signature Packet, related to that user
    def preferred_encryption_algorithm(self):
        # algid is currently ignored
        # We fix it to AES-256, ie algo 9
        return 9

    def preferred_compression_algorithm(self):
        # Compress algo if currently ignored
        # It is set to "Zip deflate with zlib header"
        return 2


class UserIDPacket(Packet):
    '''A User ID packet consists of UTF-8 text that is intended to represent
    the name and email address of the key holder. By convention, it includes an
    RFC 2822 mail name-addr, but there are no restrictions on its content.'''
    def parse(self):
        self.info = self.data.read(self.length).decode('utf8')

    def __repr__(self):
        s = super().__repr__()
        return f"{s} | {self.info}"

class SymEncryptedDataPacket(Packet):
    def __init__(self, data, length, final):
        self.data = data
        super(SymEncryptedDataPacket,self).__init__(9, length, final)

    def __bytes__(self):
        return super(SymEncryptedDataPacket,self).__bytes__() + self.data

class CompressedDataPacket(Packet):
    def __init__(self, data, length, final):
        self.data = data
        super(CompressedDataPacket,self).__init__(8, length, final)

    def __bytes__(self):
        return super(CompressedDataPacket,self).__bytes__() + self.data

class LiteralDataPacket(Packet):

    def __init__(self, data, length, final):
        self.data = data
        assert( length == len(data) )
        super(LiteralDataPacket,self).__init__(11, length, final)

    def __bytes__(self):
        return super(LiteralDataPacket,self).__bytes__() + self.data

class PublicKeyEncryptedSessionKeyPacket(Packet):

    def __repr__(self):
        s = super().__repr__()
        if hasattr(self, 'key_id'):
            return f"{s} | keyID {self.key_id} ({lookup_pub_algorithm(self.raw_pub_algorithm)[0]})"
        return s

    def __init__(self, encrypted_data, key_id, alg):
        self.encrypted_data = encrypted_data
        length = 10 + len(encrypted_data) # 1 + 8 + 1: version + key + algo
        super(PublicKeyEncryptedSessionKeyPacket,self).__init__(1, length, False) # not partial
        self.version = 3
        self.key_id = key_id
        self.raw_pub_algorithm = alg

    def __bytes__(self):
        _bytes = self.version.to_bytes(1, 'big')
        _bytes += self.key_id.encode() # hex str -> bytes
        _bytes += self.raw_pub_algorithm.to_bytes(1, 'big')
        _bytes += self.encrypted_data
        pkt = Packet(1, len(_bytes), False)
        LOG.debug('Making a header packet: %s', repr(pkt))
        return bytes(pkt) + _bytes

PACKET_TYPES = {
    #1: PublicKeyEncryptedSessionKeyPacket,
    # # 2: SignaturePacket,
    # 5: SecretKeyPacket,
    6: PublicKeyPacket,
    # 7: SecretKeyPacket,
    # 8: CompressedDataPacket,
    # 9: SymEncryptedDataPacket,
    # 11: LiteralDataPacket,
    # 12: TrustPacket,
    13: UserIDPacket,
    14: PublicKeyPacket,
    # # 17: UserAttributePacket,
    # 18: SymEncryptedDataPacket,
}

def parse_next_packet(data):
    header = parse_header(data)
    if header is None:
        return None
    tag, data_length, partial = header
    PacketType = PACKET_TYPES.get(tag, Packet)
    return PacketType(tag, data_length, partial, data)

class Pubring():
    def __init__(self, stream):
        self._store = {}
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
                self._store[packet.info] = pubkey.key_id # packet.info is a str

    def __getitem__(self, recipient):
        for info, key in self._store.items():
            #LOG.debug('Recipient "%s" | Info "%s"', recipient, info)
            if recipient in info:
                return key
        # else:
        raise PGPError(f'No public key found for {recipient}')

    def __bool__(self):
        return len(self._store) > 0

    def __repr__(self):
        list_data = [
            ('Key ID','User Info')
        ]
        for name,key_id in self._store.items():
            list_data.append( (key_id, name) )
        table = DoubleTable(list_data)
        return table.table


def print_packets(stream):
    while True:
        packet = parse_next_packet(stream)
        if packet is None:
            break
        packet.parse()
        print(repr(packet))
