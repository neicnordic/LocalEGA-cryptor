# -*- coding: utf-8 -*-

import sys
import logging
import argparse
import io
from datetime import datetime
import hashlib

from .constants import lookup_pub_algorithm, lookup_tag
from .utils import (RSAKey, DSAKey, ELGKey,
                    read_1_byte, get_mpi, read_4_bytes,
                    parse_tag, parse_length)


LOG = logging.getLogger(__name__)

class Packet(object):
    '''The base packet object containing various fields pulled from the packet
    header as well as a slice of the packet data.'''
    def __init__(self, tag=None, new_format=True, length_type=None):
        self.tag = tag
        self.name = lookup_tag(self.tag)
        self.first_time = True
        self.new_format = new_format
        self.length_type = length_type

    def parse(self, data):
        length, _ = parse_length(data, self.new_format, self.length_type)
        data.seek( length , io.SEEK_CUR )

    def __str__(self):
        return "#tag {:2} | {}".format(self.tag, self.name)

    def __repr__(self):
        return str(self)

class PublicKeyPacket(Packet):

    def __init__(self, **kwargs):
        super().__init__(tag=6, **kwargs)

    def parse(self, data):
        length, partial = parse_length(data, self.new_format, self.length_type)
        start_pos = data.tell()
        assert( not partial )
        self.pubkey_version = read_1_byte(data)
        if self.pubkey_version in (2,3):
            raise PGPError("Warning: version 3 keys are deprecated")
        elif self.pubkey_version != 4:
            raise PGPError(f"Unsupported public key packet, version {self.pubkey_version}")

        self.raw_creation_time = read_4_bytes(data)
        self.creation_time = datetime.utcfromtimestamp(self.raw_creation_time)
        # No validity, moved to Signature

        self.raw_pub_algorithm = read_1_byte(data)
        if self.raw_pub_algorithm in (1, 2, 3):
            # n, e
            n = get_mpi(data)
            e = get_mpi(data)
            self._key = RSAKey(n, e)
        elif self.raw_pub_algorithm == 17:
            # p, q, g, y
            p = get_mpi(data)
            q = get_mpi(data)
            g = get_mpi(data)
            y = get_mpi(data)
            self._key = DSAKey(p, q, g, y)
        elif self.raw_pub_algorithm in (16, 20):
            # p, g, y
            p = get_mpi(data)
            g = get_mpi(data)
            y = get_mpi(data)
            self._key = ELGKey(p, g, y)
        elif 100 <= self.raw_pub_algorithm <= 110:
            # Private/Experimental algorithms, just move on
            self._key = None
        else:
            raise ValueError(f"Unsupported public key algorithm {self.raw_pub_algorithm}")

        # Hashing only the public part (differs from self.length for private key packets)
        size = data.tell() - start_pos
        sha1 = hashlib.sha1()
        sha1.update(bytearray( (0x99, (size >> 8) & 0xff, size & 0xff) )) # 0x99 and the 2-octet length
        data.seek(start_pos, io.SEEK_SET) # rewind
        sha1.update(data.read(size))
        self.fingerprint = sha1.hexdigest().upper()
        self.key_id = self.fingerprint[-16:] # lower 64 bits

    def __repr__(self):
        s = super().__repr__()
        return f"{s} | {self.creation_time} | KeyID {self.key_id} (ver 4)({lookup_pub_algorithm(self.raw_pub_algorithm)})"

    def encrypt(self, data):
        if self._key:
            return self._key.encrypt(data)
        raise NotImplementedError(f'Asymmetric key algorithm {lookup_pub_algorithm(self.raw_pub_algorithm)} not supported')


class UserIDPacket(Packet):
    '''A User ID packet consists of UTF-8 text that is intended to represent
    the name and email address of the key holder. By convention, it includes an
    RFC 2822 mail name-addr, but there are no restrictions on its content.'''
    def __init__(self, **kwargs):
        super().__init__(tag=13, **kwargs)

    def parse(self, data):
        length, partial = parse_length(data, self.new_format, self.length_type)
        assert( not partial )
        self.info = data.read(length).decode('utf8')

    def __repr__(self):
        s = super().__repr__()
        return f"{s} | {self.info}"

# The only ones with need and support
PACKET_TYPES = {
    #5: SecretKeyPacket,
    6: PublicKeyPacket,
    #7: SecretKeyPacket, # why would someone give us their private key?...
    13: UserIDPacket,
    14: PublicKeyPacket,
}

def parse_next_packet(data):
    tag = parse_tag(data)
    if tag is None:
        return None
    tag, new_format, length_type = tag
    PacketType = PACKET_TYPES.get(tag, Packet)
    if PacketType == Packet:
        return PacketType(tag=tag, new_format=new_format, length_type=length_type)
    return PacketType(new_format=new_format, length_type=length_type)

def print_packets(stream):
    while True:
        packet = parse_next_packet(stream)
        if packet is None:
            break
        packet.parse(stream)
        print(repr(packet))
