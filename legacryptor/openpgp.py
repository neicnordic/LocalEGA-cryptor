# -*- coding: utf-8 -*-

import sys
import logging
import argparse
import io
from datetime import datetime
import hashlib
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import hashes


LOG = logging.getLogger(__name__)

###########################################################
##
##   OpenPGP constants
##
###########################################################

# https://tools.ietf.org/html/rfc4880#section-4.3
tags = {
    0:  "Reserved",
    1:  "Public-Key Encrypted Session Key Packet",
    2:  "Signature Packet",
    3:  "Symmetric-Key Encrypted Session Key Packet",
    4:  "One-Pass Signature Packet",
    5:  "Secret-Key Packet",
    6:  "Public-Key Packet",
    7:  "Secret-Subkey Packet",
    8:  "Compressed Data Packet",
    9:  "Symmetrically Encrypted Data Packet",
    10: "Marker Packet",
    11: "Literal Data Packet",
    12: "Trust Packet",
    13: "User ID Packet",
    14: "Public-Subkey Packet",
    17: "User Attribute Packet",
    18: "Sym. Encrypted and Integrity Protected Data Packet",
    19: "Modification Detection Code Packet",
}

def lookup_tag(tag):
    if tag in (60, 61, 62, 63):
        return "Private or Experimental Values"
    return tags.get(tag, "Unknown")


# Specification: https://tools.ietf.org/html/rfc4880#section-5.2
pub_algorithms = {
    1:  "RSA Encrypt or Sign",
    2:  "RSA Encrypt-Only",
    3:  "RSA Sign-Only",
    #16: "ElGamal Encrypt-Only",
    17: "DSA Digital Signature Algorithm", 
    18: "Elliptic Curve", 
    19: "ECDSA", 
    #20: "Formerly ElGamal Encrypt or Sign",
    #21: "Diffie-Hellman", # future plans
}

def lookup_pub_algorithm(alg):
    if 100 <= alg <= 110:
        return "Private/Experimental algorithm"
    return pub_algorithms.get(alg, "Unknown")


###########################################################
##
##         Asymmetric Keys and Algorithms
##
###########################################################

class RSAKey():
    def __init__(self, n, e):
        '''Create an RSA key from the public numbers.'''
        backend = default_backend()
        self._key = rsa.RSAPublicNumbers(e,n).public_key(backend)
        self._padding = padding.PKCS1v15()
        # self._padding = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    def encrypt(self, data):
        LOG.debug('Encrypting data with RSA key')
        return self._key.encrypt(data, self._padding)
        
class DSAKey():
    def __init__(self, p, q, g, y):
        '''Create a DSA key from the public numbers.'''
        backend = default_backend()
        params = dsa.DSAParameterNumbers(p,q,g)
        self._key = dsa.DSAPublicNumbers(y, params).public_key(backend)
    def encrypt(self, data): 
        LOG.debug('Encrypting data with DSA key')
        return self._key.encrypt(data)

# ElGamal is not supported by the cryptography package
# https://github.com/pyca/cryptography/issues/1363
# PyCrypto does, so we could include the latter package if we really want to support ElGamal
class ELGKey():
    def __init__(self, p, q, y):
        pass
    def encrypt(self, data):
        LOG.debug('Encrypting data with ELG key')
        raise NotImplementedError('ElGamal is not supported')


##############################################################
##
##           OpenPGP packets
##
##############################################################
class PGPError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return f'OpenPGP Error: {self.msg}'

def is_power_two(x):
    return (x & (x - 1)) == 0

def chunker(f,chunk_size):
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data

def read_1_byte(data):
    '''Pull one byte from data and return as an integer.'''
    b1 = data.read(1)
    return None if b1 in (None, b'') else ord(b1)

def read_2_bytes(data):
    '''Pull two bytes from data at offset and return as an integer.'''
    b = bytearray(2)
    _b = data.readinto(b)
    if _b is None or _b < 2:
        raise PGPError('Not enough bytes')
    return get_int2(b)

def read_4_bytes(data):
    '''Pull four bytes from data at offset and return as an integer.'''
    b = bytearray(4)
    _b = data.readinto(b)
    if _b is None or _b < 4:
        raise PGPError('Not enough bytes')
    return get_int4(b)

def get_int2(b):
    assert( len(b) > 1 )
    return (b[0] << 8) + b[1]

def get_int4(b):
    assert( len(b) > 3 )
    return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]

def get_mpi(data):
    '''Get a multi-precision integer.
    See: http://tools.ietf.org/html/rfc4880#section-3.2'''
    mpi_len = read_2_bytes(data) # length in bits
    to_process = (mpi_len + 7) // 8 # length in bytes
    b = data.read(to_process)
    #print("MPI bits:",mpi_len,"to_process", to_process)
    return int.from_bytes(b, 'big')

def to_mpi(n):
    '''Make a multi-precision integer.'''
    blen = n.bit_length()
    return blen.to_bytes(2,'big') + n.to_bytes((blen + 7) // 8, 'big')

def old_tag_length(data, length_type):
    if length_type == 0:
        data_length = read_1_byte(data)
    elif length_type == 1:
        data_length = read_2_bytes(data)
    elif length_type == 2:
        data_length = read_4_bytes(data)
    elif length_type == 3:
        data_length = None
    return data_length, False # partial is False

def new_tag_length(data):
    '''Takes a bytearray of data as input.
    Returns a derived (length, partial) tuple.
    Refer to RFC 4880 section 4.2.2: http://tools.ietf.org/html/rfc4880#section-4.2.2
    '''
    b1 = read_1_byte(data)
    length = 0
    partial = False

    # one-octet
    if b1 < 192:
        length = b1

    # two-octet
    elif b1 < 224:
        b2 = read_1_byte(data)
        length = ((b1 - 192) << 8) + b2 + 192

    # five-octet
    elif b1 == 255:
        length = read_4_bytes(data)

    # Partial Body Length header, one octet long
    else:
        # partial length, 224 <= l < 255
        length = 1 << (b1 & 0x1f)
        partial = True

    return (length, partial)

def parse_tag(data):
    """\
    A packet is composed of (in order) a `tag`, a `length` and a `body`.
    A tag is one byte long and determine how many bytes the length is.
    There are two formats for tag:
    * old style: The length can be 0, 1, 2 or 4 byte(s) long.
    * new style: The length can be 1, 2, or 4 byte(s) long.
 
    Packet Tag byte
    ---------------
    +-------------+----------+---------------+---+---+---+---+---------+---------+
    | bit         | 7        | 6             | 5 | 4 | 3 | 2 | 1       | 0       |
    +-------------+----------+---------------+---+---+---+---+---------+---------+
    |             | always 1 | packet format |               | length type       |
    |             |          |               |               | 0 = 1 byte        |
    | old-style   |          |       0       |  packet tag   | 1 = 2 bytes       |
    |             |          |               |               | 2 = 5 bytes       |
    |             |          |               |               | 3 = undertermined |
    +-------------+          +---------------+---------------+-------------------+
    |             |          |               |                                   |
    | new-style   |          |       1       |             packet tag            |
    |             |          |               |                                   |
    +-------------+----------+---------------+-----------------------------------+
    With the old format, the tag includes the length, but the number of packet types is limited to 16.
    With the new format, the number of packet type can exceed 16, and the length are the following bytes.
    The length determines how many bytes the body is.
    Note that the new format can specify a length that encodes a body chunk by chunk.
   
    Refer to RFC 4880 for more information (https://tools.ietf.org/html/rfc4880).
    """
    # First byte
    b = data.read(1)
    if not b:
        return None

    #LOG.debug(f"First byte: {b.hex()} {ord(b):08b} ({ord(b)})")
    b = ord(b)

    # 7th bit of the first byte must be a 1
    if not bool(b & 0x80):
        rest = data.read()
        LOG.debug('b: %s, REST (%d bytes): %s ...', b, len(rest), rest[:30].hex())
        raise PGPError("incorrect packet header")

    # the header is in new format if bit 6 is set
    new_format = bool(b & 0x40)

    # tag encoded in bits 5-0 (new packet format)
    tag = b & 0x3f

    if new_format:
        # length is encoded in the second (and following) octet
        return (tag, True, None)
    else:
        tag >>= 2 # tag encoded in bits 5-2, discard bits 1-0
        length_type = b & 0x03 # get the last 2 bits
        return (tag, False, length_type)

def parse_length(data, new_format, length_type):
    if new_format:
        return new_tag_length(data)
    else:
        return old_tag_length(data, length_type)

###########################################
##
## The packets (only the interesting ones)
##
###########################################

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
