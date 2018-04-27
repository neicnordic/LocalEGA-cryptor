# -*- coding: utf-8 -*-

import os
import zlib
import hashlib
import logging 
import pgpy

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import hashes

LOG = logging.getLogger(__name__)

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

###########################################################
##
##         Crypt4GA header
##
###########################################################

def pack_header(pubkey, session_key, nonce):
    LOG.info('Creating a Crypt4GA header')
    # This is, for the moment, a dummy placeholder
    # It only concatenates the session key and nonce
    # and encrypt the result with a PGP Public Key
    # which internally uses an RSAKey or a DSAKey
    return pubkey.encrypt(session_key + nonce)

def unpack_header(privkey, data):
    LOG.info('Unpacking a Crypt4GA header')
    # This is a dummy placeholder at the moment
    # Look below the session key is 32 bytes and the nonce is 16 bytes
    header = privkey.decrypt(data.read(32+16))
    session_key = header[:32]
    nonce = header[32:]
    return (session_key, nonce)

###########################################################
##
##         AES encryption.
##             including a sha256 checksum at the end
##
###########################################################
def make_digest(digest):
    '''Make a digest packet'''
    d = digest.digest()
    return b'\x0A'+ len(d).to_bytes(2, byteorder='big') + d

def encryptor():
    '''Generator that takes a block of data as input and encrypts it as output.

    The encryption algorithm is AES (in CTR mode), using a randomly-created session key.

    A sha256 checksum is appended.
    '''

    LOG.info('Starting the cipher engine')
    session_key = os.urandom(32) # for AES-256
    LOG.debug(f'session key    = {session_key}')

    nonce = os.urandom(16)
    LOG.debug(f'CTR nonce: {nonce}')

    LOG.info('Creating AES cypher (CTR mode)')
    backend = default_backend()
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce), backend=backend)
    aes = cipher.encryptor()

    mdc = hashlib.sha256()

    clearchunk, final = yield (session_key, nonce)
    while True:
        LOG.debug('Clearchunk: %s', clearchunk.decode())
        encrypted_data = bytes(aes.update(bytes(clearchunk)))
        mdc.update(encrypted_data)
        if final:
            final_data = aes.finalize()
            mdc.update(final_data)
            encrypted_data += final_data + make_digest(mdc)
        clearchunk, final = yield encrypted_data
