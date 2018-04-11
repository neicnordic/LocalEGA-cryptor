import os
import zlib 
import hashlib
import logging 

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding

from .constants import lookup_sym_algorithm

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

def parse_header(data):
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
        data_length, partial = new_tag_length(data)
    else:
        tag >>= 2 # tag encoded in bits 5-2, discard bits 1-0
        length_type = b & 0x03 # get the last 2 bits
        data_length, partial = old_tag_length(data, length_type)
    return (tag, data_length, partial)

def encode_length(length, partial): # new format only
    '''Encode the length header'''
    if partial:
        # partial length, 224 <= l < 255
        assert( is_power_two(length) )
        assert( length.bit_length() < 16 and length & 0x1f == 0 )
        return (length.bit_length() - 1).to_bytes(1,'big')

    # one-octet
    if length < 192:
        return length.to_bytes(1,'big')

    # two-octet
    if length < 8384:
        elen = ((length & 0xFF00) + (192 << 8)) + ((length & 0xFF) - 192)
        return elen.to_bytes(2,'big')

    # five-octet
    return b'\xFF' + length.to_bytes(4,'big')

def make_rsa_key(n,e):
    '''Convert a hex-based dict of values to an RSA key'''
    backend = default_backend()
    return rsa.RSAPublicNumbers(e,n).public_key(backend)

def make_dsa_key(p,q,g,y):
    '''Convert a hex-based dict of values to a DSA key'''
    backend = default_backend()
    params = dsa.DSAParameterNumbers(p,q,g)
    return dsa.DSAPublicNumbers(y, params).public_key(backend)

def make_elg_key(p,q,y):
    # backend = default_backend()
    raise NotImplementedError()

def pesk_encrypt(pubkey, m):
    alg = pubkey.raw_pub_algorithm
    args = (m,padding.PKCS1v15()) if alg in (1,2,3) else (m,)
    enc_m = pubkey._key.encrypt(*args)
    return to_mpi(int.from_bytes(enc_m, 'big'))

def encryptor(pubkey):
    '''It is a black box sitting and waiting for input data to be
       encrypted, given the `alg` algorithm.'''

    # algid is currently ignored
    # We fix it to AES-256, ie algo 9
    algid = pubkey.preferred_encryption_algorithm()
    algoname, iv_len, alg = lookup_sym_algorithm(algid)
    session_key = os.urandom(iv_len)

    # The value "m" in the above formulas is derived from the session key
    # as follows.  First, the session key is prefixed with a one-octet
    # algorithm identifier that specifies the symmetric encryption
    # algorithm used to encrypt the following Symmetrically Encrypted Data
    # Packet.  Then a two-octet checksum is appended, which is equal to the
    # sum of the preceding session key octets, not including the algorithm
    # identifier, modulo 65536.  This value is then encoded as described in
    # PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
    # form the "m" value used in the formulas above.  See Section 13.1 of
    # this document for notes on OpenPGP's use of PKCS#1.

    m = algid.to_bytes(1,'big') + session_key + (sum(session_key) % 65536).to_bytes(2,'big')
    block_size = alg.block_size // 8
    iv = (0).to_bytes(block_size, byteorder='big')
    try:
        engine = Cipher(alg(session_key), modes.CFB(iv), backend=default_backend()).encryptor()
    except UnsupportedAlgorithm as ex:
        raise PGPError(ex)

    prefix = os.urandom(block_size)
    mdc = hashlib.new('SHA1')

    indata, final = yield pesk_encrypt(pubkey, m)
    indata = prefix + prefix[-2:] + indata # prefix plus repeat
    while True:
        encrypted_data = engine.update(indata)
        mdc.update(encrypted_data)
        if final:
            final_data = engine.finalize()
            mdc.update(final_data)
            mdc.update(b'\xd3\x14')
            encrypted_data += final_data + mdc.digest()
        indata, final = yield encrypted_data

class Passthrough():
    def compress(data):
        return data
    def flush():
        return b''

def compressor(pubkey):
    algo = pubkey.preferred_compression_algorithm()
    if algo == 0: # Uncompressed
        engine = Passthrough()
        
    elif algo == 1: # Zip deflate
        engine = zlib.decompressobj(-15)
        
    elif algo == 2: # Zip deflate with zlib header
        engine = zlib.decompressobj()
        
    elif algo == 3: # Bzip2
        engine = bz2.decompressobj()
    else:
        raise NotImplementedError()

    return engine
