import os
import zlib 
import hashlib

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding

from .constants import lookup_sym_algorithm

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

def old_tag_length(data, length_type):
    if length_type == 0:
        data_length = read_1_byte(data)
    elif length_type == 1:
        data_length = read_2_bytes(data)
    elif length_type == 2:
        data_length = read_4_bytes(data)
    elif length_type == 3:
        data_length = None
        # pos = data.tell()
        # data_length = len(data.read()) # until the end
        # data.seek(pos, io.SEEK_CUR) # roll back
        #raise PGPError("Undertermined length - SHOULD NOT be used")

    return data_length, False # partial is False

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

def encryptor(pubkey, algid):
    '''It is a black box sitting and waiting for input data to be
       encrypted, given the `alg` algorithm.'''

    # algid is currently ignored
    # We fix it to AES-256, ie algo 9
    algid = 9
    algoname, iv_len, alg = lookup_sym_algorithm(algid)
    session_key = os.urandom(iv_len)

    m = algid.to_bytes(1,'big') + session_key + (sum(session_key) % 65536).to_bytes(2,'big')
    block_size = alg.block_size // 8
    iv = (0).to_bytes(block_size, byteorder='big')
    try:
        engine = Cipher(alg(session_key), modes.CFB(iv), backend=default_backend()).encryptor()
    except UnsupportedAlgorithm as ex:
        raise PGPError(ex)

    prefix = os.urandom(block_size)
    mdc = hashlib.new('SHA1')

    indata, final = yield m
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


def compressor(algo):
    # Compress algo if currently ignored
    # It is set to ZIP
    return zlib.compressobj() # Zip deflate with zlib header
