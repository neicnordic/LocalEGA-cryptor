# -*- coding: utf-8 -*-

import os
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pgpy # Simply used to encrypt the records, all in memory.

from . import __version__

LOG = logging.getLogger(__name__)

###########################################################
##
##         Crypt4GH header
##
###########################################################

"""\
A header is composed of unencrypted part and an encrypted part.

The unencrypted part is 'crypt4gh' + 4 bytes for the version + the length of the encrypted and unencrypted parts.

The encrypted part is:
* 4 bytes for the number <n> of files contained in the encrypted part
* <n> record, where a record is:
     -  8 bytes for the plaintext_start
     -  8 bytes for the plaintext_end
     -  8 bytes for the ciphertext_start
     -  8 bytes for the counter_offset (in case several files are concatenated)
     then
     - 4 bytes for the method: here only 0 (for AES-256-CTR).
     - 32 bytes for the session key
     - 16 bytes for the IV

"""

class Header():
    def __init__(self):
        # Unencrypted part
        self.magic_number = b'crypt4gh' # 8 bytes
        self.version = __version__ # Currently version 1
        # Encrypted part
        self.records = []
        self.encrypted_header = b''

    def __bytes__(self):
        LOG.info('Creating a Crypt4GH header')
        return (self.magic_number +                                                 # 8 bytes
                self.version.to_bytes(4, byteorder='little') +                      # 4 bytes
                (16 + len(self.encrypted_header)).to_bytes(4, byteorder='little') + # 4 bytes
                self.encrypted_header)

    def add_record(self, r):
        self.records.append(r)

    def encrypt(self, pubkey):
        self.encrypted_data = b''.join(r.encrypt(pubkey) for r in self.records)

class Record():
    def __init__(self, session_key, iv, plaintext_start=0, plaintext_end=None, ciphertext_start=0, counter_offset=0):
        self.session_key = session_key
        self.iv = iv
        self.plaintext_start = plaintext_start
        self.plaintext_end = plaintext_end
        self.ciphertext_start = ciphertext_start
        self.counter_offset = counter_offset

    def __bytes__(self):
        LOG.info('Creating a Crypt4GH Record')
        return (self.plaintext_start.to_bytes(4, byteorder='little') +    # 4 bytes
                (self.plaintext_end.to_bytes(4, byteorder='little') if self.plaintext_end is not None else b'\xffffffff') +  # 4 bytes
                self.ciphertext_start.to_bytes(4, byteorder='little') +    # 4 bytes
                self.counter_offset.to_bytes(4, byteorder='little') +    # 4 bytes
                b'\x00000000' +      # method = 0
                self.session_key +   # 32 bytes
                self.nonce           # IV (16 big-endian bytes)
        )

    def encrypt(self, pubkey):
        return pubkey.encrypt(self.__bytes__())


###########################################################
##
##         AES encryption.
##             including a sha256 checksum at the end
##
###########################################################
def make_digest(digest):
    '''Make a digest packet'''
    d = digest.digest()
    #return b'\x0A'+ len(d).to_bytes(2, byteorder='big') + d
    return d # 256 bits, 32 bytes

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

def decryptor(session_key, nonce):
    '''Generator that takes a block of data as input and encrypts it as output.

    The encryption algorithm is AES (in CTR mode), using a randomly-created session key.

    A sha256 checksum is appended.
    '''

    LOG.info('Starting the cipher engine')
    backend = default_backend()
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce), backend=backend)
    aes = cipher.encryptor()

    mdc = hashlib.sha256()

    clearchunk, final = yield
    while True:
        LOG.debug('Clearchunk: %s', clearchunk.decode())
        encrypted_data = bytes(aes.update(bytes(clearchunk)))
        mdc.update(encrypted_data)
        if final:
            final_data = aes.finalize()
            mdc.update(final_data)
            encrypted_data += final_data + make_digest(mdc)
        clearchunk, final = yield encrypted_data
