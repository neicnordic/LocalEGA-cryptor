# -*- coding: utf-8 -*-

import os
import sys
import io
import logging
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pgpy # Simply used to encrypt/decrypt the records, all in memory.

from . import __version__

LOG = logging.getLogger(__name__)

###########################################################
##
##         Crypt4GH header
##
###########################################################

MAGIC_NUMBER = b'crypt4gh'

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

# Note: We don't convert the bytes to int, because we are actually ignoring those records.
# I'm not sure they are any useful.

class Record():
    def __init__(self, session_key, iv,
                 plaintext_start=b'\x00000000', plaintext_end= b'\xffffffff', ciphertext_start=b'\x00000000', counter_offset=b'\x00000000', method=b'\x00000000'):
        self.plaintext_start = plaintext_start
        self.plaintext_end = plaintext_end
        self.ciphertext_start = ciphertext_start
        self.counter_offset = counter_offset
        self.method = method
        self.session_key = session_key
        self.iv = iv


    def __bytes__(self):
        return (
            self.plaintext_start  +  # 4 bytes
            self.plaintext_end    +  # 4 bytes
            self.ciphertext_start +  # 4 bytes
            self.counter_offset   +  # 4 bytes
            self.method           +  # 4 bytes
            self.session_key      +  # 32 bytes
            self.iv                  # IV (16 big-endian bytes)
        )

    @classmethod
    def new(cls, stream):
        return cls(stream[20:52], stream[52:],
                   plaintext_start = stream[:4],
                   plaintext_end = stream[4:8],
                   ciphertext_start = stream[8:12],
                   counter_offset = stream[12:16],
                   method = stream[16:20])

class Header():
    def __init__(self):
        # Unencrypted part
        self.magic_number = MAGIC_NUMBER # 8 bytes
        self.version = __version__ # Currently version 1
        # Encrypted part
        self.records = []

    def encrypt(self, pubkey): # No need to call it too often
        if not self.records:
            print("Warning: no records", file=sys.stderr)
        n = len(self.records).to_bytes(4, byteorder='little')
        records =  b''.join(bytes(r) for r in self.records)
        data = bytes(pubkey.encrypt(pgpy.PGPMessage.new(n + records, sensitive=True, format='b')))

        return (self.magic_number                                + # 8 bytes
                self.version.to_bytes(4, byteorder='little')     + # 4 bytes
                (16 + len(data)).to_bytes(4, byteorder='little') + # 4 bytes
                data)

    def __repr__(self):
        return f'<{self.magic_number}({self.version} | {len(self.records)} records)>'

    def add_record(self, r):
        self.records.append(r)

    @classmethod
    def new(cls, data, seckey):
        obj = cls()
        _data = seckey.decrypt(pgpy.PGPMessage.from_blob(data))
        data = bytes(_data)
        LOG.debug(data.hex().upper())
        n = int.from_bytes(data[:4], byteorder='little')
        LOG.debug(f'{n} records found')
        obj.records = [Record.new(data[i*68: (i+1)*68]) for i in range(0,n)]
        LOG.debug(f'Records: {obj.records}')
        obj.magic_number = MAGIC_NUMBER
        obj.version = __version__
        return obj



###########################################################
##
##         AES engine for encryption/decryption.
##             including a sha256 checksum for plaintext
##                       a sha256 checksum for ciphertext
##
###########################################################

def cryptor(session_key, nonce, method=None):
    '''Generator that takes a block of data as input and encrypts/decrypts it as output.

    The encryption/decryption algorithm is AES (in CTR mode), using the given session key and nonce.

    The output includes 2 sha256 checksums appended to the file.
    '''

    LOG.info('Starting the cipher engine (AES-256-CTR)')
    backend = default_backend()
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(nonce), backend=backend)

    aes_func = getattr(cipher, method, None)
    if aes_func is None:
        raise ValueError(f'Cipher incorrectly initialized: {method}')
    aes = aes_func()

    inputchecksum = hashlib.sha256()
    outputchecksum = hashlib.sha256()

    chunk = yield
    while True:
        data = bytes(aes.update(chunk))
        inputchecksum.update(chunk)
        outputchecksum.update(data)
        chunk = yield data
        if chunk is None: # Final chunk. Expunging.
            final_data = aes.finalize()
            outputchecksum.update(final_data)
            yield final_data
            # Returning the checksums
            yield (inputchecksum.digest(), outputchecksum.digest())
            break # Not really needed, since we won't advance the generator anymore


def encrypt(infile, outfile, pubkey, chunk_size=4096):

    try:
        LOG.info('Loading an encryption engine')

        session_key = os.urandom(32) # for AES-256
        LOG.debug(f'session key: {session_key.hex().upper()}')
        nonce = os.urandom(16)
        LOG.debug(f'  CTR nonce: {nonce.hex().upper()}')

        LOG.info('Creating Crypt4GH header')
        header = Header()
        LOG.debug('Adding a record')
        header.add_record(Record(session_key, nonce))
        header_bytes = header.encrypt(pubkey)
        outfile.write(header_bytes)

        # text = header_bytes.hex().upper()
        # text = ' '.join(text[i: i+2] for i in range(0, len(text), 2))
        # LOG.debug(f'HEADER: {text}')

        LOG.debug('Make room for the 2 SHA256 checksums')
        outfile.write(b'0' * 64)

        LOG.debug("Streaming content")
        engine = cryptor(session_key, nonce, method='encryptor')
        next(engine)
        chunk1 = infile.read(chunk_size)
        while True:
            encrypted_data = engine.send(chunk1)
            outfile.write(encrypted_data)
            chunk2 = infile.read(chunk_size)
            if not chunk2: # Finally, if chunk2 is empty
                final_data = engine.send(None)
                outfile.write(final_data)
                break
            chunk1 = chunk2 # Move chunk2 to chunk1, and let it read a new chunk2

        LOG.info('Outputing the checksums')
        mdc, checksum_header = next(engine)
        LOG.debug(f'  Encrypted SHA256 Checksum: {checksum_header.hex().upper()}', )
        LOG.debug(f'UnEncrypted SHA256 Checksum: {mdc.hex().upper()}')
        outfile.seek(len(header_bytes), io.SEEK_SET) # from start
        outfile.write(mdc)
        outfile.write(checksum_header)

    finally:
        infileno = infile.fileno()
        if infileno != 0:
            LOG.info('Closing input file (fileno %d)', infileno)
            infile.close()
        outfileno = outfile.fileno()
        if outfileno != 1:
            LOG.info('Closing output file (fileno %d)', outfileno)
            outfile.close()
    LOG.info('Encryption Successful')

def decrypt(infile, outfile, privkey, chunk_size=4096):
    assert privkey.is_unlocked, "The private key should be unlocked"
    #assert chunk_size >= 64, "Chunk size larger than 64 bytes required"

    try:
        LOG.info(f'Deconstructing the Header')
        magic_number = infile.read(8)
        if magic_number != MAGIC_NUMBER:
            raise ValueError("Not a CRYPT4GH formatted file")

        version = int.from_bytes(infile.read(4), byteorder='little')
        if version != __version__:
            raise ValueError("Invalid CRYPT4GH version")

        length = int.from_bytes(infile.read(4), byteorder='little') - 16
        encrypted_header = infile.read(length)

        LOG.info(f'Getting the checksums')
        mdc = infile.read(32)
        checksum = infile.read(32)
        LOG.info('Verifying the checksums length')
        if len(checksum) != 32:
            raise ValueError("Checksum missing")
        if len(mdc) != 32:
            raise ValueError("MDC missing")

        LOG.info('Parsing the encrypted part of the header')
        header = Header.new(encrypted_header, privkey)
        # Only interested in the first record
        r = header.records[0]

        LOG.debug(f'session key: {r.session_key.hex().upper()}')
        LOG.debug(f'  CTR nonce: {r.nonce.hex().upper()}')

        LOG.debug("Streaming content")
        engine = cryptor(r.session_key, r.nonce, method='decryptor')
        next(engine)

        LOG.debug("Streaming content")
        engine = cryptor(session_key, nonce, method='encryptor')
        next(engine)
        chunk1 = infile.read(chunk_size)
        while True:
            encrypted_data = engine.send(chunk1)
            outfile.write(encrypted_data)
            chunk2 = infile.read(chunk_size)
            if not chunk2: # Finally, if chunk2 is empty
                final_data = engine.send(None)
                outfile.write(final_data)
                break
            chunk1 = chunk2 # Move chunk2 to chunk1, and let it read a new chunk2

        LOG.info('Outputing the checksums')
        _checksum, _mdc = next(engine)
        LOG.debug(f'  Encrypted SHA256 Checksum: {_checksum.hex().upper()}', )
        LOG.debug(f'UnEncrypted SHA256 Checksum: {_mdc.hex().upper()}')

        LOG.info('Verifying the checksum')
        if checksum != _checksum:
            raise ValueError("Invalid checksum for the encrypted content")
        if mdc != _mdc:
            raise ValueError("Invalid checksum for the original content")
        

    finally:
        infileno = infile.fileno()
        if infileno != 0:
            LOG.info('Closing input file (fileno %d)', infileno)
            infile.close()
        outfileno = outfile.fileno()
        if outfileno != 1:
            LOG.info('Closing output file (fileno %d)', outfileno)
            outfile.close()
    LOG.info('Decryption Successful')


def reencrypt(infile, outfile, pubkey, privkey, chunk_size=4096):
    assert privkey.is_unlocked, "The private key should be unlocked"
    raise NotImplementedError('Coming...')
