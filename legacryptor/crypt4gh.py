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
from .exceptions import InvalidFormatError, VersionError, MDCError

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
    def __init__(self, session_key, iv, plaintext_start=0, plaintext_end=0xFFFFFFFFFFFFFFFF, ciphertext_start=32, counter_offset=0, method=0):
        self.plaintext_start = plaintext_start
        self.plaintext_end = plaintext_end
        self.ciphertext_start = ciphertext_start
        self.counter_offset = counter_offset
        self.method = method
        self.session_key = session_key
        self.iv = iv

    def __str__(self):
        return f'<Record {self.plaintext_start}|{self.plaintext_end}|{self.ciphertext_start}|{self.counter_offset}|{self.method}>'

    def __bytes__(self):
        return (
            self.plaintext_start.to_bytes(8,'little')  +  # 8 bytes
            self.plaintext_end.to_bytes(8,'little')    +  # 8 bytes
            self.ciphertext_start.to_bytes(8,'little') +  # 8 bytes
            self.counter_offset.to_bytes(8,'little')   +  # 8 bytes
            self.method.to_bytes(4,'little')           +  # 4 bytes
            self.session_key                           +  # 32 bytes
            self.iv                                       # IV (16 big-endian bytes)
        )

    @classmethod
    def new(cls, stream):
        plaintext_start = int.from_bytes(stream[:8],'little')
        del stream[:8]
        plaintext_end = int.from_bytes(stream[:8],'little')
        del stream[:8]
        ciphertext_start = int.from_bytes(stream[:8],'little')
        del stream[:8]
        counter_offset = int.from_bytes(stream[:8],'little')
        del stream[:8]
        method = int.from_bytes(stream[:4],'little')
        del stream[:4]
        session_key = bytes(stream[:32])
        del stream[:32]
        iv = bytes(stream[:16])
        del stream[:16]
        obj = cls(session_key, iv,
                  plaintext_start, plaintext_end, ciphertext_start, counter_offset, method)
        return obj

class Header():
    def __init__(self):
        # Unencrypted part
        self.magic_number = MAGIC_NUMBER # 8 bytes
        self.version = __version__ # Currently version 1
        # Encrypted part
        self.records = []

    def encrypt(self, pubkey):
        if not self.records:
            print("Warning: no records", file=sys.stderr)
        n = len(self.records).to_bytes(4, byteorder='little')
        records = n + b''.join(bytes(r) for r in self.records)
        msg = pgpy.PGPMessage.new(records, sensitive=True, format='b') # file=False
        data = bytes(pubkey.encrypt(msg))
        return (self.magic_number                                + # 8 bytes
                self.version.to_bytes(4, byteorder='little')     + # 4 bytes
                (16 + len(data)).to_bytes(4, byteorder='little') + # 4 bytes
                data)

    def __repr__(self):
        return f'<{self.magic_number}({self.version} | {len(self.records)} records)>'

    def add_record(self, r):
        self.records.append(r)

    @classmethod
    def decrypt(cls, data, seckey):
        msg = pgpy.PGPMessage.from_blob(data)
        data = bytearray(seckey.decrypt(msg).message)
        n = int.from_bytes(data[:4], byteorder='little')
        del data[:4]
        LOG.debug(f'{n} records found')
        obj = cls()
        for i in range(0,n):
            r = Record.new(data)
            obj.records.append(r)
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

    chunk = yield
    while True:
        data = bytes(aes.update(chunk))
        chunk = yield data
        if chunk is None: # Final chunk. Expunging.
            yield aes.finalize()
            break # Not really needed, since we won't advance the generator anymore

def encrypt(pubkey, infile, infilesize, outfile, chunk_size=4096):

    LOG.info('Loading an encryption engine')

    session_key = os.urandom(32) # for AES-256
    # LOG.debug(f'session key: {session_key.hex().upper()}')
    nonce = os.urandom(16)
    # LOG.debug(f'  CTR nonce: {nonce.hex().upper()}')

    LOG.info('Creating Crypt4GH header')
    header = Header()
    LOG.debug('Adding a record')
    header.add_record(Record(session_key, nonce, plaintext_end=infilesize or 0xFFFFFFFFFFFFFFFF))
    header_bytes = header.encrypt(pubkey)
    outfile.write(header_bytes)

    LOG.debug('Make room for the SHA256 MDC')
    outfile.write((0).to_bytes(32, byteorder='big'))

    LOG.debug("Streaming content")
    mdc = hashlib.sha256()
    engine = cryptor(session_key, nonce, method='encryptor')
    next(engine)

    chunk1 = infile.read(chunk_size)
    while True:
        mdc.update(chunk1)
        encrypted_data = engine.send(chunk1)
        outfile.write(encrypted_data)
        chunk2 = infile.read(chunk_size)
        if not chunk2: # Finally, if chunk2 is empty
            final_data = engine.send(None)
            outfile.write(final_data)
            break
        chunk1 = chunk2 # Move chunk2 to chunk1, and let it read a new chunk2

    LOG.info('Rewinding for the MDC')
    outfile.seek(len(header_bytes), io.SEEK_SET) # from start
    LOG.debug(f'MDC: {mdc.hexdigest().upper()}')
    outfile.write(mdc.digest())

    LOG.info('Encryption Successful')

def get_header(infile):
    '''Extract header and advance file position to AES block.'''

    LOG.info(f'Deconstructing the Header')
    buf = bytearray(16)
    infile.readinto(buf)
    magic_number = buf[:8]
    if magic_number != MAGIC_NUMBER:
        raise InvalidFormatError()

    version = int.from_bytes(buf[8:12], byteorder='little')
    if version != __version__:
        raise VersionError(version)

    length = int.from_bytes(buf[12:16], byteorder='little') - 16
    return (bytes(buf), infile.read(length))

# That allows us to decrypt and:
# - dump the output to a file
# - not process the output (only checksum it internally)
# - send it (in mem) to another quality control pass
def do_nothing(data):
    pass

def body_decrypt(record, infile, process_output=do_nothing, chunk_size=4096):
    # LOG.debug(f'session key: {record.session_key.hex().upper()}')
    # LOG.debug(f'  CTR nonce: {record.iv.hex().upper()}')

    LOG.debug("Shifting to right cipher position")
    orgmdc = infile.read(32)
    record.ciphertext_start -= 32
    infile.seek(record.ciphertext_start,io.SEEK_CUR)
    
    LOG.debug("Streaming content")
    mdc = hashlib.sha256()
    engine = cryptor(record.session_key, record.iv, method='decryptor')
    next(engine)

    chunk1 = infile.read(chunk_size)
    while True:
        data = engine.send(chunk1)
        mdc.update(data)
        process_output(data)
        chunk2 = infile.read(chunk_size)
        if not chunk2: # Finally, if chunk2 is empty
            final_data = engine.send(None)
            mdc.update(final_data)
            process_output(final_data)
            break
        chunk1 = chunk2 # Move chunk2 to chunk1, and let it read a new chunk2

    # Checking MDC
    computed_mdc = mdc.digest()
    LOG.debug(f'Computed MDC: {mdc.hexdigest().upper()}')
    LOG.debug(f'Original MDC: {orgmdc.hex().upper()}')
    if orgmdc != computed_mdc:
        # Should we erase the file?
        # Should we instead write the output to tempfile and then move it if successful?
        raise MDCError(computed_mdc, orgmdc)

    LOG.info('Decryption Successful')

    
def decrypt(privkey, infile, process_output=do_nothing, chunk_size=4096):
    assert privkey.is_unlocked, "The private key should be unlocked"
    assert chunk_size >= 32, "Chunk size larger than 32 bytes required"

    _, encrypted_part = get_header(infile)
    header = Header.decrypt(encrypted_part, privkey)
    # Only interested in the first record, for the moment
    r = header.records[0]
    # Decrypt the rest
    body_decrypt(r, infile, process_output=process_output, chunk_size=chunk_size)


def reencrypt(pubkey, privkey, infile, process_output=do_nothing, chunk_size=4096):
    '''Extract header and update with another one
    The AES encrypted part is only copied'''
    assert privkey.is_unlocked, "The private key should be unlocked"
    assert chunk_size >= 32, "Chunk size larger than 32 bytes required"

    _, encrypted_part = get_header(infile)
    header = Header.decrypt(encrypted_part, privkey)
    header_bytes = header.encrypt(pubkey)
    process_output(header_bytes)

    LOG.info(f'Streaming the remainer of the file')
    while True:
        data = infile.read(chunk_size)
        if not data:
            break
        process_output(data)

    LOG.info('Reencryption Successful')


def get_key_id(header):
    msg = pgpy.PGPMessage.from_blob(header)
    for one in msg.encrypters:
        return one
    return None

def header_to_records(privkey, header, passphrase):
    LOG.info('Extracting header from record')
    privkey,_ = pgpy.PGPKey.from_blob(privkey)
    with privkey.unlock(passphrase) as seckey:
        return Header.decrypt(header, seckey).records


if __name__ == '__main__':
    filename = sys.argv[1]
    with open(filename, 'rb') as infile:
        header = get_header(infile)
        print(get_key_id(header))
