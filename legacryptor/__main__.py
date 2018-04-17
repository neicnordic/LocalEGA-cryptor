#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging

from .cli import parse_args
from .utils import encryptor, compressor
from .packet import PublicKeyEncryptedSessionKeyPacket, CompressedDataPacket, SymEncryptedDataPacket, LiteralDataPacket
from .pubring import Pubring

LOG = logging.getLogger(__name__)

def processor(pubkey):
    encryption_engine = encryptor(pubkey)
    compressor_engine = compressor(pubkey) # ignore preference
    literal_packet = LiteralDataPacket()
    compressed_packet = CompressedDataPacket() 
    encrypted_packet = SymEncryptedDataPacket()
    cleardata, size, final = yield next(encryption_engine)
    while True:
        compressed_data = compressor_engine.compress(literal_packet(cleardata, size, final))
        if final:
            compressed_data += compressor_engine.flush()
        encrypted_data = encryption_engine.send( compressed_packet(compressed_data, final) )
        cleardata, size, final = yield encrypted_packet(encrypted_data, len(encrypted_data), final)
            
def main():

    # Parse CLI arguments
    args = parse_args()

    # Create output dir, if necessary
    if args.output != '.':
        LOG.info("Creating output directory %s", args.output)
        os.makedirs(args.output, exist_ok=True)

    # Loading the pubring
    ring = Pubring(args.pubring)

    # If --list-keys, print and exit
    if args.list_keys:
        print(repr(ring))
        return

    # Get recipient
    LOG.debug('Finding key for "%s" in pubring', args.recipient)
    pubkey = ring[args.recipient] # might raise PGPError if not found
    LOG.info('Public Key (for %s) %s', args.recipient, repr(pubkey))

    # For eah file listed on the command line
    LOG.debug("Output files in: %s", args.output)
    for f in args.filename:

        basename = os.path.basename(f)
        prefix = os.path.join(args.output,f)
        LOG.info("Encrypting %s into %s.gpg", f, prefix)
        with open(prefix+'.gpg', 'wb') as outfile:

            engine = processor(pubkey)
            encrypted_session_key = next(engine)
            LOG.debug("Create Public Key Encrypted Session Key Packet")
            pesk = PublicKeyEncryptedSessionKeyPacket(encrypted_session_key, pubkey.key_id, pubkey.raw_pub_algorithm)
            LOG.debug("Outputing Public Key Encrypted Session Key Packet: %s", repr(pesk))
            outfile.write(bytes(pesk))
            
            LOG.debug("Streaming content of %s", f)
            with open(f, 'rb') as infile:
                chunk1 = bytearray(args.chunk)
                chunk2 = bytearray(args.chunk)
                chunk_size1 = infile.readinto(chunk1)
                chunk_size2 = infile.readinto(chunk2)
                partial = (chunk_size2 != 0)
                while True:
                    final = (chunk_size2 == 0) # true if chunk2 is empty
                    encrypted_data = engine.send( (chunk1, chunk_size1, partial and final) )
                    outfile.write(encrypted_data)
                    if final:
                        break
                    # Move chunk2 to chunk1, and read into chunk2
                    chunk1, chunk2 = chunk2, chunk1 # swap names, don't touch memory allocation
                    chunk_size1 = chunk_size2
                    chunk_size2 = infile.readinto(chunk2)

        # Now... the checksums
        LOG.info("Output md5 checksum into %s.md5", prefix)
        m = hashlib.md5()
        with open(f, 'rb') as org, open(prefix+'.md5', 'wt') as orgmd5:
            m.update(org.read())
            orgmd5.write(m.hexdigest())
            
        LOG.info("Output md5 checksum into %s.gpg.md5", prefix)
        m = hashlib.md5()
        with open(prefix+'.gpg.md5', 'wt') as orggpgmd5, open(prefix+'.gpg', 'rb') as outfile:
            m.update(outfile.read())
            orggpgmd5.write(m.hexdigest())

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('Encryption failed')
        LOG.error(repr(e))
        print(e, file=sys.stderr)
        sys.exit(2)
