#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
import argparse
import yaml

from .utils import is_power_two, encryptor, compressor
from .packet import PublicKeyEncryptedSessionKeyPacket, Pubring

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('LOG_YML', os.path.join(os.path.dirname(__file__),'logger.yaml'))
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.pgp'))


def encrypt(pubkey):
    encryption_engine = encryptor(pubkey)
    cleardata = yield next(encryption_engine)
    compression_engine = compressor(pubkey)
    while True:
        if cleardata is None:
            break
        # ... do the job
        cleardata = yield b''
    # literal_stream = LiteralDataPacket(stream,data_length...)
            
def main(args=None):

    if not args:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description='''Encrypt file into a PGP message.''')
    parser.add_argument('--log'                               , help="The logger configuration file", default=DEFAULT_LOG)
    parser.add_argument('-s', '--chunk_size', dest='chunk'    , help="Size of the chunks. Must be a power of 2. [Default: 4096 bytes]", default=4096) # 1 << 12
    parser.add_argument('-p', '--pubring'   , dest="pubring"  , help=f"Path to the public key ring. If unspecified, it uses the one supplied with this package.", default=DEFAULT_PUBRING)
    parser.add_argument('-o', '--output'    , dest='output'   , help="output file destination")
    parser.add_argument('-r', '--recipient' , dest='recipient', help="Name, email or anything to find the recipient of the message in the adjacent keyring. If unspecified, it defaults to EBI.", default= '@ebi.ac.uk')
    parser.add_argument('filename'                            , help="The path of the file to decrypt")

    args = parser.parse_args()

    # Logging
    if os.path.exists(args.log):
        with open(args.log, 'rt') as stream:
            logging.config.dictConfig(yaml.load(stream))
        
    outfile = sys.stdout.buffer # default
    try:
        if not is_power_two(args.chunk):
            raise ValueError(f'The --chunk_size value "{args.chunk}" should be a power of 2')

        LOG.debug("Loading ring %s", args.pubring)
        ring = None
        with open(args.pubring, 'rb') as stream:
            ring = Pubring(stream)

        if ring is None or ring.empty():
            raise ValueError(f'The public ring "{args.pubring}" was empty or not found')

        LOG.debug('Finding key for "%s" in pubring', args.recipient)
        pubkey = ring[args.recipient] # might raise PGPError if not found
        LOG.info('Public Key (for %s) %s', args.recipient, repr(pubkey))

        if args.output:
            LOG.debug("Open output file: %s", args.output)
            outfile = open(args.output, 'wb')

        engine = encrypt(pubkey)
        encrypted_session_key = next(engine)
        LOG.debug("Create Public Key Encrypted Session Key Packet")
        pesk = PublicKeyEncryptedSessionKeyPacket(encrypted_session_key, pubkey.key_id, pubkey.raw_pub_algorithm)
        LOG.debug("Outputing Public Key Encrypted Session Key Packet: %s", repr(pesk))
        outfile.write(bytes(pesk))

        LOG.debug("Encrypting file: %s", args.filename)
        with open(args.filename, 'rb') as infile:
            chunk1 = bytearray(args.chunk)
            chunk2 = bytearray(args.chunk)
            chunk_size1 = infile.readinto(chunk1)
            chunk_size2 = infile.readinto(chunk2)
            while True:
                final = (chunk_size2 == 0) # true if chunk2 is empty
                encrypted_data = engine.send( (chunk1, chunk_size1, final) )
                outfile.write(encrypted_data)
                if final:
                    break
                # Move chunk2 to chunk1, and read into chunk2
                chunk1, chunk2 = chunk2, chunk1 # swap names, don't touch memory allocation
                chunk_size1 = chunk_size2
                chunk_size2 = infile.readinto(chunk2)

    except Exception as e:
        print('Encryption failed')
        LOG.error(repr(e))
        print(repr(e), file=sys.stderr)
        sys.exit(2)
    finally:
        if args.output:
            LOG.debug("Closing output file: %s", args.output)
            outfile.close()

if __name__ == '__main__':
    main()
