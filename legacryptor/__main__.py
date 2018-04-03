#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
import argparse
import yaml

from .utils import is_power_two, chunker, compressor, encryptor
from .packet import get_pubkey
#from .packet import PublicKey, PublicKeyEncryptedSessionKeyPacket, CompressedDataPacket, LiteralDataPacket, SymEncryptedDataPacket

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('LOG_YML', os.path.join(os.path.dirname(__file__),'logger.yaml'))
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.pgp'))

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

    try:
        if not is_power_two(args.chunk):
            raise ValueError(f'The --chunk_size value "{args.chunk}" should be a power of 2')

        LOG.debug("Finding key for: %s, in pubring: %s", args.recipient, args.pubring)
        pubkey = None
        with open(args.pubring, 'rb') as pubring:
            pubkey = get_pubkey(pubring, args.recipient) # might raise PGPError if not found
            LOG.info('Public Key (for %s) %s', args.recipient, repr(pubkey))
            
        outfile = open(args.output, 'wb') if args.output else sys.stdout.buffer
        if args.output:
            LOG.debug("Open output file: %s", args.output)

        
        # Since we ignore the Signature for the moment, we don't have
        # a way to find the user's preference for the compression or
        # the symmetric encryption algorithm.
        #
        # Therefore, we fix the compression to ZLIB
        # and the sym-encryption to AES-256.
        LOG.debug("Create Encryption and Compression engines")
        compression_engine = compressor(None) # arg ignored
        encryption_engine = encryptor(pubkey, None) # alg ignored
        session_key = next(encryption_engine)

        #enc_key = pubkey._key.encrypt(m, padding.PKCS1v15())

        LOG.debug('session key: %s', session_key.hex())
        LOG.debug('session key length: %d', len(session_key))
        
        # LOG.debug("Encrypting file: %s", args.filename)
        # with open(args.filename, 'rb') as infile:
        
        #     LOG.debug("Creating Tag 1")

        #     LOG.debug("Creating Tag 18")
        #     for literal_data in chunker(infile, args.chunk_size):
        #         outfile.write(literal_data)

    # except Exception as e:
    #     print('Encryption failed')
    #     LOG.error(repr(e))
    #     print(repr(e), file=sys.stderr)
    #     sys.exit(2)
    finally:
        if args.output:
            outfile.close()

if __name__ == '__main__':
    main()


