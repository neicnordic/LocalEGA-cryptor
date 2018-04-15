#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
import argparse

import yaml

from terminaltables import DoubleTable

from . import __title__, __version__
from .utils import is_power_two, encryptor, compressor
from .packet import PublicKeyEncryptedSessionKeyPacket, Pubring, LiteralDataPacket

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('LOG_YML', os.path.join(os.path.dirname(__file__),'logger.yaml'))
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.bin'))

def process(pubkey):
    encryption_engine = encryptor(pubkey)
    cleardata = yield next(encryption_engine)
    compression_engine = compressor(pubkey)
    while True:
        if cleardata is None:
            break
        # ... do the job
        compressed_data = engine.compress(cleardata)
        if cleardata.final:
            compressed_data += engine.flush()
        compressed_packet = CompressedDataPacket(compressed_data, len(compressed_data), cleardata.final)
        encrypted_data = encryption_engine.send(compressed_packet)
        encrypted_packet = SymEncryptedDataPacket(encrypted_data, len(encrypted_data), cleardata.final)
        cleardata = yield encrypted_packet
    # literal_stream = LiteralDataPacket(stream,data_length...)
            
def main(args=None):

    if not args:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(prog='lega-cryptor',
                                     description='''Encrypt file into a PGP message.''')
    parser.add_argument('--log'                               , help="The logger configuration file", default=DEFAULT_LOG)
    parser.add_argument('-v','--version', action='version', version=f'{__title__} {__version__}')


    # For Pubring
    pubring_group = parser.add_argument_group('Public Keys')
    pubring_group.add_argument('-l', '--list-keys', dest='list_keys',
                               action='store_true',
                               help="List the available public keys")
    pubring_group.add_argument('-p','--pubring', dest='pubring',
                               help=f"Path to the public key ring. If unspecified, it uses the one supplied with this package.",
                               default=DEFAULT_PUBRING)

    # For Encryption
    parser.add_argument('-o', '--output', dest='output',
                        help="output directory for the 3 created files", default='.')
    parser.add_argument('-r', '--recipient' , dest='recipient',
                        help="Name, email or anything to find the recipient of the message in the adjacent keyring. If unspecified, it defaults to EBI.",
                        default= '@ebi.ac.uk')
    parser.add_argument('filename', nargs='*', help="The path of the files to decrypt")

    parser.add_argument('-s', '--chunk_size', dest='chunk'    , help="Size of the chunks. Must be a power of 2. [Default: 4096 bytes]", default=4096) # 1 << 12

    args = parser.parse_args()

    # Logging
    logpath = os.path.abspath(args.log)
    if os.path.exists(logpath):
        with open(logpath, 'rt') as stream:
            logging.config.dictConfig(yaml.load(stream))
        
    outfile = sys.stdout.buffer # default
    try:
        if not is_power_two(args.chunk):
            raise ValueError(f'The --chunk_size value "{args.chunk}" should be a power of 2')

        if args.output != '.':
            LOG.info("Creating output directory %s", args.output)
            os.makedirs(args.output, exist_ok=True)

        pubringpath = os.path.abspath(args.pubring)
        LOG.debug("Loading ring %s", pubringpath)
        ring = None
        with open(pubringpath, 'rb') as stream:
            ring = Pubring(stream)

        if ring is None or ring.empty():
            raise ValueError(f'The public ring "{args.pubring}" was empty or not found')

        if args.list_keys:
            print(f'Available keys from {args.pubring}')
            print( repr(ring) )
            print('The first substring that matches the requested recipient will be used as the encryption key')
            print('Alternatively, you can use the KeyID itself')
            return

        LOG.debug('Finding key for "%s" in pubring', args.recipient)
        pubkey = ring[args.recipient] # might raise PGPError if not found
        LOG.info('Public Key (for %s) %s', args.recipient, repr(pubkey))


        LOG.debug("Output files in: %s", args.output)
        for f in args.filename:

            basename = os.path.basename(f)
            prefix = os.path.join(args.output,f)
            outfile = open(prefix+'.gpg', 'wb')
            LOG.info("Encrypting file: %s", f)

            engine = process(pubkey)
            encrypted_session_key = next(engine)
            LOG.debug("Create Public Key Encrypted Session Key Packet")
            pesk = PublicKeyEncryptedSessionKeyPacket(encrypted_session_key, pubkey.key_id, pubkey.raw_pub_algorithm)
            LOG.debug("Outputing Public Key Encrypted Session Key Packet: %s", repr(pesk))
            outfile.write(bytes(pesk))

            LOG.debug("Encrypting file: %s", f)
            with open(f, 'rb') as infile:
                chunk1 = bytearray(args.chunk)
                chunk2 = bytearray(args.chunk)
                chunk_size1 = infile.readinto(chunk1)
                chunk_size2 = infile.readinto(chunk2)
                while True:
                    final = (chunk_size2 == 0) # true if chunk2 is empty
                    packet = LiteralDataPacket(chunk1, chunk_size1, final)
                    encrypted_data = engine.send(packet)
                    outfile.write(encrypted_data)
                    if final:
                        break
                    # Move chunk2 to chunk1, and read into chunk2
                    chunk1, chunk2 = chunk2, chunk1 # swap names, don't touch memory allocation
                    chunk_size1 = chunk_size2
                    chunk_size2 = infile.readinto(chunk2)

            LOG.debug("Closing output file: %s", args.output)
            outfile.close()

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

    except Exception as e:
        print('Encryption failed')
        LOG.error(repr(e))
        print(repr(e), file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
