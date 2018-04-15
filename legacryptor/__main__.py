#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
import argparse
import yaml
import pgpy
import hashlib

from terminaltables import DoubleTable

from . import __title__, __version__
from .packet import parse_next_packet

LOG = logging.getLogger(__name__)

DEFAULT_LOG = os.getenv('LOG_YML', os.path.join(os.path.dirname(__file__),'logger.yaml'))
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.bin'))

def info2keyid(stream):
    _store = {}
    key_id = None
    while True:
        packet = parse_next_packet(stream)
        if packet is None:
            break
        packet.parse()
        if packet.tag == 6:
            key_id = packet.key_id
            LOG.debug('Remembering Key ID "%s"', key_id)
        elif packet.tag == 13: # packet 13 must be after a tag 6
            info = packet.info
            LOG.debug('Loading Key "%s" (Key ID %s)', info, key_id)
            _store[info] = key_id
    return _store
        
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

    args = parser.parse_args()

    # Logging
    logpath = os.path.abspath(args.log)
    if os.path.exists(logpath):
        with open(logpath, 'rt') as stream:
            logging.config.dictConfig(yaml.load(stream))
        
    try:

        if args.output != '.':
            LOG.info("Creating output directory %s", args.output)
            os.makedirs(args.output, exist_ok=True)

        pubringpath = os.path.abspath(args.pubring)
        LOG.debug("Loading ring %s", pubringpath)
        ring = pgpy.PGPKeyring(pubringpath)

        LOG.debug('Building conversion "recipients to key ids"')
        recipients = {}
        with open(args.pubring, 'rb') as stream:
            recipients = info2keyid(stream)

        LOG.debug('All keys: %s', recipients)

        if args.list_keys:
            list_data = [
                ['KeyID','User Info']
            ]
            for name,key_id in recipients.items():
                list_data.append([key_id, name])

            print(f'Available keys from {args.pubring}')
            table = DoubleTable(list_data)
            print( table.table )
            print('The first substring that matches the requested recipient will be used as the encryption key')
            print('Alternatively, you can use the KeyID itself')
            return

        LOG.debug('Finding key for "%s" in pubring', args.recipient)
        key_id = None
        for k,v in recipients.items():
            if args.recipient in k or args.recipient == v:
                key_id = v
                break

        LOG.debug('"%s" has KeyID %s', args.recipient, key_id)
        if key_id is None:
            raise ValueError(f'No key id found for {args.recipient}')

        with ring.key(key_id) as pubkey: # raises error if not found
            LOG.info('Public Key (for %s) %s', args.recipient, repr(pubkey))

            LOG.debug("Output files in: %s", args.output)
            for f in args.filename:

                basename = os.path.basename(f)
                prefix = os.path.join(args.output,f)
                outfile = open(prefix+'.gpg', 'wb')
                LOG.debug("Loading file: %s", f)
                message = pgpy.PGPMessage.new(f, file=True)
                LOG.info("Encrypting file: %s", f)
                encrypted_message = pubkey.encrypt(message)
                outfile.write(bytes(encrypted_message))
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
