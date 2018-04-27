#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging

from .cli import parse_args
from .pubring import Pubring
from .encrypt import encrypt_files
from .decrypt import decrypt_files
from .reencrypt import reencrypt_files

LOG = logging.getLogger(__name__)

def run():

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
    if not args.offline:
        from urllib.parse import quote
        endpoint = args.server + quote(args.recipient)
        LOG.debug('Contacting %s', endpoint)
        pubkey = None
        raise NotImplementedError('Non offline mode not implemented...yet')
    else:
        LOG.debug('Finding key for "%s" in pubring %s', args.recipient, args.pubring)
        pubkey = ring[args.recipient] # might raise PGPError if not found
        LOG.info('Public Key (for %s) %s', args.recipient, repr(pubkey))

    # For each file listed on the command line
    if args.encrypt:
        encrypt_files(pubkey, args)
    elif args.decrypt:
        decrypt_files(privkey, args)
    elif args.reencrypt:
        privkey = None # Get it from a keyserver. Similar to lega/openpgg/__main__.py
        reencrypt_files(privkey, pubkey, args)

def main():
    try:
        run()
    except Exception as e:
        print(f'======== {sys.argv[0]} Error ========')
        #LOG.error(repr(e))
        print(e, file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
