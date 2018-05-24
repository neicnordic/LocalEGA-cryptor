#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import logging

import pgpy

from .crypt4gh import encrypt, decrypt, reencrypt
from .cli import parse_args
from .pubring import Pubring

LOG = logging.getLogger(__name__)

def run(args):

    # Parse CLI arguments
    args = parse_args(args)

    #####################################
    ## Listing Recipients in the pubring
    #####################################
    if args['list']:

        if args['--server']:
            endpoint = args['--server'] + "/list"
            LOG.debug('Contacting %s', endpoint)
            raise NotImplementedError('Non offline mode not implemented...yet')
            return 0
        else:
            ring = Pubring(args['--pubring'])
            print(repr(ring))
            return 0

    #####################################
    ## For Encryption
    ##################################### 
    if args['encrypt']:

        if args['--pk']:
            pubkey, _ = pgpy.PGPKey.from_file(args['--pk'])
        else:
            # Get recipient
            recipient = args['-r']
            if args['--server']:
                from urllib.parse import quote
                endpoint = args['--server'] % quote(recipient) # handle injections
                LOG.debug('Contacting %s', endpoint)
                pubkey = None
                raise NotImplementedError('Non offline mode not implemented...yet')
            else:
                ring = Pubring(args['--pubring'])
                LOG.debug('Finding key for "%s" in %s', recipient, ring)
                pubkey = ring[recipient] # might raise PGPError if not found
                LOG.info('Public Key (for %s) %s', recipient, repr(pubkey))

        infile = open(args['--input'], 'rb') if args['--input'] else sys.stdin.buffer
        outfile = open(args['--output'], 'wb') if args['--output'] else sys.stdout.buffer
        return encrypt(infile, outfile, pubkey)

    #####################################
    ## For Encryption
    ##################################### 
    if args['decrypt']:

        seckey,_ = pgpy.PGPKey.from_file(args['--sk'])
        with seckey.unlock(args['--passphrase']) as privkey:
            infile = open(args['--input'], 'rb') if args['--input'] else sys.stdin.buffer
            outfile = open(args['--output'], 'wb') if args['--output'] else sys.stdout.buffer
            return decrypt(infile, outfile, privkey)

    #####################################
    ## For ReEncryption
    #####################################
    if args['reencrypt']:

        seckey,_ = pgpy.PGPKey.from_file(args['--sk']) # or get it from server
        with seckey.unlock(args['--passphrase']) as privkey:

            pubkey, _ = pgpy.PGPKey.from_file(args['--pk'])
            infile = open(args['--input'], 'rb') if args['--input'] else sys.stdin.buffer
            outfile = open(args['--output'], 'wb') if args['--output'] else sys.stdout.buffer
            return reencrypt(infile, outfile, pubkey, privkey)


    return 0

def main(args=sys.argv[1:]):
    try:
        return run(args)
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(e, file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
