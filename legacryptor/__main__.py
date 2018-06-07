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
        infilesize = os.path.getsize(args['--input']) if args['--input'] else None
        outfile = open(args['--output'], 'wb') if args['--output'] else sys.stdout.buffer
        return encrypt(pubkey, infile, infilesize, outfile)

    #####################################
    ## For Decryption
    ##################################### 
    if args['decrypt']:

        seckey,_ = pgpy.PGPKey.from_file(args['--sk'])
        
        from getpass import getpass
        passphrase = getpass(prompt=f'Passphrase for {args["--sk"]}: ')

        with seckey.unlock(passphrase) as privkey:
            infile = open(args['--input'], 'rb') if args['--input'] else sys.stdin.buffer
            outfile = open(args['--output'], 'wb') if args['--output'] else sys.stdout.buffer
            return decrypt(privkey, infile, outfile)

    #####################################
    ## For ReEncryption
    #####################################
    if args['reencrypt']:

        url = args['--server']
        if url:
            try:
                # Prepare to contact the Keyserver for the Master key
                with urlopen(url) as response:
                    return json.loads(response.read().decode())
            except Exception as e:
                LOG.error(repr(e))
                LOG.critical('Problem contacting the Keyserver. Ingestion Worker terminated')
                return 1
        else:
            seckey,_ = pgpy.PGPKey.from_file(args['--sk']) # or get it from server
            from getpass import getpass
            passphrase = getpass(prompt=f'Passphrase for {args["--sk"]}: ')
            with seckey.unlock(passphrase) as privkey:
                pubkey, _ = pgpy.PGPKey.from_file(args['--pk'])
                infile = open(args['--input'], 'rb') if args['--input'] else sys.stdin.buffer
                outfile = open(args['--output'], 'wb') if args['--output'] else sys.stdout.buffer
                return reencrypt(pubkey, privkey, infile, outfile)


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
