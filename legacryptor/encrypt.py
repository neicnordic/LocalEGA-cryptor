# -*- coding: utf-8 -*-

import os
import logging
import hashlib

from .utils import pack_header, encryptor

LOG = logging.getLogger(__name__)

def encrypt_file(pubkey, f, prefix, extension='c4ga', checksum='sha256', chunk_size=4096):

    outfilename = f'{prefix}.{extension}'
    LOG.info("Encrypting %s into %s", f, outfilename)
    with open(outfilename, 'wb') as outfile:

        # One engine, and therefore one session key for each file
        engine = encryptor()

        LOG.info(f'Starting the encrypting engine')
        session_key, nonce = next(engine)

        LOG.info(f'Making the header')
        header = pack_header(pubkey, session_key, nonce)
        outfile.write(header)

        LOG.debug("Streaming content of %s", f)
        with open(f, 'rb') as infile:
            chunk1 = bytearray(chunk_size)
            chunk2 = bytearray(chunk_size)
            chunk_size1 = infile.readinto(chunk1)
            chunk_size2 = infile.readinto(chunk2)
            while True:
                final = (chunk_size2 == 0) # true if chunk2 is empty
                encrypted_data = engine.send( (chunk1, final) )
                outfile.write(encrypted_data)
                if final:
                    break
                # Move chunk2 to chunk1, and read into chunk2
                chunk1, chunk2 = chunk2, chunk1 # swap names, don't touch memory allocation
                chunk_size1 = chunk_size2
                chunk_size2 = infile.readinto(chunk2)

    # Now... the checksums
    org_checksum_name = f'{prefix}.{checksum}'
    LOG.info("Output %s checksum into %s", checksum, org_checksum_name)
    m = hashlib.new(checksum)
    with open(f, 'rb') as org, open(org_checksum_name, 'wt') as orgchecksum:
        m.update(org.read())
        orgchecksum.write(m.hexdigest())
            
    outfile_checksum_name = f'{outfilename}.{checksum}'
    LOG.info("Output %s checksum into %s", checksum, outfile_checksum_name)
    m = hashlib.new(checksum)
    with open(outfile_checksum_name, 'wt') as outfilechecksum, open(outfilename, 'rb') as outfile:
        m.update(outfile.read())
        outfilechecksum.write(m.hexdigest())


def encrypt_files(pubkey, args):
    LOG.debug("Output files in %s", args.output)
    for f in args.filename:
        basename = os.path.basename(f) # Don't use that if you want to keep the tree structure and the command-line filenames
        prefix = os.path.join(args.output,f)
        encrypt_file(pubkey, f, prefix, extension=args.extension, checksum=args.checksum, chunk_size=args.chunk)
