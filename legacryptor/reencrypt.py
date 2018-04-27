# -*- coding: utf-8 -*-

# This module will stip the header part and only reencrypt it

# Strip and decrypting the header is done in decrypt.py
# encrypting the header is done in encrypt.py
# The AES encrypted bulk of each file is left untouched

def reencrypt_file(privkey, pubkey, f):
    raise NotImplementedError('Not yet implemented, but similar to decrypt.py + encrypt.py')

def reencrypt_files(privkey, pubkey, args): 
    raise NotImplementedError('Not yet implemented, but similar to lega/outgest.py')
