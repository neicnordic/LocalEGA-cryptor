import unittest
from testfixtures import tempdir
import os
import pgpy
from legacryptor.crypt4gh import encrypt, decrypt
from . import gpg_data


class TestCrypt4GH(unittest.TestCase):
    """Crypt4GH

    Testing Crypt4GH encryption/decryption and reencryption."""

    @tempdir()
    def test_encrypt(self, dir):
        """Testing Crypt4GH encryption."""
        infile = dir.write('infile.in', gpg_data.ORG_FILE)
        keyfile = dir.write('key.asc', gpg_data.PGP_PUBKEY.encode('utf-8'))
        outputdir = dir.makedir('output')
        key, _ = pgpy.PGPKey.from_file(keyfile)
        encrypt(open(infile, 'rb'), None, open(os.path.join(outputdir, 'outputfile.out'), 'wb'), key)
        result = dir.read(('output', 'outputfile.out')).hex()
        # 6372797074346768 in string format is crypt4gh
        self.assertTrue(str.startswith(result, '6372797074346768'))
        dir.cleanup()

    @tempdir()
    def test_decrypt(self, dir):
        """Testin Crypt4GH decryption."""
        pass
