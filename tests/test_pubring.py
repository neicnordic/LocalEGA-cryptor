import unittest
from legacryptor.pubring import Pubring
from testfixtures import TempDirectory, tempdir
from . import gpg_data
from terminaltables import DoubleTable


class TestPubring(unittest.TestCase):
    """Pubring

    Testing Pubring."""

    def setUp(self):
        """Setting things up."""
        self._dir = TempDirectory()
        self._path = self._dir.write('pubring.bin', gpg_data.PGP_PUBKEY.encode('utf-8'))
        self._pubring = Pubring(self._path)

    def tearDown(self):
        """Remove files."""
        self._dir.cleanup_all()

    @tempdir()
    def test_error_setup(self, dir):
        """Setting up should give an error due to unkown path."""
        path = dir.write('pubring.bin', ''.encode('utf-8'))
        # the ValueError is raised by PGPy because unproper armored PGP 
        with self.assertRaises(ValueError):
            Pubring(path)
        dir.cleanup()

    def test_load_key(self):
        """Getitem, should return the key."""
        # This identified a bug for example if there is no version in the PGP_PUBKEY
        # PGPy adds its own version e.g. Version: PGPy v0.4.3
        data = str(self._pubring.__getitem__(gpg_data.KEY_ID)).rstrip()  # for some reason PGPy adds a new line at the end
        self.assertEquals(gpg_data.PGP_PUBKEY, data)

    def test_pubring_notempty(self):
        """Pubring should not be empty."""
        self.assertEquals(True, bool(self._pubring))

    def test_pubring_str(self):
        """Get pubring path."""
        self.assertEquals(f'<Pubring from {self._path}>', str(self._pubring))

    def test_pubring_iter(self):
        """Get pubring items."""
        list = [x for x in iter(self._pubring)]
        expected = [(gpg_data.KEY_ID, gpg_data.PGP_NAME, gpg_data.PGP_EMAIL, gpg_data.PGP_COMMENT)]
        self.assertEquals(expected, list)

    def test_pubring_repr(self):
        """Get the table info from Pubring."""
        list_data = [('Key ID', 'User Name', 'User Email', 'User Comment')]
        list_data.append((gpg_data.KEY_ID, gpg_data.PGP_NAME, gpg_data.PGP_EMAIL, gpg_data.PGP_COMMENT))
        table = DoubleTable(list_data)
        data = f'''\
Available keys from {self._path}
{table.table}
The first substring that matches the requested recipient will be used as the encryption key
Alternatively, you can use the KeyID itself'''
        self.assertEquals(data, repr(self._pubring))
