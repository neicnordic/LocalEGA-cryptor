import unittest
from legacryptor.pubring import Pubring


class TestPubring(unittest.TestCase):
    """Pubring

    Testing Pubring."""

    def setUp(self):
        """Setting things up."""
        # self._pubring = Pubring('/path/pubring')

    def test_error_setup(self):
        """Setting up should give an error due to unkown path."""
        with self.assertRaises(ValueError):
            Pubring('/missing/path')
