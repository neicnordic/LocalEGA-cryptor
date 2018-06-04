import unittest
import sys
import os
from legacryptor.cli import parse_args, __doc__
from legacryptor.__main__ import main, run
from pgpy.errors import PGPError
from . import logger_data
from testfixtures import TempDirectory, tempdir


class TestCommandLineARGS(unittest.TestCase):
    """CLI args

    Testing command line argument calls."""

    def test_cmdline_no_args(self):
        """User passes no args, should fail with SystemExit."""
        with self.assertRaises(SystemExit):
            parse_args()

    def test_cmdline_help(self):
        """User passes help, should return help."""
        with self.assertRaises(SystemExit):
            parse_args(['--help'])
            self.assertEquals(__doc__, sys.stdout)

    def test_cmdline_load_logger(self):
        """Should be able to load a custom logger."""
        with TempDirectory() as dir:
            dir.write('logger.yml', logger_data.TEST_LOGGER.encode('utf-8'))
            parse_args(['--log', os.path.join(dir.path, 'logger.yml'), 'list'])

    def test_cmdline_parse_list(self):
        """User should get an args list when asking for keys list."""
        expected = {'--input': None,
                    '--keyid': None,
                    '--output': None,
                    '--pk': None,
                    '--pubring': os.path.join(os.getcwd(), 'legacryptor/pubring.bin'),
                    '--server': None,
                    '--sk': None,
                    '-r': 'ega@crg.eu',
                    'decrypt': False,
                    'encrypt': False,
                    'list': True,
                    'reencrypt': False}
        result = parse_args(['list'])
        self.assertEquals(expected, dict(result))

    def test_cmdline_main_fail(self):
        """Run without commandline args, should exit."""
        with self.assertRaises(SystemExit):
            main()

    def test_cmdline_server_notimplemented(self):
        """Trying to access server keys should raise NotImplementedError."""
        with self.assertRaises(NotImplementedError):
            run(['list', '--server', 'someserver.com'])

    @tempdir()
    def test_cmdline_encrypt_key_notfound(self, dir):
        """Raise error if key not found in default pubring."""
        with self.assertRaises(PGPError):
            run(['encrypt', '-r', 'Denmark'])
