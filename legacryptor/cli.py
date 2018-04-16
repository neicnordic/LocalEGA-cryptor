import sys
import os
import argparse
import logging.config

import yaml

from . import __title__, __version__
from .utils import is_power_two

DEFAULT_LOG = os.getenv('LOG_YML', os.path.join(os.path.dirname(__file__),'logger.yaml'))
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.bin'))

def parse_args(args=None):

    if not args:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(prog='lega-cryptor',
                                     description='''Encrypt file into a PGP message.''')
    parser.add_argument('--log'                               , help="The logger configuration file", default=DEFAULT_LOG)
    parser.add_argument('-v','--version', action='version', version=f'{__title__} {__version__}')

    # For Pubring
    recipients = parser.add_argument_group('About the Recipients')
    recipients.add_argument('-l', '--list-keys', dest='list_keys',
                            action='store_true',
                            help="List the available public keys and exits")
    recipients.add_argument('-p','--pubring', dest='pubring',
                            help=f"Path to the public key ring. If unspecified, it uses the one supplied with this package.",
                            default=DEFAULT_PUBRING)
    recipients.add_argument('-r', '--recipient' , dest='recipient',
                            help="Name, email or anything to find the recipient of the message in the adjacent keyring. If unspecified, it defaults to EBI.",
                            default= '@ebi.ac.uk')
    
    # For Encryption
    encryption = parser.add_argument_group('About the Encryption')
    encryption.add_argument('-s', '--chunk_size', dest='chunk',
                            help="Size of the chunks. Must be a power of 2. [Default: 4096 bytes]",
                            default=4096) # 1 << 12
    encryption.add_argument('-o', '--output', dest='output',
                            help="output directory for the 3 created files",
                            default='.')

    # Finally... the list of files
    parser.add_argument('filename', nargs='*', help="The path of the files to decrypt")


    _args = parser.parse_args()

    # Check is chunk is power of 2
    if not is_power_two(_args.chunk):
        raise ValueError(f'The --chunk_size value "{args.chunk}" should be a power of 2')

    # Logging
    if os.path.exists(_args.log):
        with open(_args.log, 'rt') as stream:
            logging.config.dictConfig(yaml.load(stream))
    
    return _args
