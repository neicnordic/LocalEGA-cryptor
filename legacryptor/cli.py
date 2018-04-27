import sys
import os
import argparse
import logging.config

import yaml

from . import __title__, __version__

DEFAULT_LOG = os.getenv('LOG_YML', os.path.join(os.path.dirname(__file__),'logger.yaml'))
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.bin'))

def parse_args(args=None):

    if not args:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(prog='lega-cryptor',
                                     description='''Encrypt, Decrypt or Re-Encrypt files using the Crypt4GA standard.''')
    parser.add_argument('--log'                               , help="The logger configuration file", default=DEFAULT_LOG)
    parser.add_argument('-v','--version', action='version', version=f'{__title__} {__version__}')

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-e','--encrypt',    dest='encrypt',   action='store_true', help="Encrypt the given files")
    mode.add_argument('-d','--decrypt',    dest='decrypt',   action='store_true', help="Decrypt the given files")
    mode.add_argument('-de','--reencrypt', dest='reencrypt', action='store_true', help="Re-Encrypt the given files")
    mode.add_argument('-l', '--list-keys', dest='list_keys', action='store_true', help="List the available public keys and exits")

    # Public keys from PGP key server
    server = parser.add_argument_group('About the PGP KeyServer')
    server.add_argument('-s', '--server', dest='server',
                        help="Endpoint to query public keys. [Default: https://pgp.nbis.se/get/]",
                        default="https://pgp.nbis.se/get/")
    server.add_argument('-n','--offline', dest='offline',
                        action='store_true',
                        help="Disable the server queries and load a local pubring")
    
    # For Pubring
    recipients = parser.add_argument_group('About the Recipients')
    recipients.add_argument('-p','--pubring', dest='pubring',
                            help=f"Path to the public key ring. If unspecified, it uses the one supplied with this package.",
                            default=DEFAULT_PUBRING)
    recipients.add_argument('-r', '--recipient' , dest='recipient',
                            help="Name, email or anything to find the recipient of the message in the adjacent keyring. If unspecified, it defaults to CRG.",
                            default= 'ega@crg.eu')
    
    # For Encryption
    encryption = parser.add_argument_group('About the Encryption')
    encryption.add_argument('-c', '--chunk_size', dest='chunk',
                            help="Each is read in chunks. This parameter sets the buffer size. [Default: 4096 bytes]",
                            default=4096) # 1 << 12
    encryption.add_argument('-o', '--output', dest='output',
                            help="output directory for the 3 created files",
                            default='.')

    encryption.add_argument('-C', '--checksum', dest='checksum',
                            help="Checksum algorithm and extension. [Default: sha256]",
                            default='sha256')
    encryption.add_argument('-E', '--extension', dest='extension',
                            help="Filename Extension. [Default: c4ga]",
                            default='c4ga')

    # Finally... the list of files
    parser.add_argument('filename', nargs='*', help="The path of the files to decrypt")


    _args = parser.parse_args()

    # Logging
    if os.path.exists(_args.log):
        with open(_args.log, 'rt') as stream:
            logging.config.dictConfig(yaml.load(stream))
    
    return _args
