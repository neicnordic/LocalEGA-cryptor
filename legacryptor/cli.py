import sys
import os
import logging
import logging.config

from docopt import docopt

from . import __title__, __version__

PROG = 'lega-cryptor'
DEFAULT_LOG = os.getenv('LEGA_LOG', None)
DEFAULT_PUBRING = os.getenv('LEGA_PUBRING', os.path.join(os.path.dirname(__file__),'pubring.bin'))

__doc__ = f'''

LocalEGA utilities for the cryptographic GA4GH standard.

Usage:
   {PROG} [-hv] [--log <file>] list [-s <URL> | -p <path>]
   {PROG} [-hv] [--log <file>] encrypt [-r <recipient>] -s <URL> [-i <input>] [-o <output>]
   {PROG} [-hv] [--log <file>] encrypt [-r <recipient>] [-p <path>] [-i <input>] [-o <output>]
   {PROG} [-hv] [--log <file>] encrypt --pk <path> [-i <input>] [-o <output>]
   {PROG} [-hv] [--log <file>] decrypt --sk <path> [-i <input>] [-o <output>]
   {PROG} [-hv] [--log <file>] reencrypt --sk <path> --pk <path> [-i <input>] [-o <output>]
   {PROG} [-hv] [--log <file>] reencrypt --server <url> --keyid <secret> [-i <input>] [-o <output>]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to the logger file (in YML format)
   -s <URL>, --server <URL>     
                          Lists information about all keys in the keyserver
   -p <file>, --pubring <file>  
                          Lists information about all keys in the pubring.
                          If not specified, a default pubring is used either from the
                          LEGA_PUBRING environment variable (if it exists) or as the one
                          suppied within this package.
   -r RECIPIENT           Encrypt for the given recipient [default: ega@crg.eu]
   --pk <keyfile>         Public PGP key to be used for encryption
   --sk <keyfile>         Private PGP key to be used for decryption
   --keyid <id>           Key ID used to retrieve the key material from the keyserver
   -i <file>, --input <file>
                          Input file. If not specified, it uses stdin
   -o <file>, --output <file>
                          Output file.  If not specified, it uses stdout

Environment variables:
   LEGA_LOG       If defined, it will be used as the default logger
   LEGA_PUBRING   If defined, it will be used as the default pubring

'''

def parse_args(argv=sys.argv[1:]):

    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # if args['version']: print(version); sys.exit(0)
    # if args['help']: print(__doc__.strip()); sys.exit(0)

    # Logging
    logger = args['--log'] or DEFAULT_LOG
    if logger and os.path.exists(logger):
        with open(logger, 'rt') as stream:
            import yaml
            logging.config.dictConfig(yaml.load(stream))

    if ((args['list'] or args['encrypt']) and 
        (not args['--pubring'] and not args['--server'])):
        args['--pubring'] = DEFAULT_PUBRING

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    #print(args)
    return args



