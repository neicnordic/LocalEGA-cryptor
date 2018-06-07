[![Build Status](https://travis-ci.org/NBISweden/LocalEGA-cryptor.svg?branch=master)](https://travis-ci.org/NBISweden/LocalEGA-cryptor)
[![Coverage Status](https://coveralls.io/repos/github/NBISweden/LocalEGA--cryptor/badge.svg?branch=master)](https://coveralls.io/github/NBISweden/LocalEGA-cryptor?branch=master)

`lega-cryptor` is a tool to encrypt, decrypt or re-encrypt files
according to the [GA4GH cryptographic standard](add the link).

# Installation

```
git clone https://github.com/NBISweden/LocalEGA-cryptor
pip install -r LocalEGA-cryptor/requirements.txt
pip install -e ./LocalEGA-cryptor
```

or

```
pip install git+https://github.com/NBISweden/LocalEGA-cryptor.git
```

# Usage

The usual `-h` flag shows you the different options that the tool accepts.

```bash
$ lega-cryptor -h
LocalEGA utilities for the cryptographic GA4GH standard.

Usage:
   lega-cryptor [-hv] [--log <file>] list [-s <URL> | -p <path>]
   lega-cryptor [-hv] [--log <file>] encrypt [-r <recipient>] -s <URL> [-i <input>] [-o <output>]
   lega-cryptor [-hv] [--log <file>] encrypt [-r <recipient>] [-p <path>] [-i <input>] [-o <output>]
   lega-cryptor [-hv] [--log <file>] encrypt --pk <path> [-i <input>] [-o <output>]
   lega-cryptor [-hv] [--log <file>] decrypt --sk <path> [-i <input>] [-o <output>]
   lega-cryptor [-hv] [--log <file>] reencrypt --sk <path> --pk <path> [-i <input>] [-o <output>]
   lega-cryptor [-hv] [--log <file>] reencrypt --server <url> --keyid <secret> [-i <input>] [-o <output>]

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
                          supplied within this package.
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
```

# Finding which public key to use

```bash
$ lega-cryptor list
Available keys from [path redacted]/legacryptor/pubring.bin
╔══════════════════╦════════════════╦═════════════════════╦════════════════════════════════════════╗
║ Key ID           ║ User Name      ║ User Email          ║ User Comment                           ║
╠══════════════════╬════════════════╬═════════════════════╬════════════════════════════════════════╣
║ 783A1FDBD9899BBA ║ EGA Sweden     ║ ega@nbis.se         ║ @NBIS                                  ║
║ F57E35FE22290D3A ║ EGA Finland    ║ ega@csc.fi          ║ @CSC                                   ║
║ 3D214775952B5529 ║ EGA_Public_key ║ ega-admin@ebi.ac.uk ║ Public key protected with a passphrase ║
║ 6148E9185EB5F733 ║ EGA CRG        ║ ega@crg.eu          ║ @CRG                                   ║
╚══════════════════╩════════════════╩═════════════════════╩════════════════════════════════════════╝
The first substring that matches the requested recipient will be used as the encryption key
Alternatively, you can use the KeyID itself
```

> Note: The hereabove output might differ from your output.
> The associated public keyring is just used for the demo.

## Creating a Custom Public Keyring

In order to create a custom Public keyring in a custom `/path` one can make use of:

```
gpg --no-default-keyring --keyring /path/pubring.bin --import /path/key.pub
```
Repeat the process for multiple keys.

# Examples

If you want to encrypt a file, say, for the Swedish Local EGA instance:


```bash
$ lega-cryptor encrypt -r Sweden < inputfile > outputfile
```

or equivalently,
```bash
$ lega-cryptor encrypt -r nbis.se < inputfile > outputfile
$ lega-cryptor encrypt -r 783A1FDBD9899BBA < inputfile > outputfile
$ lega-cryptor encrypt -r Sweden -i inputfile -o outputfile
```
# File Format

Refer to the [following slide](https://docs.google.com/presentation/d/1Jg0cUCLBO7ctyIWiyTmxb5Il_fQVzKzrxHHzR0K9ZvU/edit#slide=id.g3b7e5ab607_0_2?usp=sharing)

# Demonstration

Here is a demo of the tool using the following scenario: We have pre-created 2 keypairs, namely `test.pub / test.sec` and `test2.pub / test2.sec`, and we run the steps:

1. Encryption with a first public key, here `test.pub`
2. Decryption with the relevant private key (Here the `test.sec`, where the passphrase is given at a no-echo prompt, to unlock it)
3. Re-encryption with a second public key (Here `test2.pub` and the private key `test.sec` from 2)
4. Decryption using the second private key `test2.sec` (along with the no-echo prompted passphrase to unlock it).

[![asciicast](https://asciinema.org/a/ypkjaoDgQOGg2pILdFI4JlFGg.png)](https://asciinema.org/a/ypkjaoDgQOGg2pILdFI4JlFGg)
