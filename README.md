`lega-cryptor` is a tool to encrypt, decrypt or re-encrypt files
according to the [Crypt4GA standard](add the link).

# Installation

```
git clone https://github.com/NBISweden/LocalEGA-cryptor
pip install -r LocalEGA-cryptor/requirements.txt
pip install -e ./LocalEGA-cryptor/
```

or

```
pip install git+https://github.com/NBISweden/LocalEGA-cryptor.git
```


# Usage

The usual `-h` flag shows you the different options that the tool accepts.

```bash
$ lega-cryptor -h
usage: lega-cryptor [-h] [--log LOG] [-v] (-e | -d | -de | -l) [-s SERVER]
                    [-n] [-p PUBRING] [-r RECIPIENT] [-c CHUNK] [-o OUTPUT]
                    [-C CHECKSUM] [-E EXTENSION]
                    [filename [filename ...]]

Encrypt, Decrypt or Re-Encrypt files using the Crypt4GA standard.

positional arguments:
  filename              The path of the files to decrypt

optional arguments:
  -h, --help            show this help message and exit
  --log LOG             The logger configuration file
  -v, --version         show program's version number and exit
  -e, --encrypt         Encrypt the given files
  -d, --decrypt         Decrypt the given files
  -de, --reencrypt      Re-Encrypt the given files
  -l, --list-keys       List the available public keys and exits

About the PGP KeyServer:
  -s SERVER, --server SERVER
                        Endpoint to query public keys. [Default:
                        https://pgp.nbis.se/get/]
  -n, --offline         Disable the server queries and load a local pubring

About the Recipients:
  -p PUBRING, --pubring PUBRING
                        Path to the public key ring. If unspecified, it uses
                        the one supplied with this package.
  -r RECIPIENT, --recipient RECIPIENT
                        Name, email or anything to find the recipient of the
                        message in the adjacent keyring. If unspecified, it
                        defaults to CRG.

About the Encryption:
  -c CHUNK, --chunk_size CHUNK
                        Each is read in chunks. This parameter sets the buffer
                        size. [Default: 4096 bytes]
  -o OUTPUT, --output OUTPUT
                        output directory for the 3 created files
  -C CHECKSUM, --checksum CHECKSUM
                        Checksum algorithm and extension. [Default: sha256]
  -E EXTENSION, --extension EXTENSION
                        Filename Extension. [Default: c4ga]
```

# Finding which public key to use

```bash
$ lega-cryptor -l
Available keys from [path redacted]/legacryptor/pubring.bin
╔══════════════════╦═══════════════════════════════════════════════════════════════════════════════╗
║ Key ID           ║ User Info                                                                     ║
╠══════════════════╬═══════════════════════════════════════════════════════════════════════════════╣
║ 783A1FDBD9899BBA ║ EGA Sweden (@NBIS) <ega@nbis.se>                                              ║
║ F57E35FE22290D3A ║ EGA Finland (@CSC) <ega@csc.fi>                                               ║
║ 3D214775952B5529 ║ EGA_Public_key (Public key protected with a passphrase) <ega-admin@ebi.ac.uk> ║
║ 6148E9185EB5F733 ║ EGA CRG (@CRG) <ega@crg.eu>                                                   ║
╚══════════════════╩═══════════════════════════════════════════════════════════════════════════════╝
The first substring that matches the requested recipient will be used as the encryption key
Alternatively, you can use the KeyID itself
```

> Note: The hereabove output might differ from your output.
> The associated public keyring is just used for the demo.

# Examples

If you want to encrypt a file (or a list of files), say, for the Swedish Local EGA instance:


```bash
$ lega-cryptor -e -r Sweden -n -o ~/output/directory <file-to-encrypt1> <file-to-encrypt2> ...
```

The `-n` makes you use the package-supplied keyring. It is useful if you don't have access to internet.

Equivalently, you could use:

```bash
$ lega-cryptor -e -r nbis.se -n -o ~/output/directory <file-to-encrypt1> <file-to-encrypt2> ...
```

or

```bash
$ lega-cryptor -e -r 783A1FDBD9899BBA -n -o ~/output/directory <file-to-encrypt1> <file-to-encrypt2> ...
```
