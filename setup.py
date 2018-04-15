from setuptools import setup
from legacryptor import __version__, __author__

setup(name='legacryptor',
      version=__version__,
      url='http://nbisweden.github.io/LocalEGA-cryptor',
      license='Apache License 2.0',
      author=__author__,
      author_email='ega@nbis.se',
      description='Local EGA Cryptor',
      long_description='''\
LocalEGA Cryptor encrypts file using the OpenPGP protocol and some given public keys.

PGP Public keys are contained in the adjacent pubring.pgp file.
''',
      packages=['legacryptor'],
      include_package_data=False,
      package_data={ 'legacryptor': ['pubring.bin'] },
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'lega-cryptor = legacryptor.__main__:main',
          ]
      },
      platforms = 'any',
      # install_requires=[
      #     'cryptography==2.1.4',
      #     'sphinx_rtd_theme',
      #     'terminaltables',
      # ],
)
          
