from setuptools import setup

setup(
    name='ntruencrypt',
    version='1.0',
    description='A libntruencrypt python wrapper',
    url='https://github.com/SnowyCoder/ntruencryptlib-wrapper',
    author='Rossi Lorenzo',
    author_email='rossilorenzo@mail.com',
    license='MIT',
    keywords='Bitcoin wallet BIP32 BIP38 BIP39 secp256k1',
    packages=['ntruencrypt'],
    test_suite="tests",
    project_urls={
        'Source': 'https://github.com/SnowyCoder/ntruencryptlib-wrapper',
        'Tracker': 'https://github.com/SnowyCoder/ntruencryptlib-wrapper/issues',
    }
)
