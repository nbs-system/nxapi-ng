from setuptools import setup, find_packages

with open('requirements.txt') as f:
    required = map(str.strip, f.read().splitlines())

setup(
    name='nxapi',
    packages=find_packages(),
    version='0.1',
    install_requires=['python-pcre']
)
