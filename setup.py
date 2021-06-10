import os
import sys
from setuptools import setup, find_packages
from whoisit.version import version


with open('README.md', 'rt') as f:
    long_description = f.read()


with open('requirements.txt', 'rt') as f:
    requirements = tuple(f.read().split())


setup(
    name = 'whoisit',
    version = version,
    url = 'https://github.com/meeb/whoisit',
    author = 'https://github.com/meeb',
    author_email = 'meeb@meeb.org',
    description = 'A Python client to RDAP WHOIS-like services for internet resources.',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    license = 'BSD',
    include_package_data = True,
    install_requires = requirements,
    packages = find_packages(),
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords = ('whoisit', 'whois', 'rdap', 'ip', 'network', 'cidr', 'prefix', 'domain',
                'asn', 'autnum', 'tld', 'entity', 'handle', 'arin', 'afrinic', 'apnic',
                'ripe', 'lacnic')
)
