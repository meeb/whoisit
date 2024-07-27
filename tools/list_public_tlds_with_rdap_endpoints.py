#!/usr/bin/env python
"""
    Lists all public root TLDs and checks if they have a known RDAP endpoint
    in the IANA bootstrap data. Used for testing which TLDs may not work and
    could require an override.
"""


import sys
from pathlib import Path


parent_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(parent_dir))


import requests

import whoisit
from whoisit.logger import get_logger
from whoisit.errors import UnsupportedError
from whoisit.overrides import iana_overrides


log = get_logger('tools')
overrides = iana_overrides.get('domain', {})
ROOT_TLD_URL = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'


def fetch_root_tlds(url):
    tlds = []
    response = requests.get(url)
    for line in response.iter_lines(decode_unicode=True):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        tlds.append(line.lower())
    return list(sorted(tlds))


def get_endpoint(tld):
    try:
        endpoints, match = whoisit._bootstrap.get_dns_endpoints(tld)
        return endpoints, 'iana'
    except UnsupportedError:
        endpoints = overrides.get(tld)
        if endpoints:
            return endpoints, 'override'
        else:
            return [], 'unsupported'


if __name__ == '__main__':
    whoisit.bootstrap()
    log.info(f'Fetching root TLDs from: {ROOT_TLD_URL}')
    tlds = fetch_root_tlds(ROOT_TLD_URL)
    log.info(f'Loaded {len(tlds)} root TLDs')
    for tld in tlds:
        endpoints, label = get_endpoint(tld)
        endpoints_str = ' '.join(endpoints)
        if label == 'unsupported':
            log.error(f'.{tld} UNSUPPORTED')
        else:
            log.info(f'.{tld} ({label}) endpoints {endpoints_str}')
    log.info(f'Done')
