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


import requests  # noqa: E402
import whoisit  # noqa: E402
from whoisit.logger import get_logger  # noqa: E402
from whoisit.errors import UnsupportedError  # noqa: E402
from whoisit.overrides import iana_overrides  # noqa: E402


log = get_logger("tools")
overrides: dict = iana_overrides.get("domain", {})
ROOT_TLD_URL: str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


def fetch_root_tlds(url: str) -> list[str]:
    root_tlds = []
    response = requests.get(url)
    for line in response.iter_lines(decode_unicode=True):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        root_tlds.append(line.lower())
    return list(sorted(root_tlds))


def get_endpoint(tld: str) -> tuple[list[str], str]:
    try:
        tld_endpoints, match = whoisit._bootstrap.get_dns_endpoints(tld)
        return tld_endpoints, "iana"
    except UnsupportedError:
        tld_endpoints = overrides.get(tld)
        if tld_endpoints:
            return tld_endpoints, "override"
        else:
            return [], "unsupported"


if __name__ == "__main__":
    whoisit.bootstrap()
    log.info(f"Fetching root TLDs from: {ROOT_TLD_URL}")
    tlds = fetch_root_tlds(ROOT_TLD_URL)
    log.info(f"Loaded {len(tlds)} root TLDs")
    for tld in tlds:
        endpoints, label = get_endpoint(tld)
        endpoints_str = " ".join(endpoints)
        if label == "unsupported":
            log.error(f".{tld} UNSUPPORTED")
        else:
            log.info(f".{tld} ({label}) endpoints {endpoints_str}")
    log.info("Done")
