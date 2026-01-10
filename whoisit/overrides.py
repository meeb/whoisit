"""
Various RDAP servers are either incorrect or not listed in the IANA
bootstrap data. This file contains a list of overrides that are overlayed
onto the IANA data by default.

Last updated: 2026-01-05 03:46:00 UTC
"""

iana_overrides: dict[str, ...] = {
    "domain": {
        "ac": ["https://rdap.identitydigital.services/rdap/"],
        "ag": ["https://rdap.identitydigital.services/rdap/"],
        "bh": ["https://rdap.centralnic.com/bh/"],
        "bz": ["https://rdap.identitydigital.services/rdap/"],
        "ch": ["https://rdap.nic.ch/"],
        "co": ["https://rdap.registry.co/co/"],
        "de": ["https://rdap.denic.de/"],
        "gl": ["https://rdap.centralnic.com/gl/"],
        "io": ["https://rdap.identitydigital.services/rdap/"],
        "lc": ["https://rdap.identitydigital.services/rdap/"],
        "li": ["https://rdap.nic.li/"],
        "me": ["https://rdap.identitydigital.services/rdap/"],
        "mn": ["https://rdap.identitydigital.services/rdap/"],
        "my": ["https://rdap.mynic.my/rdap/"],
        "pr": ["https://rdap.identitydigital.services/rdap/"],
        "sc": ["https://rdap.identitydigital.services/rdap/"],
        "sh": ["https://rdap.identitydigital.services/rdap/"],
        "us": ["https://rdap.nic.us/"],
        "vc": ["https://rdap.identitydigital.services/rdap/"],
    }
}
