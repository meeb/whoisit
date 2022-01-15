"""
    Various RDAP servers are either incorrect or not listed in the IANA
    bootstrap data. This file contains a list of overrides that are overlayed
    onto the IANA data by default.
"""

iana_overrides = {
    
    'domain': {

        # 2021-11-30 - .de has an RDAP endpoint it's just not listed
        'de': ['https://rdap.denic.de/'],

        # 2022-01-15 - .ch has an RDAP endpoint it's just not listed
        'ch': ['https://rdap.nic.ch/'],

    }

}
