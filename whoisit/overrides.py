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

        # 2023-08-21 - .li has an RDAP endpoint it's just not listed
        'li': ['https://rdap.nic.li/'],

        # 2022-10-17 - .gl and .gl SLDs have RDAP endpoints they're just not listed
        'gl': ['https://rdap.centralnic.com/gl/'],
        'co.gl': ['https://rdap.centralnic.com/co.gl/'],
        'com.gl': ['https://rdap.centralnic.com/com.gl/'],
        'edu.gl': ['https://rdap.centralnic.com/edu.gl/'],
        'gov.gl': ['https://rdap.centralnic.com/gov.gl/'],
        'net.gl': ['https://rdap.centralnic.com/net.gl/'],
        'org.gl': ['https://rdap.centralnic.com/org.gl/'],

        # 2023-09-05 - .nl has an RDAP endpoint it's just not listed
        'nl': ['https://rdap.sidn.nl/'],

        # 2024-04-30 - the Identity Digital RDAP server appears to support these ccTLDs
        'ac': ['https://rdap.identitydigital.services/rdap/'],
        'ag': ['https://rdap.identitydigital.services/rdap/'],
        'bz': ['https://rdap.identitydigital.services/rdap/'],
        'io': ['https://rdap.identitydigital.services/rdap/'],
        'lc': ['https://rdap.identitydigital.services/rdap/'],
        'me': ['https://rdap.identitydigital.services/rdap/'],
        'mn': ['https://rdap.identitydigital.services/rdap/'],
        'pr': ['https://rdap.identitydigital.services/rdap/'],
        'sc': ['https://rdap.identitydigital.services/rdap/'],
        'sh': ['https://rdap.identitydigital.services/rdap/'],
        'vc': ['https://rdap.identitydigital.services/rdap/'],

        # 2024-05-03 - .co has an RDAP endpoint it's just not listed
        'co': ['https://rdap.nic.co/'],
    }

}
