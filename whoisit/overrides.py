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

        # 2022-10-17 - .gl and .gl SLDs have RDAP endpoints they're just not listed
        'gl': ['https://rdap.centralnic.com/gl/'],
        'co.gl': ['https://rdap.centralnic.com/co.gl/'],
        'com.gl': ['https://rdap.centralnic.com/com.gl/'],
        'edu.gl': ['https://rdap.centralnic.com/edu.gl/'],
        'gov.gl': ['https://rdap.centralnic.com/gov.gl/'],
        'net.gl': ['https://rdap.centralnic.com/net.gl/'],
        'org.gl': ['https://rdap.centralnic.com/org.gl/']

    }

}
