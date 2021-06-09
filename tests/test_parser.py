import unittest
import json
from pathlib import Path
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network
from dateutil.tz import tzoffset, tzutc
import whoisit


BASE_DIR = Path(__file__).resolve().parent


class ParserTestCase(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        whoisit.clear_bootstrapping()
        with open(BASE_DIR / 'data_bootstrap.json', 'rt') as f:
            whoisit.load_bootstrap_data(f.read())

    def test_parser_interface(self):
        with self.assertRaises(whoisit.errors.ParseError):
            whoisit.parser.parse(whoisit._bootstrap, 'invalid', {})
        fake_response = {'handle': 'TEST', 'name': 'test'}
        fake_response['objectClassName'] = 'autnum'
        whoisit.parser.parse(whoisit._bootstrap, 'autnum', fake_response)
        fake_response['objectClassName'] = 'domain'
        whoisit.parser.parse(whoisit._bootstrap, 'domain', fake_response)
        fake_response['objectClassName'] = 'ip network'
        whoisit.parser.parse(whoisit._bootstrap, 'ip', fake_response)
        fake_response['objectClassName'] = 'entity'
        whoisit.parser.parse(whoisit._bootstrap, 'entity', fake_response)

    def test_autnum_response_parser(self):
        with open(BASE_DIR / 'data_rdap_response_asn.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'autnum', test_data)
        self.assertEqual(parsed['type'], 'autnum')
        self.assertEqual(parsed['handle'], 'AS13335')
        self.assertEqual(parsed['name'], 'CLOUDFLARENET')
        self.assertEqual(parsed['url'], 'https://rdap.arin.net/registry/autnum/13335')
        self.assertEqual(parsed['handle'], 'AS13335')
        self.assertEqual(parsed['rir'], 'arin')
        self.assertEqual(parsed['asn_range'], [13335, 13335])
        self.assertEqual(parsed['whois_server'], 'whois.arin.net')
        self.assertEqual(parsed['copyright_notice'], 'Copyright 1997-2021, American Registry for Internet Numbers, Ltd.')
        self.assertEqual(parsed['terms_of_service_url'], 'https://www.arin.net/resources/registry/whois/tou/')
        self.assertEqual(parsed['last_changed_date'], datetime(2017, 2, 17, 18, 4, 32, tzinfo=tzoffset(None, -18000)))
        self.assertEqual(parsed['registration_date'], datetime(2010, 7, 14, 18, 35, 57, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(parsed['entities']['registrant'], {
            'email': '',
            'handle': 'CLOUD14',
            'name': 'Cloudflare, Inc.',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/CLOUD14',
            'whois_server': 'whois.arin.net',
        })
        self.assertEqual(parsed['entities']['abuse'], {
            'email': 'abuse@cloudflare.com',
            'handle': 'ABUSE2916-ARIN',
            'name': 'Abuse',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ABUSE2916-ARIN',
            'whois_server': 'whois.arin.net',
        })
        self.assertEqual(parsed['entities']['noc'], {
            'email': 'noc@cloudflare.com',
            'handle': 'NOC11962-ARIN',
            'name': 'NOC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/NOC11962-ARIN',
            'whois_server': 'whois.arin.net',
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': 'rir@cloudflare.com',
            'handle': 'ADMIN2521-ARIN',
            'name': 'Admin',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ADMIN2521-ARIN',
            'whois_server': 'whois.arin.net'
        })

    def test_domain_response_parser(self):

        # google.com
        with open(BASE_DIR / 'data_rdap_response_domain1.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'domain', test_data)
        self.assertEqual(parsed['type'], 'domain')
        self.assertEqual(parsed['name'], 'GOOGLE.COM')
        self.assertEqual(parsed['handle'], '2138514_DOMAIN_COM-VRSN')
        self.assertEqual(parsed['rir'], '')
        self.assertEqual(parsed['last_changed_date'], None)
        self.assertEqual(parsed['registration_date'], datetime(1997, 9, 15, 4, 0, tzinfo=tzutc()))
        self.assertEqual(parsed['expiration_date'], datetime(2028, 9, 14, 4, 0, tzinfo=tzutc()))
        self.assertEqual(parsed['url'], 'https://rdap.verisign.com/com/v1/domain/GOOGLE.COM')
        self.assertEqual(parsed['terms_of_service_url'], 'https://www.verisign.com/domain-names/registration-data-access-protocol/terms-service/index.xhtml')
        self.assertEqual(parsed['whois_server'], '')
        self.assertEqual(parsed['copyright_notice'], '')
        self.assertEqual(parsed['nameservers'], [
            'NS1.GOOGLE.COM',
            'NS2.GOOGLE.COM',
            'NS3.GOOGLE.COM',
            'NS4.GOOGLE.COM'
        ])
        self.assertEqual(parsed['status'], [
            'client delete prohibited',
            'client transfer prohibited',
            'client update prohibited',
            'server delete prohibited',
            'server transfer prohibited',
            'server update prohibited'
        ])
        self.assertEqual(parsed['entities']['registrar'], {
            'email': '',
            'handle': '292',
            'name': 'MarkMonitor Inc.',
            'rir': '',
            'type': 'entity',
            'url': '',
            'whois_server': ''
        })

        # norway.no
        with open(BASE_DIR / 'data_rdap_response_domain2.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'domain', test_data)
        self.assertEqual(parsed['type'], 'domain')
        self.assertEqual(parsed['name'], 'norway.no')
        self.assertEqual(parsed['handle'], 'NOR34044D-NORID')
        self.assertEqual(parsed['rir'], '')
        self.assertEqual(parsed['last_changed_date'], datetime(2021, 1, 14, 5, 16, 59, tzinfo=tzutc()))
        self.assertEqual(parsed['registration_date'], datetime(2017, 1, 24, 12, 9, 23, tzinfo=tzutc()))
        self.assertEqual(parsed['expiration_date'], None)
        self.assertEqual(parsed['url'], 'https://rdap.norid.no/domain/norway.no')
        self.assertEqual(parsed['terms_of_service_url'], 'https://www.norid.no/en/domeneoppslag/vilkar')
        self.assertEqual(parsed['whois_server'], '')
        self.assertEqual(parsed['copyright_notice'], '')
        self.assertEqual(parsed['nameservers'], [
            'ns1-09.azure-dns.com',
            'ns2-09.azure-dns.net',
            'ns3-09.azure-dns.org',
            'ns4-09.azure-dns.info'
        ])
        self.assertEqual(parsed['status'], [])
        self.assertEqual(parsed['entities']['registrar'], {
            'email': 'kundeservice@domeneshop.no',
            'handle': 'REG42-NORID',
            'name': 'Domeneshop AS',
            'rir': '',
            'type': 'entity',
            'url': 'https://rdap.norid.no/entity/reg42-NORID',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': 'hostmaster@domeneshop.no',
            'handle': 'DH21326R-NORID',
            'name': 'Domeneshop Hostmaster',
            'rir': '',
            'type': 'entity',
            'url': 'https://rdap.norid.no/entity/DH21326R-NORID',
            'whois_server': ''
        })

    def test_ip_response_parser(self):

        # ipv4 address
        with open(BASE_DIR / 'data_rdap_response_ip_v4.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'ip', test_data)
        self.assertEqual(parsed['type'], 'ip network')
        self.assertEqual(parsed['name'], 'APNIC-LABS')
        self.assertEqual(parsed['handle'], '1.1.1.0 - 1.1.1.255')
        self.assertEqual(parsed['rir'], 'apnic')
        self.assertEqual(parsed['last_changed_date'], datetime(2020, 7, 15, 13, 10, 57, tzinfo=tzutc()))
        self.assertEqual(parsed['registration_date'], None)
        self.assertEqual(parsed['expiration_date'], None)
        self.assertEqual(parsed['url'], 'https://rdap.apnic.net/ip/1.1.1.0/24')
        self.assertEqual(parsed['terms_of_service_url'], 'http://www.apnic.net/db/dbcopyright.html')
        self.assertEqual(parsed['whois_server'], 'whois.apnic.net')
        self.assertEqual(parsed['copyright_notice'], '')
        self.assertEqual(parsed['description'], [
            'APNIC and Cloudflare DNS Resolver project',
            'Routed globally by AS13335/Cloudflare',
            'Research prefix for APNIC Labs'
        ])
        self.assertEqual(parsed['entities']['administrative'], {
            'email': 'research@apnic.net',
            'handle': 'AR302-AP',
            'name': 'APNIC RESEARCH',
            'rir': 'apnic',
            'type': 'entity',
            'url': 'https://rdap.apnic.net/entity/AR302-AP',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['abuse'], {
            'email': 'helpdesk@apnic.net',
            'handle': 'IRT-APNICRANDNET-AU',
            'name': 'IRT-APNICRANDNET-AU',
            'rir': 'apnic',
            'type': 'entity',
            'url': 'https://rdap.apnic.net/entity/IRT-APNICRANDNET-AU',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': 'research@apnic.net',
            'handle': 'AR302-AP',
            'name': 'APNIC RESEARCH',
            'rir': 'apnic',
            'type': 'entity',
            'url': 'https://rdap.apnic.net/entity/AR302-AP',
            'whois_server': ''
        })

        # ipv4 network
        with open(BASE_DIR / 'data_rdap_response_cidr_v4.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'ip', test_data)
        self.assertEqual(parsed['type'], 'ip network')
        self.assertEqual(parsed['name'], 'APNIC-LABS')
        self.assertEqual(parsed['handle'], '1.1.1.0 - 1.1.1.255')
        self.assertEqual(parsed['rir'], 'apnic')
        self.assertEqual(parsed['last_changed_date'], datetime(2020, 7, 15, 13, 10, 57, tzinfo=tzutc()))
        self.assertEqual(parsed['registration_date'], None)
        self.assertEqual(parsed['expiration_date'], None)
        self.assertEqual(parsed['url'], 'https://rdap.apnic.net/ip/1.1.1.0/24')
        self.assertEqual(parsed['terms_of_service_url'], 'http://www.apnic.net/db/dbcopyright.html')
        self.assertEqual(parsed['whois_server'], 'whois.apnic.net')
        self.assertEqual(parsed['copyright_notice'], '')
        self.assertEqual(parsed['assignment_type'], 'assigned portable')
        self.assertEqual(parsed['country'], 'AU')
        self.assertEqual(parsed['ip_version'], 4)
        self.assertEqual(parsed['network'], IPv4Network('1.1.1.0/24'))
        self.assertEqual(parsed['description'], [
            'APNIC and Cloudflare DNS Resolver project',
            'Routed globally by AS13335/Cloudflare',
            'Research prefix for APNIC Labs'
        ])
        self.assertEqual(parsed['entities']['administrative'], {
            'email': 'research@apnic.net',
            'handle': 'AR302-AP',
            'name': 'APNIC RESEARCH',
            'rir': 'apnic',
            'type': 'entity',
            'url': 'https://rdap.apnic.net/entity/AR302-AP',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['abuse'], {
            'email': 'helpdesk@apnic.net',
            'handle': 'IRT-APNICRANDNET-AU',
            'name': 'IRT-APNICRANDNET-AU',
            'rir': 'apnic',
            'type': 'entity',
            'url': 'https://rdap.apnic.net/entity/IRT-APNICRANDNET-AU',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': 'research@apnic.net',
            'handle': 'AR302-AP',
            'name': 'APNIC RESEARCH',
            'rir': 'apnic',
            'type': 'entity',
            'url': 'https://rdap.apnic.net/entity/AR302-AP',
            'whois_server': ''
        })

        # ipv6 address
        with open(BASE_DIR / 'data_rdap_response_ip_v6.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'ip', test_data)
        self.assertEqual(parsed['type'], 'ip network')
        self.assertEqual(parsed['name'], 'GOOGLE-IPV6')
        self.assertEqual(parsed['handle'], 'NET6-2001-4860-1')
        self.assertEqual(parsed['parent_handle'], 'NET6-2001-4800-0')
        self.assertEqual(parsed['rir'], 'arin')
        self.assertEqual(parsed['last_changed_date'], datetime(2012, 2, 24, 9, 44, 34, tzinfo=tzoffset(None, -18000)))
        self.assertEqual(parsed['registration_date'], datetime(2005, 3, 14, 11, 31, 8, tzinfo=tzoffset(None, -18000)))
        self.assertEqual(parsed['expiration_date'], None)
        self.assertEqual(parsed['url'], 'https://rdap.arin.net/registry/ip/2001:4860::')
        self.assertEqual(parsed['terms_of_service_url'], 'https://www.arin.net/resources/registry/whois/tou/')
        self.assertEqual(parsed['whois_server'], 'whois.arin.net')
        self.assertEqual(parsed['copyright_notice'], 'Copyright 1997-2021, American Registry for Internet Numbers, Ltd.')
        self.assertEqual(parsed['assignment_type'], 'direct allocation')
        self.assertEqual(parsed['ip_version'], 6)
        self.assertEqual(parsed['network'], IPv6Network('2001:4860::/32'))
        self.assertEqual(parsed['description'], [])
        self.assertEqual(parsed['entities']['registrant'], {
            'email': '',
            'handle': 'GOGL',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/GOGL',
            'whois_server': 'whois.arin.net'
        })
        self.assertEqual(parsed['entities']['noc'], {
            'email': 'arin-contact@google.com',
            'handle': 'ZG39-ARIN',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ZG39-ARIN',
            'whois_server': 'whois.arin.net'
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': 'arin-contact@google.com',
            'handle': 'ZG39-ARIN',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ZG39-ARIN',
            'whois_server': 'whois.arin.net'
        })
        self.assertEqual(parsed['entities']['abuse'], {
            'email': 'arin-contact@google.com',
            'handle': 'ZG39-ARIN',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ZG39-ARIN',
            'whois_server': 'whois.arin.net'
        })

        # ipv6 network
        with open(BASE_DIR / 'data_rdap_response_cidr_v6.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'ip', test_data)
        self.assertEqual(parsed['type'], 'ip network')
        self.assertEqual(parsed['name'], 'GOOGLE-IPV6')
        self.assertEqual(parsed['handle'], 'NET6-2001-4860-1')
        self.assertEqual(parsed['parent_handle'], 'NET6-2001-4800-0')
        self.assertEqual(parsed['rir'], 'arin')
        self.assertEqual(parsed['last_changed_date'], datetime(2012, 2, 24, 9, 44, 34, tzinfo=tzoffset(None, -18000)))
        self.assertEqual(parsed['registration_date'], datetime(2005, 3, 14, 11, 31, 8, tzinfo=tzoffset(None, -18000)))
        self.assertEqual(parsed['expiration_date'], None)
        self.assertEqual(parsed['url'], 'https://rdap.arin.net/registry/ip/2001:4860::')
        self.assertEqual(parsed['terms_of_service_url'], 'https://www.arin.net/resources/registry/whois/tou/')
        self.assertEqual(parsed['whois_server'], 'whois.arin.net')
        self.assertEqual(parsed['copyright_notice'], 'Copyright 1997-2021, American Registry for Internet Numbers, Ltd.')
        self.assertEqual(parsed['assignment_type'], 'direct allocation')
        self.assertEqual(parsed['ip_version'], 6)
        self.assertEqual(parsed['network'], IPv6Network('2001:4860::/32'))
        self.assertEqual(parsed['description'], [])
        self.assertEqual(parsed['entities']['registrant'], {
            'email': '',
            'handle': 'GOGL',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/GOGL',
            'whois_server': 'whois.arin.net'
        })
        self.assertEqual(parsed['entities']['noc'], {
            'email': 'arin-contact@google.com',
            'handle': 'ZG39-ARIN',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ZG39-ARIN',
            'whois_server': 'whois.arin.net'
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': 'arin-contact@google.com',
            'handle': 'ZG39-ARIN',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ZG39-ARIN',
            'whois_server': 'whois.arin.net'
        })
        self.assertEqual(parsed['entities']['abuse'], {
            'email': 'arin-contact@google.com',
            'handle': 'ZG39-ARIN',
            'name': 'Google LLC',
            'rir': 'arin',
            'type': 'entity',
            'url': 'https://rdap.arin.net/registry/entity/ZG39-ARIN',
            'whois_server': 'whois.arin.net'
        })

    def test_entity_response_parser(self):
        with open(BASE_DIR / 'data_rdap_response_entity.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, 'ip', test_data)
        self.assertEqual(parsed['type'], 'entity')
        self.assertEqual(parsed['name'], '')
        self.assertEqual(parsed['handle'], 'IPAM2-RIPE')
        self.assertEqual(parsed['parent_handle'], '')
        self.assertEqual(parsed['rir'], 'ripe')
        self.assertEqual(parsed['last_changed_date'], datetime(2020, 8, 24, 20, 23, 47, tzinfo=tzutc()))
        self.assertEqual(parsed['registration_date'], None)
        self.assertEqual(parsed['expiration_date'], None)
        self.assertEqual(parsed['url'], 'https://rdap.db.ripe.net/entity/IPAM2-RIPE')
        self.assertEqual(parsed['terms_of_service_url'], 'http://www.ripe.net/db/support/db-terms-conditions.pdf')
        self.assertEqual(parsed['whois_server'], 'whois.ripe.net')
        self.assertEqual(parsed['copyright_notice'], '')
        self.assertEqual(parsed['description'], [])
        self.assertEqual(parsed['entities']['registrant'], {
            'email': '',
            'handle': 'ORG-NI9-RIPE',
            'name': '',
            'rir': '',
            'type': 'entity',
            'url': '',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['administrative'], {
            'email': '',
            'handle': 'WB1700-RIPE',
            'name': '',
            'rir': '',
            'type': 'entity',
            'url': '',
            'whois_server': ''
        })
        self.assertEqual(parsed['entities']['technical'], {
            'email': '',
            'handle': 'WB1700-RIPE',
            'name': '',
            'rir': '',
            'type': 'entity',
            'url': '',
            'whois_server': ''
        })
