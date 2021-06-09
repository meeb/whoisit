import unittest
import json
from pathlib import Path
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
        fake_response['objectClassName'] = 'ip'
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
        pass

    def test_ip_response_parser(self):
        pass

    def test_entity_response_parser(self):
        pass
