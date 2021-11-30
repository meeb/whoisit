import unittest
import json
from pathlib import Path
from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address
import whoisit


BASE_DIR = Path(__file__).resolve().parent


class BootstrapTestCase(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        whoisit.clear_bootstrapping()
        with open(BASE_DIR / 'data_bootstrap.json', 'rt') as f:
            self.bootstrap_data = f.read()
    
    def tearDown(self):
        whoisit.clear_bootstrapping()

    def test_bootstrap_saving(self):
        whoisit.clear_bootstrapping()
        whoisit.load_bootstrap_data(self.bootstrap_data)
        test_dict = json.loads(self.bootstrap_data)
        saved_data = whoisit.save_bootstrap_data()
        saved_dict = json.loads(saved_data)
        self.assertEqual(test_dict, saved_dict)
        whoisit.clear_bootstrapping()

    def test_bootstrap_loading(self):
        whoisit.clear_bootstrapping()
        with self.assertRaises(whoisit.errors.BootstrapError):
            whoisit.load_bootstrap_data('')
        with self.assertRaises(whoisit.errors.BootstrapError):
            whoisit.load_bootstrap_data('{"some":"dict"}')
        with self.assertRaises(whoisit.errors.BootstrapError):
            whoisit.load_bootstrap_data(12345)
        with self.assertRaises(whoisit.errors.BootstrapError):
            whoisit.load_bootstrap_data(b'test')
        whoisit.clear_bootstrapping()
        self.assertFalse(whoisit.is_bootstrapped())
        whoisit.load_bootstrap_data(self.bootstrap_data)
        self.assertTrue(whoisit.is_bootstrapped())
        test_dict = json.loads(self.bootstrap_data)
        for item in whoisit._bootstrap.BOOTSTRAP_URLS.keys():
            self.assertEqual(test_dict[item], whoisit._bootstrap._data[item])
        whoisit.clear_bootstrapping()

    def test_bootstrap_asn_parser(self):
        test_rdap_url = 'https://rdap.example.com/'
        test_data = [[['1-2', '6-7', '9'], [test_rdap_url]]]
        expected = {
            (1, 2): [test_rdap_url],
            (6, 7): [test_rdap_url],
            (9, 9): [test_rdap_url],
        }
        self.assertEqual(whoisit._bootstrap.parse_asn_data(test_data), expected)

    def test_bootstrap_dns_parser(self):
        test_rdap_url = 'https://rdap.example.com/'
        test_data = [[['a', 'b', 'c'], [test_rdap_url]]]
        expected = {
            'a': [test_rdap_url],
            'b': [test_rdap_url],
            'c': [test_rdap_url],
        }
        self.assertEqual(whoisit._bootstrap.parse_dns_data(test_data), expected)

    def test_bootstrap_ipv4_parser(self):
        test_rdap_url = 'https://rdap.example.com/'
        test_data = [[['10.0.0.0/8', '127.0.0.0/8'], [test_rdap_url]]]
        expected = {
            IPv4Network('10.0.0.0/8'): [test_rdap_url],
            IPv4Network('127.0.0.0/8'): [test_rdap_url],
        }
        self.assertEqual(whoisit._bootstrap.parse_ipv4_data(test_data), expected)

    def test_bootstrap_ipv6_parser(self):
        test_rdap_url = 'https://rdap.example.com/'
        test_data = [[['2001:1400::/22', '2001:200::/23'], [test_rdap_url]]]
        expected = {
            IPv6Network('2001:1400::/22'): [test_rdap_url],
            IPv6Network('2001:200::/23'): [test_rdap_url],
        }
        self.assertEqual(whoisit._bootstrap.parse_ipv6_data(test_data), expected)

    def test_bootstrap_ipv6_parser(self):
        test_rdap_url = 'https://rdap.example.com/'
        test_data = [[['does', 'nothing', 'yet'], [test_rdap_url]]]
        expected = {}
        self.assertEqual(whoisit._bootstrap.parse_object_data(test_data), expected)

    def test_bootstrap_full_parsing(self):

        # Load bootstrap data
        whoisit.clear_bootstrapping()
        whoisit.load_bootstrap_data(self.bootstrap_data)

        # ASN endpoint tests
        test = 327691
        expected = ['https://rdap.afrinic.net/rdap/'], True
        self.assertEqual(whoisit._bootstrap.get_asn_endpoints(test), expected)
        test = 4567
        expected = ['https://rdap.arin.net/registry/'], True
        self.assertEqual(whoisit._bootstrap.get_asn_endpoints(test), expected)
        test = 206236
        expected = ['https://rdap.db.ripe.net/'], True
        self.assertEqual(whoisit._bootstrap.get_asn_endpoints(test), expected)
        test = 2047
        expected = ['https://rdap.db.ripe.net/'], True
        self.assertEqual(whoisit._bootstrap.get_asn_endpoints(test), expected)
        # One of the random fallbacks for an invalid ASN
        test = 59438593485903
        random_servers, exact_match = whoisit._bootstrap.get_asn_endpoints(test)
        self.assertTrue(isinstance(random_servers[0], str))
        self.assertEqual(exact_match, False)
        # One of the random fallbacks for an invalid ASN
        test = -1
        random_servers, exact_match = whoisit._bootstrap.get_asn_endpoints(test)
        self.assertTrue(isinstance(random_servers[0], str))
        self.assertEqual(exact_match, False)

        # Domain endpoint tests
        test = 'com'
        expected = ['https://rdap.verisign.com/com/v1/'], True
        self.assertEqual(whoisit._bootstrap.get_dns_endpoints(test), expected)
        test = 'no'
        expected = ['https://rdap.norid.no/'], True
        self.assertEqual(whoisit._bootstrap.get_dns_endpoints(test), expected)
        test = 'dev'
        expected = ['https://www.registry.google/rdap/'], True
        self.assertEqual(whoisit._bootstrap.get_dns_endpoints(test), expected)
        # Invalid TLDs should raise an error
        test = 'testtesttesttesttesttesttesttesttesttesttest'
        with self.assertRaises(whoisit.errors.UnsupportedError):
            whoisit._bootstrap.get_dns_endpoints(test)

        # IPv4 prefix endpoint tests
        test = IPv4Address('1.1.1.1')
        expected = ['https://rdap.apnic.net/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv4_endpoints(test), expected)
        test = IPv4Network('1.1.1.0/24')
        expected = ['https://rdap.apnic.net/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv4_endpoints(test), expected)
        test = IPv4Address('8.8.8.8')
        expected = ['https://rdap.arin.net/registry/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv4_endpoints(test), expected)
        test = IPv4Network('8.8.8.0/24')
        expected = ['https://rdap.arin.net/registry/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv4_endpoints(test), expected)
        with self.assertRaises(whoisit.errors.BootstrapError):
            # Private IP addresses can't have a public RDAP endpoint at all
            whoisit._bootstrap.get_ipv4_endpoints(IPv4Address('127.0.0.1'))

        # IPv6 prefix endpoint tests
        test = IPv6Address('2606:4700:4700::1111')
        expected = ['https://rdap.arin.net/registry/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv6_endpoints(test), expected)
        test = IPv6Network('2606:4700::/32')
        expected = ['https://rdap.arin.net/registry/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv6_endpoints(test), expected)
        test = IPv6Address('2001:67c:2e8:22::c100:68b')
        expected = ['https://rdap.db.ripe.net/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv6_endpoints(test), expected)
        test = IPv6Network('2001:67c:2e8::/48')
        expected = ['https://rdap.db.ripe.net/'], True
        self.assertEqual(whoisit._bootstrap.get_ipv6_endpoints(test), expected)
        with self.assertRaises(whoisit.errors.BootstrapError):
            # Private IP addresses can't have a public RDAP endpoint at all
            whoisit._bootstrap.get_ipv6_endpoints(IPv6Address('fc00::1'))

        # Entity endpoint tests with prefixes
        test = 'ENTITY-RIPE'
        expected = ['https://rdap.db.ripe.net/'], True
        self.assertEqual(whoisit._bootstrap.get_entity_endpoints(test), expected)
        test = 'ENTITY-AP'
        expected = ['https://rdap.apnic.net/'], True
        self.assertEqual(whoisit._bootstrap.get_entity_endpoints(test), expected)
        test = 'ARIN-ENTITY'
        expected = ['https://rdap.arin.net/registry/'], True
        self.assertEqual(whoisit._bootstrap.get_entity_endpoints(test), expected)
        # Entities without a prefix or postfix we can parse are unsupported
        with self.assertRaises(whoisit.errors.UnsupportedError):
            whoisit._bootstrap.get_entity_endpoints('ANYTHING')

        # Clean up
        whoisit.clear_bootstrapping()

    def test_override_endpoint(self):

        # Load bootstrap data
        whoisit.clear_bootstrapping()
        whoisit.load_bootstrap_data(self.bootstrap_data)

        # Invalid RIR endpoint name
        with self.assertRaises(whoisit.errors.BootstrapError):
            whoisit._bootstrap.get_rir_endpoint('test')

        # Check the RIRs are all supported
        for name, endpoint in whoisit._bootstrap.RIR_RDAP_ENDPOINTS.items():
            self.assertEqual(whoisit._bootstrap.get_rir_endpoint(name), endpoint)

        # Check the RIR names are valid
        expected = ('afrinic', 'arin', 'apnic', 'jpnic', 'idnic', 'krnic',
                    'lacnic', 'registro.br', 'ripe', 'twnic')
        self.assertEqual(whoisit._bootstrap.get_rir_endpoint_names(), expected)

        # Clean up
        whoisit.clear_bootstrapping()

    def test_iana_overrides(self):

        # Test iana_overrides are a dict
        from whoisit.overrides import iana_overrides
        self.assertIsInstance(iana_overrides, dict)

        # Test bootstrapping with overrides disabled
        whoisit.clear_bootstrapping()
        whoisit.load_bootstrap_data(self.bootstrap_data)
        self.assertFalse(whoisit._bootstrap.is_using_overrides())
        with self.assertRaises(whoisit.errors.UnsupportedError):
            # .de has no RDAP entry in IANA data currently, this should error
            whoisit._bootstrap.get_dns_endpoints('de')

        # Test bootstrapping with overrides enabled
        whoisit.clear_bootstrapping()
        whoisit.load_bootstrap_data(self.bootstrap_data, overrides=True)
        self.assertTrue(whoisit._bootstrap.is_using_overrides())
        # .de has endpoint overrides
        override_endpoints, match = whoisit._bootstrap.get_dns_endpoints('de')
        self.assertEqual(override_endpoints[0], 'https://rdap.denic.de/')
        self.assertFalse(match)
