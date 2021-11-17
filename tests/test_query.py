import requests
import unittest
import json
from pathlib import Path
from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address
import whoisit


BASE_DIR = Path(__file__).resolve().parent


class QueryTestCase(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        whoisit.clear_bootstrapping()
        with open(BASE_DIR / 'data_bootstrap.json', 'rt') as f:
            whoisit.load_bootstrap_data(f.read())

    def test_adding_query_url_params(self):
        url = 'https://example.com/'
        s = requests.Session()
        q = whoisit.query.Query(s, 'GET', url)
        params = {'test': 'test'}
        expected = 'https://example.com/?test=test'
        self.assertEqual(q.add_url_params(url, params), expected)
        params = {'test': 123}
        expected = 'https://example.com/?test=123'
        self.assertEqual(q.add_url_params(url, params), expected)

    def test_build(self):

        # Invalid build query requests
        with self.assertRaises(whoisit.errors.QueryError):
            whoisit.build_query(query_type='test', query_value=1)
        with self.assertRaises(whoisit.errors.QueryError):
            whoisit.build_query(query_type=b'test', query_value=1)
        with self.assertRaises(whoisit.errors.QueryError):
            whoisit.build_query(query_type={}, query_value=1)
        with self.assertRaises(whoisit.errors.QueryError):
            whoisit.build_query(query_type=None, query_value=1)
        with self.assertRaises(whoisit.errors.QueryError):
            whoisit.build_query()

        # ASN requests
        method, url, exact_match = whoisit.build_query(query_type='asn',
                                                       query_value=123)
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.arin.net/registry/autnum/123')
        method, url, exact_match = whoisit.build_query(query_type='asn',
                                                       query_value=61952)
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.db.ripe.net/autnum/61952')

        # Domain requests
        method, url, exact_match = whoisit.build_query(query_type='domain',
                                                       query_value='test.com')
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.verisign.com/com/v1/domain/test.com')
        method, url, exact_match = whoisit.build_query(query_type='domain',
                                                       query_value='test.no')
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.norid.no/domain/test.no')
        # TLD with no RDAP service should raise a UnsupportedError
        with self.assertRaises(whoisit.errors.UnsupportedError):
            whoisit.build_query(query_type='domain', query_value='test.test')

        # IP requests
        method, url, exact_match = whoisit.build_query(
            query_type='ip', query_value='1.1.1.1')
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.apnic.net/ip/1.1.1.1')
        method, url, exact_match = whoisit.build_query(
            query_type='ip', query_value=IPv4Address('1.1.1.1'))
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.apnic.net/ip/1.1.1.1')
        method, url, exact_match = whoisit.build_query(
            query_type='ip', query_value=IPv4Network('1.1.1.0/24'))
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.apnic.net/ip/1.1.1.0/24')
        method, url, exact_match = whoisit.build_query(
            query_type='ip', query_value='2606:4700:4700::1111')
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.arin.net/registry/ip/2606:4700:4700::1111')
        method, url, exact_match = whoisit.build_query(
            query_type='ip', query_value=IPv6Address('2606:4700:4700::1111'))
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.arin.net/registry/ip/2606:4700:4700::1111')
        method, url, exact_match = whoisit.build_query(
            query_type='ip', query_value=IPv6Network('2606:4700::/32'))
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.arin.net/registry/ip/2606:4700::/32')

    def test_building_override_request(self):
        # Test that overriding the endpoint works, 1.1.1.1 is not allocated to afrinic
        method, url, exact_match = whoisit.build_query(query_type='ip',
                                                       query_value='1.1.1.1',
                                                       rir='afrinic')
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.afrinic.net/rdap/ip/1.1.1.1')
        # ... or ripe
        method, url, exact_match = whoisit.build_query(query_type='ip',
                                                       query_value='1.1.1.1',
                                                       rir='ripe')
        self.assertEqual(method, 'GET')
        self.assertEqual(url, 'https://rdap.db.ripe.net/ip/1.1.1.1')
