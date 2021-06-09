import unittest
import json
from pathlib import Path
import whoisit


BASE_DIR = Path(__file__).resolve().parent


class ParserTestCase(unittest.TestCase):

    maxDiff = None

    def test_parser_interface(self):
        with self.assertRaises(whoisit.errors.ParseError):
            whoisit.parser.parse('invalid', {})
        whoisit.parser.parse('autnum', {})
        whoisit.parser.parse('domain', {})
        whoisit.parser.parse('ip', {})
        whoisit.parser.parse('entity', {})

    def test_autnum_response_parser(self):
        with open(BASE_DIR / 'data_rdap_response_asn.json') as f:
            test_data = json.loads(f.read())
        parsed = whoisit.parser.parse('autnum', test_data)

    def test_domain_response_parser(self):
        pass

    def test_ip_response_parser(self):
        pass

    def test_entity_response_parser(self):
        pass
