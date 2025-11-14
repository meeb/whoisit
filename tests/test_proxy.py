import unittest


import whoisit


class ProxyTestCase(unittest.TestCase):

    maxDiff = None

    def test_proxy(self):
        self.assertEqual(whoisit.get_proxy(), None)
        whoisit.set_proxy('http://localhost:1111')
        self.assertEqual(whoisit.get_proxy(), 'http://localhost:1111')
        whoisit.set_proxy('http://localhost:2222')
        self.assertEqual(whoisit.get_proxy(), 'http://localhost:2222')
        whoisit.clear_proxy()
        self.assertEqual(whoisit.get_proxy(), None)
