import unittest
import ssl
import whoisit


class SSLTestCase(unittest.TestCase):

    maxDiff = None

    def test_allow_insecure_ssl(self):
        # Dig into the requests then urllib3 internals to check
        # the cipher suite that has been provided to the SSL context
        whoisit_session = whoisit.get_session()
        # Specifically the https:// scheme requests adapter
        https_adapter = whoisit_session.get_adapter('https://')
        pool_manager = https_adapter.poolmanager
        # Any https:// scheme prefix is fine here
        connection_pool = pool_manager.connection_from_url('https://test')
        # Internal urllib3 method, this doesn't actually connect yet but
        # has an ssl_context set
        new_connection = connection_pool._new_conn()
        # With a secure (default) session the ssl_context here should be None
        self.assertEqual(new_connection.ssl_context, None)
        # Create a new session that allows insecure SSL connections
        del whoisit_session
        whoisit_session = whoisit.get_session(allow_insecure_ssl=True)
        https_adapter = whoisit_session.get_adapter('https://')
        pool_manager = https_adapter.poolmanager
        connection_pool = pool_manager.connection_from_url('https://test')
        new_connection = connection_pool._new_conn()
        # ssl_context should now be an ssl.SSLContext instance
        self.assertIsInstance(new_connection.ssl_context, ssl.SSLContext)
        insecure_ciphers = new_connection.ssl_context.get_ciphers()
        # insecure_ciphers should be a list of dicts of ciphers and
        # now contain old, insecure ciphers
        self.assertIsInstance(insecure_ciphers, list)
        found_insecure_ciphers = False
        for insecure_cipher in insecure_ciphers:
            # SSLv3 is not a secure cipher and will only be present if insecure
            # ciphers have been permitted
            if insecure_cipher.get('protocol', '') == 'SSLv3':
                found_insecure_ciphers = True
        self.assertEqual(found_insecure_ciphers, True)
