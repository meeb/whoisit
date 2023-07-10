import os
from urllib3.util import retry
try:
    from urllib3.util import create_urllib3_context
except ImportError:
    from urllib3.util.ssl_ import create_urllib3_context
from urllib3.poolmanager import PoolManager
import requests
from .errors import QueryError, UnsupportedError
from .logger import get_logger
from .version import version


log = get_logger('utils')
user_agent = 'whoisit/{version}'
insecure_ssl_ciphers = 'ALL:@SECLEVEL=1'
http_timeout = 10               # Maximum time in seconds to allow for an HTTP request
http_retry_statuses = [429]     # HTTP status codes to trigger a retry wih backoff
http_max_retries = 3            # Maximum number of HTTP requests to retry before failing
http_pool_connections = 10      # Maximum number of HTTP pooled connections
http_pool_maxsize = 10          # Maximum HTTP pool connection size
_default_session = {'secure': None, 'insecure': False}


def get_session(session=None, allow_insecure_ssl=False):
    """
        Creates and caches the default sessions, one for secure (default) SSL
        and one for SSL with an insecure cipher suite.
    """
    global _default_session
    if session:
        if allow_insecure_ssl:
            if not _default_session['insecure']:
                _default_session['insecure'] = session
            return _default_session['insecure']
        else:
            if not _default_session['secure']:
                _default_session['secure'] = session
            return _default_session['secure']
    else:
        if allow_insecure_ssl:
            _default_session['insecure'] = create_session(allow_insecure_ssl=allow_insecure_ssl)
            return _default_session['insecure']
        else:
            _default_session['secure'] = create_session()
            return _default_session['secure']


class InsecureSSLAdapter(requests.adapters.HTTPAdapter):
    """
        Custom adapter to permit insecure SSL connections.
    """

    def init_poolmanager(self, connections, maxsize, block=False):
        insecure_ssl_ciphersuite = create_urllib3_context(ciphers=insecure_ssl_ciphers)
        self.poolmanager = PoolManager(ssl_context=insecure_ssl_ciphersuite)


def create_session(allow_insecure_ssl=False):
    session = requests.session()
    session_retry = retry.Retry(total=http_max_retries,
                                status_forcelist=http_retry_statuses,
                                backoff_factor=1)
    whoisit_adapter = requests.adapters.HTTPAdapter(
        max_retries=session_retry,
        pool_connections=http_pool_connections,
        pool_maxsize=http_pool_maxsize)
    session.mount('https://', whoisit_adapter)
    if allow_insecure_ssl:
        session.mount('https://', InsecureSSLAdapter())
    return session


def http_request(session, url, method='GET', headers=None, data=None, *args, **kwargs):
    """
        Simple wrapper over requests. Allows for optionally downgrading SSL
        ciphers if required.
    """
    headers = headers or {}
    data = data or {}
    methods = ('GET',)
    if method not in methods:
        raise UnsupportedError(f'HTTP methods supported are: {methods}, got: {method}')
    headers['User-Agent'] = user_agent.format(version=version)
    log.debug(f'Making HTTP {method} request to {url}')
    try:
        if 'timeout' not in kwargs:
            kwargs['timeout'] = http_timeout
        return session.request(method, url, headers=headers, data=data, *args, **kwargs)
    except Exception as e:
        raise QueryError(f'Failed to make a {method} request to {url}: {e}') from e


def is_subnet_of(network_a, network_b):
    a_len = network_a.prefixlen
    b_len = network_b.prefixlen
    return a_len >= b_len and network_a.supernet(a_len - b_len) == network_b


default_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'


def contains_only_chars(s, chars=default_chars):
    for c in s:
        if c not in chars:
            return False
    return True
