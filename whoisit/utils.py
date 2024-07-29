from urllib3.util import retry

try:
    from urllib3.util import create_urllib3_context
except ImportError:
    from urllib3.util.ssl_ import create_urllib3_context

import httpx
import requests
from urllib3.poolmanager import PoolManager

from .errors import QueryError, UnsupportedError
from .logger import get_logger
from .version import version


log = get_logger('utils')
user_agent = 'whoisit/{version}'
insecure_ssl_ciphers = 'ALL:@SECLEVEL=1'
http_timeout = 10                    # Maximum time in seconds to allow for an HTTP request
http_retry_statuses = [429]          # HTTP status codes to trigger a retry wih backoff
http_max_retries = 3                 # Maximum number of HTTP requests to retry before failing
http_pool_connections = 10           # Maximum number of HTTP pooled connections
http_pool_maxsize = 10               # Maximum HTTP pool connection size
async_http_max_connections = 100     # Maximum number of HTTP connections allowed for async client
async_max_keepalive_connections = 20 # Allow the connection pool to maintain keep-alive connections below this point
_default_session = {'secure': None, 'insecure': False}


def get_session_or_async_client(session_or_async_client=None, allow_insecure_ssl=False, is_async=False):
    """
        Creates and caches the default sessions, one for secure (default) SSL
        and one for SSL with an insecure cipher suite.
    """
    global _default_session
    if session_or_async_client:
        if allow_insecure_ssl:
            if not _default_session['insecure']:
                _default_session['insecure'] = session_or_async_client
            return _default_session['insecure']
        else:
            if not _default_session['secure']:
                _default_session['secure'] = session_or_async_client
            return _default_session['secure']
    else:
        if allow_insecure_ssl:
            if is_async:
                _default_session['insecure'] = create_async_client(allow_insecure_ssl=allow_insecure_ssl)
            else:
                _default_session['insecure'] = create_session(allow_insecure_ssl=allow_insecure_ssl)
            return _default_session['insecure']
        else:
            if is_async:
                _default_session['secure'] = create_async_client(allow_insecure_ssl=allow_insecure_ssl)
            else:
                _default_session['secure'] = create_session(allow_insecure_ssl=allow_insecure_ssl)
            return _default_session['secure']


def get_session(session=None, allow_insecure_ssl=False) -> requests.Session:
    return get_session_or_async_client(session, allow_insecure_ssl, is_async=False)


def get_async_client(client=None, allow_insecure_ssl=False) -> httpx.AsyncClient:
    return get_session_or_async_client(client, allow_insecure_ssl, is_async=True)


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


def create_async_client(allow_insecure_ssl=False):
    limits = httpx.Limits(max_connections=async_http_max_connections, max_keepalive_connections=async_max_keepalive_connections)
    retries = httpx.AsyncHTTPTransport(retries=http_max_retries, limits=limits)
    headers = {"User-Agent": user_agent.format(version=version)}
    verify = not allow_insecure_ssl
    client = httpx.AsyncClient(transport=retries, verify=verify, headers=headers, follow_redirects=True)
    return client


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


async def http_request_async(client: httpx.AsyncClient, url, method='GET', headers=None, data=None, *args, **kwargs):
    """
        Simple wrapper over httpx.
    """
    headers = headers or {}
    data = data or {}
    methods = ('GET',)
    if method not in methods:
        raise UnsupportedError(f'HTTP methods supported are: {methods}, got: {method}')

    log.debug(f'Making async HTTP {method} request to {url}')
    try:
        if 'timeout' not in kwargs:
            kwargs['timeout'] = http_timeout
        return await client.request(method, url, headers=headers, data=data, *args, **kwargs)
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


def recursive_merge(d1, d2):
    for k, v in d2.items():
        if k in d1 and isinstance(d1[k], dict) and isinstance(v, dict):
            recursive_merge(d1[k], v)
        elif v:
            d1[k] = v
