import os
from urllib3.util.retry import Retry
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


def create_session():
    session = requests.session()
    retry = Retry(total=http_max_retries,
                  status_forcelist=http_retry_statuses,
                  backoff_factor=1)
    retry_adapter = requests.adapters.HTTPAdapter(
        max_retries=retry,
        pool_connections=http_pool_connections,
        pool_maxsize=http_pool_maxsize)
    session.mount('https://', retry_adapter)
    return session


def http_request(session, url, method='GET', allow_insecure_ssl=False,
                 headers={}, data={}, *args, **kwargs):
    """
        Simple wrapper over requests. Allows for optionally downgrading SSL
        ciphers if required.
    """
    methods = ('GET',)
    if method not in methods:
        raise UnsupportedError(f'HTTP methods supported are: {methods}, got: {method}')
    headers['User-Agent'] = user_agent.format(version=version)
    log.debug(f'Making HTTP {method} request to {url}')
    secure_ciphers = requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS
    try:
        if allow_insecure_ssl:
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += insecure_ssl_ciphers
            try:
                requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += \
                    insecure_ssl_ciphers
            except AttributeError:
                pass
        if 'timeout' not in kwargs:
            kwargs['timeout'] = http_timeout
        return session.request(method, url, headers=headers, data=data, *args, **kwargs)
    except Exception as e:
        raise QueryError(f'Failed to make a {method} request to {url}: {e}') from e
    finally:
        if allow_insecure_ssl:
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = secure_ciphers
            try:
                requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS = \
                    secure_ciphers
            except AttributeError:
                pass


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
