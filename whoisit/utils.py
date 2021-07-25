import requests
import urllib3
from .errors import QueryError, UnsupportedError
from .logger import get_logger


log = get_logger('utils')


user_agent = 'whoisit'
insecure_ssl_ciphers = ':HIGH:!DH:!aNULL'


def http_request(url, method='GET', allow_insecure_ssl=False,
                 headers={}, data={}, *args, **kwargs):
    '''
        Simple wrapper over requests. Allows for optionally downgrading SSL
        ciphers if required.
    '''
    methods = ('GET',)
    if method not in methods:
        raise UnsupportedError(f'HTTP methods supported are: {methods}, got: {method}')
    headers['User-Agent'] = user_agent
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
        return requests.request(method, url, headers=headers, data=data, *args,
                                **kwargs)
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
