import requests
from .errors import QueryError, UnsupportedError
from .logger import get_logger


log = get_logger('utils')


user_agent = 'whoisit'


def http_request(url, method='GET', headers={}, data={}, *args, **kwargs):
    '''
        Simple wrapper over requests.
    '''
    methods = ('GET',)
    if method not in methods:
        raise UnsupportedError(f'HTTP methods supported are: {methods}, got: {method}')
    headers['User-Agent'] = user_agent
    log.debug(f'Making HTTP {method} request to {url}')
    try:
        return requests.request(method, url, headers=headers, data=data, *args,
                                **kwargs)
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
