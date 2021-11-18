import os
import re
import requests
from .errors import QueryError, UnsupportedError
from .logger import get_logger


log = get_logger('utils')
insecure_ssl_ciphers = 'ALL:@SECLEVEL=1'


def get_user_agent_string():
    """Return the user agent string."""
    here_dir = os.path.dirname(os.path.abspath(__file__))
    init_file = os.path.join(here_dir, "__init__.py")
    with open(init_file, "r") as i_f:
        init_file_contents = i_f.read()
    rx_compiled = re.compile("version\s*=\s*\'(\S+)\'")
    rxmatch = rx_compiled.search(init_file_contents)
    if not rxmatch:
        return "whoisit/UNKNOWN_VERSION"
    return "whoisit/{}".format(rxmatch.group(1))


def http_request(session, url, method='GET', allow_insecure_ssl=False,
                 headers={}, data={}, *args, **kwargs):
    '''
        Simple wrapper over requests. Allows for optionally downgrading SSL
        ciphers if required.
    '''
    methods = ('GET',)
    if method not in methods:
        raise UnsupportedError(f'HTTP methods supported are: {methods}, got: {method}')
    headers['User-Agent'] = get_user_agent_string()
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
        return session.request(method, url, headers=headers, data=data, *args,
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
