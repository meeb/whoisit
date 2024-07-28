import random
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from urllib.parse import (
    parse_qs,
    quote,
    unquote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from .errors import (
    QueryError,
    ResourceAccessDeniedError,
    RateLimitedError,
    RemoteServerError,
    ResourceDoesNotExist,
    UnsupportedError,
)
from .logger import get_logger
from .utils import contains_only_chars, http_request, http_request_async


log = get_logger('query')


class QueryBuilder:

    QUERY_TYPES_MAP = {
        'asn': 'autnum',
        'as': 'autnum',
        'autnum': 'autnum',
        'domain': 'domain',
        'tld': 'domain',
        'dns': 'domain',
        'ipv4': 'ip',
        'ipv6': 'ip',
        'ip': 'ip',
        'prefix': 'ip',
        'cidr': 'ip',
        'network': 'ip',
        'object': 'entity',
        'entity': 'entity',
    }

    def __init__(self, bootstrap):
        # These map to the supported RDAP types, not the bootstrap data types
        self.query_endpoints_fetchers = {
            'autnum': self.get_autnum_endpoint,
            'domain': self.get_domain_endpoint,
            'ip': self.get_ip_endpoint,
            'entity': self.get_entity_endpoint,
        }
        self.bootstrap = bootstrap

    def build(self, query_type=None, query_value=None, rir=None):
        if not self.bootstrap.is_bootstrapped():
            raise QueryError(f'You need to load bootstrap data before making '
                             f'any queries')
        query_type = str(query_type).strip().lower()
        what = self.QUERY_TYPES_MAP.get(query_type)
        if not what:
            raise QueryError(f'Unknown query_type: {query_type}')
        if not query_value:
            raise QueryError(f'query_value must be set')
        if rir:
            url, exact_match = self.get_override_endpoint(rir, what, query_value)
        else:
            fetcher = self.query_endpoints_fetchers[what]
            url, exact_match = fetcher(query_value)
        method = 'GET'
        match_str = ' (exact match)' if exact_match else ''
        log.debug(f'{what} query for {query_value} built as {method} {url}{match_str}')
        return method, url, exact_match

    def construct_url(self, base_url, what, value):
        if not base_url.endswith('/'):
            base_url += '/'
        resource = urljoin(base_url, str(what))
        if not resource.endswith('/'):
            resource += '/'
        quoted_value = quote(str(value))
        return unquote(urljoin(resource, quoted_value))

    def get_autnum_endpoint(self, value):
        if isinstance(value, str):
            value = value.strip().upper()
            if value.startswith('AS'):
                value = value[2:]
        try:
            value = int(value)
        except (TypeError, ValueError) as e:
            raise QueryError(f'Failed to cast AS number to integer: {e}') from e
        endpoints, exact_match = self.bootstrap.get_asn_endpoints(value)
        endpoint = random.choice(endpoints)
        if not exact_match:
            log.debug(f'Failed to match ASN: {value} to an RDAP service, '
                      f'defaulting to: {endpoint}')
        return self.construct_url(endpoint, 'autnum', value), exact_match

    def get_domain_endpoint(self, value):
        value = str(value).strip()
        parts = value.split('.')
        if len(parts) < 2:
            raise QueryError(f'Failed to extract TLD from domain "{value}"')
        domain = '.'.join(parts[:-1])
        try:
            # First check for SLDs
            tld = '.'.join(parts[-2:])
            endpoints, exact_match = self.bootstrap.get_dns_endpoints(tld)
        except UnsupportedError:
            # If no SLD match, try the TLD
            tld = parts[-1]
            endpoints, exact_match = self.bootstrap.get_dns_endpoints(tld)
        endpoint = random.choice(endpoints)
        if not exact_match:
            log.debug(f'Failed to match domain: {value} to an RDAP service, '
                      f'defaulting to: {endpoint}')
        return self.construct_url(endpoint, 'domain', value), exact_match

    def get_ip_endpoint(self, value):
        if not isinstance(value, (IPv4Address, IPv4Network, IPv6Address, IPv6Network)):
            value = str(value)
        if isinstance(value, str):
            try:
                value = ip_address(value)
            except (TypeError, ValueError):
                try:
                    value = ip_network(value)
                except (TypeError, ValueError):
                    raise QueryError(f'Unable to cast input as either an IP address '
                                     f'or IP network: {value}')
        if value.version == 4:
            endpoints, exact_match = self.bootstrap.get_ipv4_endpoints(value)
            endpoint = random.choice(endpoints)
            if not exact_match:
                log.debug(f'Failed to match IPv4: {value} to an RDAP service, '
                          f'defaulting to: {endpoint}')
        else:
            endpoints, exact_match = self.bootstrap.get_ipv6_endpoints(value)
            endpoint = random.choice(endpoints)
            if not exact_match:
                log.debug(f'Failed to match IPv6: {value} to an RDAP service, '
                          f'defaulting to: {endpoint}')
        return self.construct_url(endpoint, 'ip', str(value)), exact_match

    def get_entity_endpoint(self, value):
        value = str(value).strip().upper()
        # Entity names can only contain A-Z upper case, 0-9 and hyphens
        if not contains_only_chars(value):
            raise QueryError(f'Entity tags or handles can only container uppercase '
                             f'A-Z, 0-9 and hyphens, got: {value}')
        endpoints, exact_match = self.bootstrap.get_entity_endpoints(value)
        endpoint = random.choice(endpoints)
        return self.construct_url(endpoint, 'entity', value), exact_match

    def get_override_endpoint(self, rir_endpoint_name, query_name, value):
        '''
            The query should be built using a manually overriden RIR endpoint name,
            such as 'arin' or 'ripe' and not use the bootstrap data.
        '''
        if isinstance(value, str):
            value = value.strip()
        query_name = str(query_name).strip()
        endpoint = self.bootstrap.get_rir_endpoint(rir_endpoint_name)
        if not endpoint:
            rir_names = self.bootstrap.get_rir_endpoint_names()
            raise QueryError(f'Unknown RIR endpoint name, must be one of: {rir_names}')
        return self.construct_url(endpoint, query_name, value), True


class BaseQuery:
    """
        Make an HTTP request to an RDAP endpoint as a query. This is slightly more
        elaborate than a single function just to allow kwargs to be arbitrarily passed
        to both requests and the requested URL if required.
    """

    def __init__(self, method, url, **kwargs):
        self.method = method.strip().upper()
        if kwargs:
            # kwargs are appended to the URL, such as test=123 becomes url?test=123
            self.url = self.add_url_params(url, kwargs)
        else:
            self.url = url

    def add_url_params(self, url, extra_params):
        parts = urlsplit(url)
        qs = {}
        for k, v in parse_qs(parts.query):
            qs[k] = v
        for k, v in extra_params.items():
            qs[k] = str(v)
        qs_str = urlencode(qs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, qs_str, ''))


    def _decode_content(self, response):
        """
            Decode the content of the response and attempt to force it into a
            unicode string. This is used as part of the query failure exceptions
            to allow downstream clients to decide how to behave when errors occur.
        """
        try:
            return response.text.strip()
        except (ValueError, UnicodeDecodeError) as e:
            return response.content.decode('utf-8', errors='ignore').strip()

    def _process_response(self, response):
        status_code_map = {
            401: (
                ResourceAccessDeniedError,
                f'RDAP {self.method} request to {self.url} returned a '
                f'401 error, unauthorized',
            ),
            403: (
                ResourceAccessDeniedError,
                f'RDAP {self.method} request to {self.url} returned a '
                f'403 error, forbidden',
            ),
            404: (
                ResourceDoesNotExist,
                f'RDAP {self.method} request to {self.url} returned a '
                f'404 error, the resource does not exist',
            ),
            422: (
                ResourceAccessDeniedError,
                f'RDAP {self.method} request to {self.url} returned a '
                f'422 error, the request was unprocessable',
            ),
            429: (
                RateLimitedError,
                f'RDAP {self.method} request to {self.url} returned a '
                f'429 error, the resource has been rate limited',
            ),
            500: (
                RemoteServerError,
                f'RDAP {self.method} request to {self.url} returned a '
                f'500 error, the resource returned a remote server error',
            ),
        }
        if response.status_code in status_code_map:
            error_class, error_message = status_code_map[response.status_code]
            error_content = self._decode_content(response)
            raise error_class(error_message,
                              status_code=response.status_code,
                              response=error_content)
        elif response.status_code != 200:
            error_content = self._decode_content(response)
            raise QueryError(f'RDAP {self.method} request to {self.url} returned a '
                             f'non-200 status code of {response.status_code}',
                             status_code=response.status_code,
                             response=error_content)
        try:
            return response.json()
        except (TypeError, ValueError) as e:
            raise QueryError(f'Failed to parse RDAP Query response as JSON: {e}', response=error_content) from e


class Query(BaseQuery):
    """
        Make an HTTP request to an RDAP endpoint as a query. This is slightly more
        elaborate than a single function just to allow kwargs to be arbitrarily passed
        to both requests and the requested URL if required.
    """

    def __init__(self, session, method, url, **kwargs):
        super().__init__(method, url, **kwargs)
        self.session = session

    def request(self, *args, **kwargs):
        # args and kwargs here are passed directly to requests.request(...)
        response = http_request(self.session, url=self.url, method=self.method, *args, **kwargs)
        return self._process_response(response)


class QueryAsync(BaseQuery):
    """
        Make an async HTTP request to an RDAP endpoint as a query. This is slightly more
        elaborate than a single function just to allow kwargs to be arbitrarily passed
        to both requests and the requested URL if required.
    """

    def __init__(self, client, method, url, **kwargs):
        super().__init__(method, url, **kwargs)
        self.client = client

    async def request(self, *args, **kwargs):
        # args and kwargs here are passed directly to httpx.request(...)
        response = await http_request_async(self.client, url=self.url, method=self.method, *args, **kwargs)
        return self._process_response(response)
