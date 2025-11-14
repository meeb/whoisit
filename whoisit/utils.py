from ipaddress import IPv4Network, IPv6Network
from urllib3.util import retry
from urllib3.poolmanager import PoolManager

try:
    from urllib3.util import create_urllib3_context
except ImportError:
    from urllib3.util.ssl_ import create_urllib3_context
import httpx
import requests
from .errors import QueryError, UnsupportedError
from .logger import get_logger
from .version import version


log = get_logger("utils")
user_agent = "whoisit/{version}"
insecure_ssl_ciphers = "ALL:@SECLEVEL=1"
http_timeout = 10  # Maximum time in seconds to allow for an HTTP request
http_retry_statuses = [429]  # HTTP status codes to trigger a retry wih backoff
http_max_retries = 3  # Maximum number of HTTP requests to retry before failing
http_pool_connections = 10  # Maximum number of HTTP pooled connections
http_pool_maxsize = 10  # Maximum HTTP pool connection size
async_http_max_connections = (
    100  # Maximum number of HTTP connections allowed for async client
)
async_max_keepalive_connections = (
    20  # Allow the connection pool to maintain keep-alive connections below this point
)
_default_session = {"secure": None, "insecure": False}
_proxy = None


def get_session_or_async_client(
    session_or_async_client: requests.Session | httpx.AsyncClient | None = None,
    allow_insecure_ssl: bool = False,
    is_async: bool = False,
) -> requests.Session | httpx.AsyncClient:
    """
    Creates and caches the default sessions, one for secure (default) SSL
    and one for SSL with an insecure cipher suite.
    """
    global _default_session
    key = "insecure" if allow_insecure_ssl else "secure"
    if session_or_async_client:
        if _default_session[key] is None:
            _default_session[key] = session_or_async_client
        return _default_session[key]
    else:
        if is_async:
            if not isinstance(_default_session[key], httpx.AsyncClient):
                _default_session[key] = create_async_client(
                    allow_insecure_ssl=allow_insecure_ssl
                )
        else:
            if not isinstance(_default_session[key], requests.Session):
                _default_session[key] = create_session(
                    allow_insecure_ssl=allow_insecure_ssl
                )
        return _default_session[key]


def clear_session() -> bool:
    global _default_session
    _default_session = {"secure": None, "insecure": None}
    return True


def clear_proxy() -> bool:
    global _proxy
    _proxy = None
    clear_session()
    return True


def get_proxy() -> str | None:
    global _proxy
    return _proxy


def set_proxy(proxy: str) -> bool:
    global _proxy
    if not isinstance(proxy, str):
        raise ValueError(
            '"proxy" must be a string and specified in the proto://[user:pass]@host:port format'
        )
    _proxy = proxy
    clear_session()
    return True


def get_session(
    session: requests.Session | None = None, allow_insecure_ssl: bool = False
) -> requests.Session:
    return get_session_or_async_client(session, allow_insecure_ssl, is_async=False)


def get_async_client(
    client: httpx.AsyncClient | None = None, allow_insecure_ssl: bool = False
) -> httpx.AsyncClient:
    return get_session_or_async_client(client, allow_insecure_ssl, is_async=True)


class InsecureSSLAdapter(requests.adapters.HTTPAdapter):
    """
    Custom adapter to permit insecure SSL connections.
    """

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False
    ) -> None:
        insecure_ssl_ciphersuite = create_urllib3_context(ciphers=insecure_ssl_ciphers)
        self.poolmanager = PoolManager(ssl_context=insecure_ssl_ciphersuite)


def create_session(allow_insecure_ssl: bool = False) -> requests.Session:
    session = requests.session()
    session_retry = retry.Retry(
        total=http_max_retries, status_forcelist=http_retry_statuses, backoff_factor=1
    )
    whoisit_adapter = requests.adapters.HTTPAdapter(
        max_retries=session_retry,
        pool_connections=http_pool_connections,
        pool_maxsize=http_pool_maxsize,
    )
    session.mount("https://", whoisit_adapter)
    if allow_insecure_ssl:
        session.mount("https://", InsecureSSLAdapter())
    return session


def create_async_client(allow_insecure_ssl: bool = False) -> httpx.AsyncClient:
    limits = httpx.Limits(
        max_connections=async_http_max_connections,
        max_keepalive_connections=async_max_keepalive_connections,
    )
    retries = httpx.AsyncHTTPTransport(retries=http_max_retries, limits=limits)
    headers = {"User-Agent": user_agent.format(version=version)}
    verify = not allow_insecure_ssl
    client = httpx.AsyncClient(
        transport=retries,
        verify=verify,
        headers=headers,
        follow_redirects=True,
        proxy=get_proxy(),
    )
    return client


def _validate_request(
    headers: dict | None, data: dict | None, method: str
) -> tuple[dict, dict, str, str, dict, str]:
    headers = headers or {}
    data = data or {}
    methods = ("GET",)
    if method not in methods:
        raise UnsupportedError(f"HTTP methods supported are: {methods}, got: {method}")
    headers["User-Agent"] = user_agent.format(version=version)
    proxy = get_proxy()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    proxystr = f" via proxy: {proxy}" if proxy else ""
    return headers, data, method, proxy, proxies, proxystr


def http_request(
    session: requests.Session,
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: dict | None = None,
    *args,
    **kwargs,
) -> requests.Response:
    """
    Simple wrapper over requests. Allows for optionally downgrading SSL
    ciphers if required.
    """
    headers, data, method, proxy, proxies, proxystr = _validate_request(
        headers, data, method
    )
    log.debug(f"Making HTTP {method} request to {url}{proxystr}")
    try:
        if "timeout" not in kwargs:
            kwargs["timeout"] = http_timeout
        return session.request(
            method, url, headers=headers, data=data, proxies=proxies, *args, **kwargs
        )
    except Exception as e:
        raise QueryError(
            f"Failed to make a {method} request to {url}{proxystr}: {e}"
        ) from e


async def http_request_async(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: dict | None = None,
    *args,
    **kwargs,
) -> httpx.Response:
    """
    Simple wrapper over httpx.
    """
    headers, data, method, proxy, proxies, proxystr = _validate_request(
        headers, data, method
    )
    log.debug(f"Making async HTTP {method} request to {url}{proxystr}")
    try:
        if "timeout" not in kwargs:
            kwargs["timeout"] = http_timeout
        return await client.request(
            method, url, headers=headers, data=data, *args, **kwargs
        )
    except Exception as e:
        raise QueryError(
            f"Failed to make a {method} request to {url}{proxystr}: {e}"
        ) from e


def is_subnet_of(
    network_a: IPv4Network | IPv6Network, network_b: IPv4Network | IPv6Network
) -> bool:
    if network_a.version != network_b.version:
        raise ValueError(
            f"Cannot compare subnets of different address families: {network_a} and {network_b}"
        )
    a_len = network_a.prefixlen
    b_len = network_b.prefixlen
    return a_len >= b_len and network_a.supernet(a_len - b_len) == network_b


default_chars: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"


def contains_only_chars(s: str, chars: str = default_chars) -> bool:
    for c in s:
        if c not in chars:
            return False
    return True


def recursive_merge(d1: dict, d2: dict) -> None:
    """
    Recursively merge two dictionaries. This is used to overlay subrequest
    data from related info RDAP endpoints over the top of primary RDAP
    request data. It has some special handling to account for related RDAP
    info having slightly different formats for events, notices, and remarks.
    """
    for k, v in d2.items():
        if k in d1 and isinstance(d1[k], dict) and isinstance(v, dict):
            recursive_merge(d1[k], v)
        elif k == "events" and isinstance(v, list):
            v1 = d1.get(k) or []
            d1[k] = recursive_merge_lists(v1, v, dedup_on="eventAction")
        elif k in {"notices", "remarks"} and isinstance(v, list):
            v1 = d1.get(k) or []
            d1[k] = recursive_merge_lists(v1, v)
        elif v:
            d1[k] = v


def recursive_merge_lists(l1: list, l2: list, dedup_on: str = "title") -> list:
    list1 = {l[dedup_on]: l for l in l1 if dedup_on in l}  # noqa: E741
    list2 = {l[dedup_on]: l for l in l2 if dedup_on in l}  # noqa: E741
    recursive_merge(list1, list2)
    return list(list1.values())
