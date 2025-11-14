from collections.abc import Iterator
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import httpx
import requests
from .bootstrap import _BootstrapWrapper
from .errors import ArgumentError
from .parser import parse
from .query import Query, QueryAsync, QueryBuilder
from .utils import (
    get_async_client,
    get_session,
    recursive_merge,
    clear_session as clear_session,
    set_proxy as set_proxy,
    get_proxy as get_proxy,
    clear_proxy as clear_proxy,
)
from .version import version as version


# Private methods

_bootstrap = _BootstrapWrapper()
_query_builder = QueryBuilder(_bootstrap)


# Expose class methods as the public API

bootstrap = _bootstrap.bootstrap
bootstrap_async = _bootstrap.bootstrap_async
is_bootstrapped = _bootstrap.is_bootstrapped
clear_bootstrapping = _bootstrap.clear_bootstrapping
save_bootstrap_data = _bootstrap.save_bootstrap_data
load_bootstrap_data = _bootstrap.load_bootstrap_data
bootstrap_is_older_than = _bootstrap.bootstrap_is_older_than
build_query = _query_builder.build


# Query helpers


def _asn(
    as_number: int,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    session: requests.Session | None = None,
    async_client: httpx.AsyncClient | None = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    method, url, _ = build_query(query_type="asn", query_value=as_number, rir=rir)
    if isinstance(async_client, httpx.AsyncClient):
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield (
        response
        if raw
        else parse(_bootstrap, "autnum", as_number, response, include_raw)
    )


def asn(
    as_number: int,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _asn(as_number, rir, raw, include_raw, session=session)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def asn_async(
    as_number: int,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _asn(as_number, rir, raw, include_raw, async_client=async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


def _domain(
    domain_name: str,
    raw: bool = False,
    include_raw: bool = False,
    follow_related: bool = True,
    session: requests.Session | None = None,
    async_client: httpx.AsyncClient | None = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    is_async = isinstance(async_client, httpx.AsyncClient)
    method, url, _ = build_query(query_type="domain", query_value=domain_name)
    if is_async:
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    if raw:
        yield response
    if follow_related:
        # Attempt to follow the 'related' or 'registration' links if the TLD has
        # an upstream RDAP endpoint that may have more information
        relresponse = None
        for link in response.get("links", []):
            rel = link.get("rel", "")
            if rel in ("related", "registration"):
                relhref = link.get("href", "")
                reltype = link.get("type", "")
                # Exclude related links with type set to HTML content types to avoid parsing web pages as JSON
                if relhref and not reltype.startswith("text/html"):
                    if is_async:
                        relq = QueryAsync(async_client, method, relhref)
                    else:
                        relq = Query(session, method, relhref)
                    yield
                    relresponse = yield relq
                    break
        if relresponse:
            # Overlay the related response over the original response
            recursive_merge(response, relresponse)
    yield parse(_bootstrap, "domain", domain_name, response, include_raw)


def domain(
    domain_name: str,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
    follow_related: bool = True,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _domain(domain_name, raw, include_raw, follow_related, session, None)
    resp: dict | None = None
    q: Query
    for q in gen:
        req_resp: dict = q.request()
        resp = gen.send(req_resp)
        if resp is req_resp:
            gen.close()
            break
    return resp


async def domain_async(
    domain_name: str,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
    follow_related: bool = True,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _domain(domain_name, raw, include_raw, follow_related, None, async_client)
    resp: dict | None = None
    q: QueryAsync
    for q in gen:
        req_resp: dict = await q.request()
        resp = gen.send(req_resp)
        # happens when raw=true
        if resp is req_resp:
            gen.close()
            break
    return resp


def _ip(
    ip_address_or_network: str | IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    session: requests.Session | None = None,
    async_client: bool = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    method, url, _ = build_query(
        query_type="ip", query_value=ip_address_or_network, rir=rir
    )
    if isinstance(async_client, httpx.AsyncClient):
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield (
        response
        if raw
        else parse(_bootstrap, "ip", ip_address_or_network, response, include_raw)
    )


def ip(
    ip_address_or_network: str | IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _ip(ip_address_or_network, rir, raw, include_raw, session, None)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def ip_async(
    ip_address_or_network: str | IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _ip(ip_address_or_network, rir, raw, include_raw, None, async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


def _entity(
    entity_handle: str,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    session: requests.Session | None = None,
    async_client: httpx.AsyncClient | None = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    method, url, _ = build_query(
        query_type="entity", query_value=entity_handle, rir=rir
    )
    if isinstance(async_client, httpx.AsyncClient):
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield (
        response
        if raw
        else parse(_bootstrap, "entity", entity_handle, response, include_raw)
    )


def entity(
    entity_handle: str,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _entity(entity_handle, rir, raw, include_raw, session, None)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def entity_async(
    entity_handle,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _entity(entity_handle, rir, raw, include_raw, None, async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp
