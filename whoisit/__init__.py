from .bootstrap import _BootstrapMainModule
from .errors import ArgumentError
from .parser import parse
from .query import Query, QueryAsync, QueryBuilder
from .utils import get_async_client, get_session, recursive_merge, clear_session, set_proxy, get_proxy, clear_proxy
from .version import version


# Private methods

_bootstrap = _BootstrapMainModule()
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

def _asn(as_number, rir=None, raw=False, include_raw=False, session=None, async_client=None):
    if raw and include_raw:
        raise ArgumentError("Cannot set both 'raw' and 'include_raw' to True")
    
    is_async = async_client is not None
    method, url, _ = build_query(query_type='asn', query_value=as_number, rir=rir)

    if is_async:
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield response if raw else parse(_bootstrap, 'autnum', as_number, response, include_raw)


def asn(as_number, rir=None, raw=False, include_raw=False, allow_insecure_ssl=False, session=None):
    session = get_session(session, allow_insecure_ssl)
    gen = _asn(as_number, rir, raw, include_raw, session=session)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def asn_async(as_number, rir=None, raw=False, include_raw=False, allow_insecure_ssl=False, async_client=None):
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _asn(as_number, rir, raw, include_raw, async_client=async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


def _domain(domain_name, raw=False, include_raw=False, session=None, follow_related=True, async_client=None, is_async=False):
    if raw and include_raw:
        raise ArgumentError("Cannot set both 'raw' and 'include_raw' to True")
    
    is_async = async_client is not None
    method, url, _ = build_query(query_type='domain', query_value=domain_name)

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
        for link in response.get('links', []):
            rel = link.get('rel', '')
            if rel in ('related', 'registration'):
                relhref = link.get('href', '')
                reltype = link.get('type', '')
                # Exclude related links with type set to HTML content types to avoid parsing web pages as JSON
                if relhref and not reltype.startswith('text/html'):
                    if is_async:
                        relq = QueryAsync(async_client, method, relhref)
                    else:
                        relq= Query(session, method, relhref)
                    yield
                    relresponse = yield relq
                    break
        if relresponse:
            # Overlay the related response over the original response
            recursive_merge(response, relresponse)
    yield parse(_bootstrap, 'domain', domain_name, response, include_raw)


def domain(domain_name, raw=False, include_raw=False, allow_insecure_ssl=False, session=None, follow_related=True):
    session = get_session(session, allow_insecure_ssl)
    gen = _domain(domain_name, raw, include_raw, session, follow_related, None)
    resp: dict = None

    q: Query
    for q in gen:
        req_resp: dict = q.request()
        resp = gen.send(req_resp)

        if resp is req_resp:
            gen.close()
            break

    return resp


async def domain_async(domain_name, raw=False, include_raw=False, allow_insecure_ssl=False, async_client=None, follow_related=True):
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _domain(domain_name, raw, include_raw, None, follow_related, async_client)
    resp: dict = None

    q: QueryAsync
    for q in gen:
        req_resp: dict = await q.request()
        resp = gen.send(req_resp)

        # happens when raw=true
        if resp is req_resp:
            gen.close()
            break

    return resp


def _ip(ip_address_or_network, rir=None, raw=False, include_raw=False, session=None, async_client=None, is_async=False):
    if raw and include_raw:
        raise ArgumentError("Cannot set both 'raw' and 'include_raw' to True")
    
    is_async = async_client is not None
    method, url, _ = build_query(query_type='ip', query_value=ip_address_or_network, rir=rir)

    if is_async:
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield response if raw else parse(_bootstrap, 'ip', ip_address_or_network, response, include_raw)


def ip(ip_address_or_network, rir=None, raw=False, include_raw=False, allow_insecure_ssl=False, session=None):
    session = get_session(session, allow_insecure_ssl)
    gen = _ip(ip_address_or_network, rir, raw, include_raw, session, None)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def ip_async(ip_address_or_network, rir=None, raw=False, include_raw=False, allow_insecure_ssl=False, async_client=None):
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _ip(ip_address_or_network, rir, raw, include_raw, None, async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


def _entity(entity_handle, rir=None, raw=False, include_raw=False, session=None, async_client=None, is_async=False):
    if raw and include_raw:
        raise ArgumentError("Cannot set both 'raw' and 'include_raw' to True")
    
    is_async = async_client is not None
    method, url, _ = build_query(query_type='entity', query_value=entity_handle, rir=rir)

    if is_async:
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield response if raw else parse(_bootstrap, 'entity', entity_handle, response, include_raw)

def entity(entity_handle, rir=None, raw=False, include_raw=False, allow_insecure_ssl=False, session=None):
    session = get_session(session, allow_insecure_ssl)
    gen = _entity(entity_handle, rir, raw, include_raw, session, None)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def entity_async(ip_address_or_network, rir=None, raw=False, include_raw=False, allow_insecure_ssl=False, async_client=None):
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _entity(ip_address_or_network, rir, raw, include_raw, None, async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp
