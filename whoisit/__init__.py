import requests
from .bootstrap import Bootstrap
from .query import QueryBuilder, Query
from .parser import parse
from .logger import get_logger
from .utils import create_session, get_session, recursive_merge
from .version import version


# Private methods


_bootstrap = Bootstrap()
_query_builder = QueryBuilder(_bootstrap)


# Expose class methods as the public API


is_bootstrapped = _bootstrap.is_bootstrapped
clear_bootstrapping = _bootstrap.clear_bootstrapping
bootstrap = _bootstrap.bootstrap
save_bootstrap_data = _bootstrap.save_bootstrap_data
load_bootstrap_data = _bootstrap.load_bootstrap_data
bootstrap_is_older_than = _bootstrap.bootstrap_is_older_than
build_query = _query_builder.build


# Query helpers


def asn(as_number, rir=None, raw=False, allow_insecure_ssl=False, session=None):
    session = get_session(session, allow_insecure_ssl=allow_insecure_ssl)
    method, url, exact_match = build_query(
        query_type='asn', query_value=as_number, rir=rir)
    q = Query(session, method, url)
    response = q.request()
    return response if raw else parse(_bootstrap, 'autnum', as_number, response)


def domain(domain_name, raw=False, allow_insecure_ssl=False, session=None, follow_related=True):
    session = get_session(session, allow_insecure_ssl=allow_insecure_ssl)
    method, url, exact_match = build_query(
        query_type='domain', query_value=domain_name)
    q = Query(session, method, url)
    response = q.request()
    if raw:
        return response
    if follow_related:
        # Attempt to follow the 'related' or 'registration' links if the TLD has
        # an upstream RDAP endpoint that may have more information
        relresponse = None
        for link in response.get('links', []):
            rel = link.get('rel', '')
            if rel in ('related', 'registration'):
                relhref = link.get('href', '')
                if relhref:
                    relq = Query(session, method, relhref)
                    relresponse = relq.request()
                    break
        if relresponse:
            # Overlay the related response over the original response
            recursive_merge(response, relresponse)
    return parse(_bootstrap, 'domain', domain_name, response)


def ip(ip_address_or_network, rir=None, raw=False, allow_insecure_ssl=False, session=None):
    session = get_session(session, allow_insecure_ssl=allow_insecure_ssl)
    method, url, exact_match = build_query(
        query_type='ip', query_value=ip_address_or_network, rir=rir)
    q = Query(session, method, url)
    response = q.request()
    return response if raw else parse(_bootstrap, 'ip', ip_address_or_network, response)


def entity(entity_handle, rir=None, raw=False, allow_insecure_ssl=False, session=None):
    session = get_session(session, allow_insecure_ssl=allow_insecure_ssl)
    method, url, exact_match = build_query(
        query_type='entity', query_value=entity_handle, rir=rir)
    q = Query(session, method, url)
    response = q.request()
    return response if raw else parse(_bootstrap, 'entity', entity_handle, response)
