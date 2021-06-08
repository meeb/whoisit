from .bootstrap import Bootstrap
from .query import QueryBuilder, Query


version = '1.0'


# Expose class methods as the public API


_bootstrap = Bootstrap()
is_bootstrapped = _bootstrap.is_bootstrapped
clear_bootstrapping = _bootstrap.clear_bootstrapping
bootstrap = _bootstrap.bootstrap
save_bootstrap_data = _bootstrap.save_bootstrap_data
load_bootstrap_data = _bootstrap.load_bootstrap_data
bootstrap_is_older_than = _bootstrap.bootstrap_is_older_than


_query_builder = QueryBuilder(_bootstrap)
build_query = _query_builder.build


# Primary query helpers


def asn(as_number):
    method, url, exact_match = build_query(query_type='asn',
                                           query_value=as_number)
    q = Query(method, url)
    return q.request()


def domain(domain_name):
    method, url, exact_match = build_query(query_type='domain',
                                           query_value=domain_name)
    q = Query(method, url)
    return q.request()


def ip(ip_address_or_network):
    method, url, exact_match = build_query(query_type='ip',
                                           query_value=ip_address_or_network)
    q = Query(method, url)
    return q.request()


def entity(entity_handle):
    method, url, exact_match = build_query(query_type='entity',
                                           query_value=entity_handle)
    q = Query(method, url)
    return q.request()
