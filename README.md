# whoisit

A Python client to RDAP WHOIS-like services for internet resources (IPs, ASNs, domains,
etc.). `whoisit` is a simple library that makes requests to the "new" RDAP (Registration
Data Access Protocol) query services for internet resource information. These services
started to appear in 2017 and have become more widespread since 2020.

`whoisit` is designed to abstract over RDAP. While RDAP is a basic HTTP and JSON based
protocol which can be implemented in a single line with `requests` the bootstrapping
(which RDAP service to query for what item) and extracting useful information from the
RDAP responses is extensive enough that a library like this is useful.


## Installation

`whoisit` is pure Python and only has a dependancy on the `requests` and `dateutil`
libraries. You can install `whoisit` via pip:

```bash
$ pip install whoisit
```

Any modern version of Python3 will be compatible.


## Usage

`whoisit` supports the 4 main types of lookups supported by RDAP services. These are:

 * ASNs (autonomous systems numbers) known as `autnum` objects
 * DNS registrations known as `domain` objects - only some TLDs are supported
 * IPv4 and IPv6 addresses and CIDRs / prefixes known as `ip` objects
 * Entities (People, organisations etc. by ENTITY-HANDLES) known as `entity` objects

`whoisit` returns parsed RDAP formatted JSON as a flat dictionary by default.

Basic examples:

```python
import whoisit

whoisit.bootstrap()

results = whoisit.asn(1234)
print(results['name'])

results = whoisit.domain('example.com')
print(results['nameservers'])

results = whoisit.ip('1.2.3.4')
print(results['name'])

results = whoisit.ip('1.2.3.0/24')
print(results['name'])

results = whoisit.ip('2404:1234:1234:1234:1234:1234:1234:1234')
print(results['name'])

results = whoisit.ip('2404:1234::/32')
print(results['name'])

results = whoisit.entity('ARIN-CHA-1')
print(results['email'])
```

In each case `results` will be a dictionary containing the most useful information for
each request type. If the data you want is not in the response you can request the raw,
unparsed and large RDAP JSON data by adding the `raw=True` argument to the request, for
example:

```python
results = whoisit.domain('example.com', raw=True)
# 'results' is now the full, raw response from the RDAP service
```

If for some reason you accidentally end up querying the wrong RDAP endpoint your query
should end up still working, for example if you query ARIN for information on the IP
address `1.1.1.1` it will redirect you to APNIC (where `1.1.1.1` is allocated)
automatically.

Some resources, most notably entity handles, do not redirect or have assigned obvious
namespaces linked to particular registries. For these queries `whoisit` will attempt to
guess the RDAP service to query by examining the name for prefixes or postfix, such as
many RIPE entities are named `RIPE-SOMETHING`. If your entity does not have an obvious
prefix or postfix like `ARIN-*` or `*-AP` you will need to tell `whoisit` which registry
to make the request to by specifying the `rir=name` argument. For example:

```python
# This will work OK because the entity is prefixed with an obvious RIR name
results = whoisit.entity('RIPE-NCC-MNT')

# This will cause a QueryError to be raised because ARIN returns a 404 for RIPE-NCC-MNT
results = whoisit.entity('RIPE-NCC-MNT', rir='arin')

# This will cause a UnsupportedError to be raised because we have no way to detect
# which RDAP service to query as the entity has no RIR prefix or postfix
results = whoisit.entity('AS5089-MNT')

# This will work OK because the entity is registered at RIPE
results = whoisit.entity('AS5089-MNT', rir='ripe')
```


## Bootstrapping

`whoisit` needs to know which RDAP service to query for a resource. This information is
provided by the IANA as bootstrapping information. Bootstrapping data simply says things
like 'this CIDR is allocated to ARIN, this CIDR is allocated to RIPE' and so on for all
resources. The bootstrap data means you should be directly querying the correct RDAP
server for your request at all times. You should cache the bootstrap information locally
if you plan to make more than a single request otherwise you'll make additional requests
to the IANA every time you run a query. Example bootstrap information caching:

```python
import whoisit

print(whoisit.is_bootstrapped())  # -> False
whoisit.bootstrap()               # Slow, makes several HTTP requests to the IANA
print(whoisit.is_bootstrapped())  # -> True

if whoisit.is_bootstrapped():
    # bootstrap_info returned here is a string of JSON serialised bootstap information
    # You can store it in a memory cache or write it to disk for a few days
    bootstrap_info = whoisit.save_bootstrap_data()

# Clear bootstrapping data
whoisit.clear_bootstrapping()

# Later, you can do
print(whoisit.is_bootstrapped())  # -> False
if not whoisit.is_bootstrapped():
    whoisit.load_bootstrap_data(bootstrap_info)  # Fast, no HTTP requests made
print(whoisit.is_bootstrapped())  # -> True

# For convenience internally whoisit stores a timestamp of when the bootstrap data was
# last updated and has a "is older than" helper method
if whoisit.bootstrap_is_older_than(days=3):
    # Bootstrap data was last updated over 3 days ago, refresh it
    whoisit.clear_bootstrapping()
    whoisit.bootstrap()
    bootstrap_info = whoisit.save_bootstrap_data()  # and save it to upload your cache
```

A reasonable suggested way to handle bootstrapping data would be to use Memcached or
Redis, for example:

```python
import whoisit
import redis

r = redis.Redis(host='localhost', port=6379, db=0)

bootstrap_info = r.get('whoisit_bootstrap_info')
if bootstrap_info:
    whoisit.load_bootstrap_data(bootstrap_info)
else:
    whoisit.bootstrap()
    bootstrap_info = whoisit.save_bootstrap_data()
    expire_in_3_days = 60 * 60 * 24 *3
    r.set('whoisit_bootstrap_info', bootstrap_info, ex=expire_in_3_days)

# Send queries as normal once bootstrapped
whoisit.asn(12345)
```


## Parsers

While by default `whoisit` returns parsed, summary useful information. The following
keys are returned for each request type:

### Parsed ASN results

| key | description     |
|-----|-----------------|

### Parsed domain results

| key | description     |
|-----|-----------------|

### Parsed IP results

| key | description     |
|-----|-----------------|

### Parsed entity results

| key | description     |
|-----|-----------------|


## Full API synopsis

### `whoisit.is_bootstrapped()` -> `bool`

Returns boolean True or False if your `whoisit` instance is bootstrapped or not.

### `whoisit.bootstrap()` -> `bool`

Bootstraps your `whoisit` instance with remote IANA bootstrap information. Returns
True or raises a `whoisit.errors.BootstrapError` exception if it fails. This method
makes HTTP requests to the IANA.

### `whoisit.clear_bootstrapping()` -> `bool`

Clears any stored bootstrap information. Always returns boolean True.

### `whoisit.save_bootstrap_data()` -> `str`

Returns a string of JSON serialised bootstrap information if any is loaded. If no
bootstrap information loaded a `whoisit.errors.BootstrapError` will be raised.

### `whoisit.load_bootstrap_data(data=str)` -> `bool`

Loads a string of JSON serialised bootstrap data as returned by `save_bootstrap_data()`.
Returns True if the data is loaded or raises a `whoisit.errors.BootstrapError` if
loading fails.

### `whoisit.bootstrap_is_older_than(days=int)` -> `bool`

Tests if the loaded bootstrap data is older than the specified number of days as an
integer. Returns True or False. If no bootstrap information is loaded a
`whoisit.errors.BootstrapError` exception will be raised.

### `whoisit.asn(asn=123, rir=None, raw=False)` -> `dict`

Queries a remote RDAP server for information about the specified AS number. AS number
must be an integer. Returns a dict of information. If `raw=True` is passed a large dict
of the raw RDAP response will be returned. If the query fails a
`whoisit.errors.QueryError` exception will be raised. If no bootstrap data is loaded
a `whoisit.errors.BootstrapError` exception will be raised. 


### `whoisit.domain(domain="example.com", raw=False)` -> `dict`

Queries a remote RDAP server for information about the specified domain name. The domain
name must be a string and in a valid domain name "something.tld" style format. Returns a
dict of information. If `raw=True` is passed a large dict of the raw RDAP response will
be returned. If the query fails a `whoisit.errors.QueryError` exception will be raised.
If no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be
raised. If the TLD is unsupported a `whoisit.errors.UnsupportedError` exception will be
raised.

### `whoisit.ip(ip="1.1.1.1", raw=False)` -> `dict`

Queries a remote RDAP server for information about the specified IP address or CIDR. The
IP address or CIDR must be a string and in the correct IP address or CIDR format.
Returns a dict of information. If `raw=True` is passed a large dict of the raw RDAP
response will be returned. If the query fails a `whoisit.errors.QueryError`
exception will be raised. If no bootstrap data is loaded a
`whoisit.errors.BootstrapError` exception will be raised.

### `whoisit.entity(entity=str, raw=False)` -> `dict`

Queries a remote RDAP server for information about the specified entity name. The
entity name must be a string and in the correct entity format. Returns a dict of
information. If `raw=True` is passed a large dict of the raw RDAP response will be
returned. If the query fails a `whoisit.errors.QueryError` exception will be raised.
If no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be
raised.


## Data usage

All data returned by RDAP servers are covered by the various policies embeddd in the
results. As such you should carefuly review your usage of the data to make sure it
complies with the policy of the RDAP server you are querying.


## Excessive use

As an API client `whoisit` is entirely subject to the resource and request limits
applied by the remote RDAP servers it queries. If you recieve request errors for rate
limiting you should slow down your requests. Different servers have different limits.
The LACNIC RDAP server in particular only permits a low number of requests per minute.


# Tests

There is a test suite that you can run by cloing this repository, installing the
required dependancies and execuiting:

```bash
$ make test
```


# Contributing

All properly formatted and sensible pull requests, issues and comments are
