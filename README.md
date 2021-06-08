# whoisit

A Python client to RDAP WHOIS-like services for internet resources (IPs, ASNs, domains,
etc.). `whoisit` is a simple library that makes requests to the "new" (since about
2017, becoming widespread in 2019 / 2020) RDAP (Registration Data Access Protocol) query
services for internet resource information.

This is not a complicated library, it just makes some HTTP requests.


## Installation

`whoisit` is pure Python and only has a dependancy on the `requests` library. You can
install it via pip:

```bash
$ pip install whoisit
```


## Usage

`whoisit` supports the 4 main types of lookups supported by RDAP services. These are:

 * ASNs (autonomous systems numbers) known as `autnum` objects
 * DNS registrations known as `domain` objects - only some TLDs are supported
 * IPv4 and IPv6 addresses and CIDRs / prefixes known as `ip` objects
 * Entities (People, organisations etc. by ENTITY-HANDLES) known as `entity` objects

`whoisit` returns the RDAP formatted JSON as a dictionary verbatim by default.

Basic examples:

```python
import whoisit

whoisit.bootstrap()

results = whoisit.asn(1234)
results = whoisit.domain('example.com')
results = whoisit.ip('1.2.3.4')
results = whoisit.ip('1.2.3.0/24')
results = whoisit.ip('2404:1234:1234:1234:1234:1234:1234:1234')
results = whoisit.ip('2404:1234::/32')
results = whoisit.entity('ARIN-CHA-1')
```

In each case `results` will be a large dictionary containing RDAP formatted information.


## Bootstrapping

`whoisit` needs to know which RDAP service to query for a resourcce, to do it needs get
the bootstrap information from the IANA. Bootstrapping data simply says things like
'this CIDR is allocated to ARIN, this one is allocated to RIPE' and so on for all
resources. The bootstrap data means you should be directly querying the correct RDAP
server for your request at all times. You should cache the bootstrap information locally
if you plan to make more than a single request otherwise you'll make additional requests
to the IANA every time you run a query. Example bootstrap information caching:

```python
import whoisit

print(whoisit.is_bootstrapped())  # -> False
whoisit.bootstrap()               # Slow, makes several HTTP requests
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

# Send queries as normal
whoisit.asn(12345)
```


## Parsers

While by default `whoisit` returns raw RDAP formatted data it can be troublesome to
extract reliable meaningful information from the results. To help with this `whoisit`
comes with some utility helper methods to parse the results. Examples:

```python
import whoisit

# Load some cached bootstrapping data from somewhere
bootstrap_info = your_load_bootstrap_data_method()
whoisit.load_bootstrap_data(bootstrap_info)

# Look something up
results = whoisit.domain('example.com')

# Parse the results, returns another dict but far smaller and with standardised keys
parsed_results = whoisit.parse(results)
```

The following keys are returned by the parser for each results type:

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

### `whoisit.is_bootstrapped()` -> bool

Returns boolean True or False if your `whoisit` instance is bootstrapped or not.

### `whoisit.bootstrap()` -> bool

Bootstraps your `whoisit` instance with remote IANA bootstrap information. Returns
True or raises a `whoisit.errors.BootstrapError` exception if it fails.

### `whoisit.clear_bootstrapping()` -> bool

Clears any stored bootstrap information. Always returns boolean True.

### `whoisit.save_bootstrap_data()` -> str

Returns a string of JSON serialised bootstrap information if any is loaded. If no
bootstrap information loaded a a `whoisit.errors.BootstrapError` will be raised.

### `whoisit.load_bootstrap_data(data=str)` -> bool

Loads a string of JSON serialised bootstrap data as returned by `save_bootstrap_data()`.
Returns True if the data is loaded or raises a `whoisit.errors.BootstrapError` if
loading fails.

### `whoisit.bootstrap_is_older_than(days=int)` -> bool

Tests if the loaded bootstrap data is older than the specified number of days as an
integer. Returns True or False. If no bootstrap information is loaded a
`whoisit.errors.BootstrapError` exception will be raised.

### `whoisit.asn(asn=int)` -> dict

Queries a remote RDAP server for information about the specified AS number. AS number
must be an integer. Returns a dict of RDAP information. If the query fails a
`whoisit.errors.QueryError` exception will be raised. If no bootstrap data is loaded
a `whoisit.errors.BootstrapError` exception will be raised.

`whoisit.autnum(asn=int)` is an alias for `whoisit.asn(asn=int)`.

### `whoisit.domain(domain=str)` -> dict

Queries a remote RDAP server for information about the specified domain name. The domain
name must be a string and in a valid domain name style format. Returns a dict of RDAP
information. If the query fails a `whoisit.errors.QueryError` exception will be raised.
If no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be
raised. If the TLD is unsupported a `whoisit.errors.UnsupportedError` exception will be
raised.

### `whoisit.ip(ip=str)` -> dict

Queries a remote RDAP server for information about the specified IP address or CIDR. The
IP address or CIDR must be a string and in the correct IP address or CIDR format.
Returns a dict of RDAP information. If the query fails a `whoisit.errors.QueryError`
exception will be raised. If no bootstrap data is loaded a
`whoisit.errors.BootstrapError` exception will be raised.

### `whoisit.entity(entity=str)` -> dict

Queries a remote RDAP server for information about the specified entity name. The
entity name must be a string and in the correct entity format. Returns a dict of RDAP
information. If the query fails a `whoisit.errors.QueryError` exception will be raised.
If no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be
raised.

### `whoisit.parse(data=dict)` -> dict

Parses a results dict and returns a summarised standard dict. The input data must be a
dict. Note if you pass this method a malformed dictionary it will simply return a empty
values.


## Data usage

All data returned by RDAP servers are covered by the various policies embeddd in the
results. As such you should carefuly review your usage of the data to make sure it
complies with the policy of the RDAP server you are querying


## Excessive use

As an API client `whoisit` is entirely subject to the resource and request limits
applied by the remote RDAP servers it queries. If you recieve request errors for rate
limiting you should slow down your requests. Different servers have different limits.
The LACNIC RDAP server in particular only permits a low number of requests per minute.


# Tests

There is a minimal test suite mostly to verify the parsers, you can run it by cloing
this repository, installing the required dependancies and execuiting:

```bash
$ make test
```


# Contributing

All properly formatted and sensible pull requests, issues and comments are
