class WhoisItError(Exception):
    '''
        Parent Exception for all whoisit raised exceptions.
    '''

class BootstrapError(WhoisItError):
    '''
        Raised when there are any issues with bootstrapping.
    '''

class QueryError(WhoisItError):
    '''
        Raised when there are any issues with queries.
    '''

class UnsupportedError(WhoisItError):
    '''
        Raised when a feature in a query is unsupported.
    '''


class ParseError(WhoisItError):
    '''
        Raised when failing to parse response data.
    '''
