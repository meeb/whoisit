class WhoisItError(Exception):
    """
    Parent Exception for all whoisit raised exceptions.
    """


class ArgumentError(WhoisItError):
    """
    Raised when there are any issues with function arguments, e.g. invalid combinations.
    """


class BootstrapError(WhoisItError):
    """
    Raised when there are any issues with bootstrapping.
    """


class QueryError(WhoisItError):
    """
    Raised when there are any issues with queries.
    """

    def __init__(self, message: str, status_code: int = 0, response: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class UnsupportedError(WhoisItError):
    """
    Raised when a feature in a query is unsupported.
    """


class ParseError(WhoisItError):
    """
    Raised when failing to parse response data.
    """


class ResourceDoesNotExist(QueryError):
    """
    Raised when querying a resource which doesn't exist.
    """


class ResourceAccessDeniedError(QueryError):
    """
    Raised when querying a resource returns an access denied response.
    """


class RateLimitedError(QueryError):
    """
    Raised when querying a resource and getting a rate limited response.
    """


class RemoteServerError(QueryError):
    """
    Raised when querying a resource and getting a remote server error response.
    """
