from .errors import ParseError


class Parser:
    '''
        A Parser extracts the most useful information from an RDAP response for each
        response type (ip, domain etc.) and returns it as a flat dictionary.
    '''

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def parse(self):
        raise NotImplemented('parse must be implemented')


class ParseAutnum(Parser):

    def parse(self):
        rtn = {}
        return rtn


class ParseDomain(Parser):

    def parse(self):
        rtn = {}
        return rtn


class ParseIP(Parser):

    def parse(self):
        rtn = {}
        return rtn


class ParseEntity(Parser):

    def parse(self):
        rtn = {}
        return rtn


parser_map {
    'autnum': ParseAutnum,
    'domain': ParseDomain,
    'ip': ParseIP,
    'entity': ParseEntity,
}


def parse(data_type, raw_data):
    parser_class = parser_map.get(data_type, None)
    if not parser_class:
        raise ParseError(f'No parser for data_type: {data_type}')
    p = parser_class(raw_data)
    return p.parse()
