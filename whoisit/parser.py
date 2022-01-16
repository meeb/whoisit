from sys import getsizeof
from ipaddress import ip_address, IPv4Network, IPv6Network
from dateutil.parser import parse as dateutil_parse
from .errors import BootstrapError, ParseError
from .logger import get_logger


log = get_logger('parser')


def clean(s):
    if s is None:
        s = ''
    if not isinstance(s, str):
        s = str(s)
    return s.strip()


class Parser:
    """
        A Parser extracts the most useful information from an RDAP response for each
        response type (ip, domain etc.) and returns it as a flat dictionary. This
        parent class extracts generic information available to all entity types where
        available.
    """

    def __init__(self, bootstrap, raw_data, using_overrides=False):
        self.bootstrap = bootstrap
        self.raw_data = raw_data
        self.parsed = {}
        self.using_overrides = bool(using_overrides)
        self.extract_handle()
        # As a basic check every object must have at least a handle set
        if not self.parsed['handle']:
            # Permit overridden endpoints to not return a handle
            if not self.using_overrides:
                raise ParseError(f'Failed to parse any meaningful data to find a '
                                 f'handle in raw data: {self.raw_data}')
        self.extract_parent_handle()
        self.extract_name()
        self.extract_whois_server()
        self.extract_response_type()
        self.extract_notices()
        self.extract_description()
        self.extract_dates()
        self.extract_self_link()
        self.extract_entities()

    def parse(self):
        raise NotImplemented('parse must be implemented')

    def parse_vcard_array(self, vcard):
        '''
            Extract useful summary information from a vcard array. This only extracts
            the email address and name.
        '''
        if not isinstance(vcard, list):
            return False
        if len(vcard) != 2:
            return False
        card_field, card_data = vcard
        if card_field != 'vcard':
            return False
        name, email = '', ''
        for field in card_data:
            if len(field) != 4:
                continue
            entry_field, entry_data, entry_type, entry_label = field
            if entry_type != 'text':
                continue
            elif entry_field == 'fn':
                name = clean(entry_label)
            elif entry_field == 'org':
                name = clean(entry_label)
            elif entry_field == 'email':
                email = clean(entry_label)
        return (name, email) if name or email else False

    def extract_handle(self):
        self.parsed['handle'] = clean(self.raw_data.get('handle', '')).upper()

    def extract_parent_handle(self):
        self.parsed['parent_handle'] = clean(
            self.raw_data.get('parentHandle', '')).upper()

    def extract_name(self):
        self.parsed['name'] = clean(self.raw_data.get('name', ''))

    def extract_whois_server(self):
        self.parsed['whois_server'] = clean(self.raw_data.get('port43', ''))

    def extract_response_type(self):
        self.parsed['type'] = clean(self.raw_data.get('objectClassName', ''))

    def extract_notices(self):
        self.parsed['terms_of_service_url'] = ''
        self.parsed['copyright_notice'] = ''
        for notice in self.raw_data.get('notices', []):
            title = clean(notice.get('title', '')).lower()
            if title in ('terms of service', 'terms of use', 'terms and conditions'):
                links = notice.get('links', [])
                try:
                    link = links[0]
                except IndexError:
                    continue
                self.parsed['terms_of_service_url'] = clean(
                    link.get('href', '')).strip()
            elif title == 'copyright notice':
                descriptions = notice.get('description', [])
                try:
                    description = descriptions[0]
                except IndexError:
                    continue
                self.parsed['copyright_notice'] = clean(description)

    def extract_description(self):
        self.parsed['description'] = []
        remarks = self.raw_data.get('remarks', [])
        for remark in remarks:
            title = clean(remark.get('title', '')).lower()
            description = remark.get('description', [])
            if not description:
                continue
            if len(remarks) == 1:
                # There is only one remark, use it
                self.parsed['description'] = description
            elif title == 'description':
                # Multiple remarks, add only the description
                self.parsed['description'] = description


    def extract_dates(self):
        self.parsed['last_changed_date'] = None
        self.parsed['registration_date'] = None
        self.parsed['expiration_date'] = None
        for event in self.raw_data.get('events', []):
            action = event.get('eventAction').strip().lower()
            if action == 'last changed':
                last_changed_date = event.get('eventDate', '')
                if last_changed_date:
                    self.parsed['last_changed_date'] = dateutil_parse(last_changed_date)
            elif action == 'registration':
                registration_date = event.get('eventDate', '')
                if registration_date:
                    self.parsed['registration_date'] = dateutil_parse(registration_date)
            elif action == 'expiration':
                expiration_date = event.get('eventDate', '')
                if expiration_date:
                    self.parsed['expiration_date'] = dateutil_parse(expiration_date)

    def extract_self_link(self):
        self.parsed['url'] = ''
        for link in self.raw_data.get('links', []):
            if link.get('rel', '').strip().lower() == 'self':
                self.parsed['url'] = clean(link.get('href', ''))
        else:
            self.parsed['rir'] = ''
        if self.parsed['url']:
            try:
                self.parsed['rir'] = self.bootstrap.get_rir_name_by_endpoint_url(
                    self.parsed['url'])
            except BootstrapError:
                pass

    def extract_entities(self):
        self.parsed['entities'] = {}
        for entity in self.raw_data.get('entities', []):
            handle = clean(entity.get('handle', '')).upper()
            url = ''
            for link in entity.get('links', []):
                if link.get('rel', '').strip().lower() == 'self':
                    url = clean(link.get('href', ''))
            if not url:
                url = entity.get('url', '')
            rir = ''
            if url:
                try:
                    rir = self.bootstrap.get_rir_name_by_endpoint_url(url)
                except BootstrapError:
                    pass
            entity_type = clean(entity.get('objectClassName', ''))
            whois_server = clean(entity.get('port43', ''))
            # Most common use cases care about the name and email address
            name, email = '', ''
            vcard = self.parse_vcard_array(entity.get('vcardArray', []))
            if vcard:
                name, email = vcard
            for role in entity.get('roles', []):
                entity = {}
                if handle:
                    entity['handle'] = handle
                if url:
                    entity['url'] = url
                if entity_type:
                    entity['type'] = entity_type
                if whois_server:
                    entity['whois_server'] = whois_server
                if name:
                    entity['name'] = name
                if email:
                    entity['email'] = email
                if rir:
                    entity['rir'] = rir
                if entity:
                    self.parsed['entities'].setdefault(role, []).append(entity)


class ParseAutnum(Parser):
    """
        Additional data extractors for autnum objects.
    """

    def parse(self):
        response_type = self.parsed['type']
        if response_type != 'autnum':
            raise ParseError(f'Expected response type of "autnum", got reply '
                             f'data of type "{response_type}" instead')
        self.extract_asn_range()
        return self.parsed

    def extract_asn_range(self):
        self.parsed['asn_range'] = None
        start_asn_range = self.raw_data.get('startAutnum', 0)
        end_asn_range = self.raw_data.get('endAutnum', 0)
        if start_asn_range > 0 and end_asn_range > 0:
            self.parsed['asn_range'] = [start_asn_range, end_asn_range]


class ParseDomain(Parser):
    """
        Additional data extractors for domain objects.
    """

    def parse(self):
        response_type = self.parsed['type']
        if response_type != 'domain':
            raise ParseError(f'Expected response type of "domain", got reply '
                             f'data of type "{response_type}" instead')
        self.extract_domain_name()
        self.extract_domain_nameservers()
        self.extract_domain_status()
        self.extract_domain_dnssec()
        return self.parsed

    def extract_domain_name(self):
        self.parsed['name'] = clean(self.raw_data.get('ldhName', ''))

    def extract_domain_nameservers(self):
        self.parsed['nameservers'] = []
        for nameserver in self.raw_data.get('nameservers', []):
            if nameserver.get('objectClassName', '') == 'nameserver':
                nameserver = nameserver.get('ldhName', '')
                if nameserver:
                    self.parsed['nameservers'].append(clean(nameserver))

    def extract_domain_status(self):
        self.parsed['status'] = []
        for status in self.raw_data.get('status', []):
            self.parsed['status'].append(clean(status))

    def extract_domain_dnssec(self):
        """
            SecureDNS.delegationSigned boolean indicates active dnssec.
        """
        self.parsed['dnssec'] = False
        if self.raw_data.get('secureDNS', {}).get('delegationSigned', None):
            self.parsed['dnssec'] = True


class ParseIPNetwork(Parser):
    """
        Additional data extractors for ip network objects.
    """

    def parse(self):
        response_type = self.parsed['type']
        if response_type != 'ip network':
            raise ParseError(f'Expected response type of "ip network", got reply '
                             f'data of type "{response_type}" instead')
        self.extract_country()
        self.extract_ip_version()
        self.extract_assignment_type()
        self.extract_network()
        return self.parsed

    def extract_country(self):
        self.parsed['country'] = clean(self.raw_data.get('country', ''))

    def extract_ip_version(self):
        self.parsed['ip_version'] = None
        ip_version = clean(self.raw_data.get('ipVersion', ''))
        if ip_version == 'v4':
            self.parsed['ip_version'] = 4
        elif ip_version == 'v6':
            self.parsed['ip_version'] = 6

    def extract_assignment_type(self):
        self.parsed['assignment_type'] = clean(self.raw_data.get('type', '')).lower()

    def extract_network(self):
        self.parsed['network'] = None
        cidr = self.raw_data.get('cidr0_cidrs', [])
        try:
            cidr_parts = cidr[0]
        except IndexError:
            return
        length = cidr_parts.get('length', '')
        v4prefix = cidr_parts.get('v4prefix', '')
        v6prefix = cidr_parts.get('v6prefix', '')
        if length:
            if v4prefix:
                try:
                    self.parsed['network'] = IPv4Network(f'{v4prefix}/{length}')
                except (TypeError, ValueError):
                    return
            elif v6prefix:
                try:
                    self.parsed['network'] = IPv6Network(f'{v6prefix}/{length}')
                except (TypeError, ValueError):
                    return


class ParseEntity(Parser):
    """
        Additional data extractors for entity objects.
    """

    def parse(self):
        response_type = self.parsed['type']
        if response_type != 'entity':
            raise ParseError(f'Expected response type of "entity", got reply '
                             f'data of type "{response_type}" instead')
        self.extract_root_vcard()
        return self.parsed

    def extract_root_vcard(self):
        self.parsed['name'] = ''
        self.parsed['email'] = ''
        root_vcard = self.raw_data.get('vcardArray', [])
        if root_vcard:
            parsed = self.parse_vcard_array(root_vcard)
            if parsed:
                name, email = parsed
                if name:
                    self.parsed['name'] = name
                if email:
                    self.parsed['email'] = email


# These map the objectClassName values returned in RDAP responses
parser_map = {
    'autnum': ParseAutnum,
    'domain': ParseDomain,
    'ip network': ParseIPNetwork,
    'entity': ParseEntity,
}


def parse(bootstrap, data_type, raw_data):
    # Find a parser for the response type, falling back to the request / data type
    response_type = raw_data.get('objectClassName', data_type)
    parser_class = parser_map.get(response_type, None)
    if not parser_class:
        raise ParseError(f'No parser for response_type: {response_type}')
    log.debug(f'Parsing request type {data_type} {getsizeof(raw_data)} byte dict '
              f'with parser: {response_type} / {parser_class}')
    p = parser_class(bootstrap, raw_data,
                     using_overrides=bootstrap.is_using_overrides())
    return p.parse()
