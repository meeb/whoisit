from ipaddress import (
    IPv4Network,
    IPv6Network,
    ip_address,
    ip_network,
    summarize_address_range,
)
from sys import getsizeof

from dateutil.parser import parse as dateutil_parse
from typing_extensions import TypedDict

from .bootstrap import _BootstrapWrapper
from .errors import BootstrapError, ParseError
from .logger import get_logger

log = get_logger("parser")


def clean(s: str) -> str:
    if s is None:
        s = ""
    if not isinstance(s, str):
        s = str(s)
    return s.strip()


def clean_address(a: str | None) -> str:
    if a is None:
        a = ""
    if isinstance(a, list):
        a = " ".join(a)
    if not isinstance(a, str):
        a = str(a)
    return a.strip()


class VCardArrayDataDict(TypedDict, total=False):
    name: str
    person: str
    organisation: str
    kind: str
    title: str
    role: str
    email: str
    emails: list[str]
    tel: str
    phones: list[str]
    fax: list[str]
    websites: list[str]
    contact_uris: list[str]
    address: "VCardArrayAddressDataDict"


class VCardArrayAddressDataDict(TypedDict, total=False):
    po_box: str
    ext_address: str
    street_address: str
    locality: str
    region: str
    postal_code: str
    country: str
    label: str


def _append_unique(d: dict, key: str, value: str) -> None:
    if value:
        d.setdefault(key, [])
        if value not in d[key]:
            d[key].append(value)


def parse_vcard(vcard: dict | list) -> VCardArrayDataDict | None:
    """
    Extract useful summary information from a VCard (jCard) array.
    """
    if not isinstance(vcard, list):
        return None
    if len(vcard) != 2:
        return None
    card_field, card_data = vcard
    if card_field != "vcard" or not isinstance(card_data, list):
        return None
    v_card_array_data_dict = VCardArrayDataDict()
    full_name = ""
    for field in card_data:
        if not isinstance(field, list) or len(field) != 4:
            continue
        entry_field, entry_data, entry_type, entry_label = field
        if not isinstance(entry_data, dict):
            entry_data = {}
        # Contact methods are often URIs, such as tel:+1.555, everything else
        # used is text
        if entry_field == "email":
            email = clean(entry_label)
            if email.lower().startswith("mailto:"):
                email = email[7:]
            _append_unique(v_card_array_data_dict, "emails", email)
        elif entry_field == "tel":
            tel = clean(entry_label)
            if tel.lower().startswith("tel:"):
                tel = tel[4:]
            tel_types = entry_data.get("type", [])
            if isinstance(tel_types, str):
                tel_types = [tel_types]
            tel_types = [str(t).lower() for t in tel_types]
            key = "fax" if "fax" in tel_types else "phones"
            _append_unique(v_card_array_data_dict, key, tel)
        elif entry_field == "url":
            _append_unique(v_card_array_data_dict, "websites", clean(entry_label))
        elif entry_field == "contact-uri":
            _append_unique(v_card_array_data_dict, "contact_uris", clean(entry_label))
        elif entry_type != "text":
            continue
        elif entry_field == "fn":
            full_name = clean(entry_label)
            v_card_array_data_dict["name"] = full_name
        elif entry_field == "org":
            v_card_array_data_dict["name"] = clean(entry_label)
            v_card_array_data_dict["organisation"] = clean_address(entry_label)
        elif entry_field == "kind":
            v_card_array_data_dict["kind"] = clean(entry_label).lower()
        elif entry_field in ("title", "role"):
            v_card_array_data_dict[entry_field] = clean(entry_label)
        elif entry_field == "adr":
            label = entry_data.get("label", "")
            if isinstance(label, list):
                label = "\n".join(str(line) for line in label)
            address = None
            if isinstance(entry_label, list) and len(entry_label) == 7:
                address = VCardArrayAddressDataDict(
                    po_box=clean_address(entry_label[0]),
                    ext_address=clean_address(entry_label[1]),
                    street_address=clean_address(entry_label[2]),
                    locality=clean_address(entry_label[3]),
                    region=clean_address(entry_label[4]),
                    postal_code=clean_address(entry_label[5]),
                    country=clean_address(entry_label[6]),
                )
            elif label:
                address = VCardArrayAddressDataDict(
                    po_box="",
                    ext_address="",
                    street_address="",
                    locality="",
                    region="",
                    postal_code="",
                    country="",
                )
            if address is not None:
                if label:
                    lines = (line.strip() for line in str(label).splitlines())
                    address["label"] = "\n".join(line for line in lines if line)
                v_card_array_data_dict["address"] = address
    # The first email and first non-fax phone number are the primary contacts
    if v_card_array_data_dict.get("emails"):
        v_card_array_data_dict["email"] = v_card_array_data_dict["emails"][0]
    if v_card_array_data_dict.get("phones"):
        v_card_array_data_dict["tel"] = v_card_array_data_dict["phones"][0]
    # "name" is either the full name or the organisation, whichever is last in the
    # vcard, so set the person name separately where the vcard is not for an
    # organisation and the full name is useful
    kind = v_card_array_data_dict.get("kind", "")
    if (
        full_name
        and kind != "org"
        and (kind == "individual" or full_name != v_card_array_data_dict.get("name"))
    ):
        v_card_array_data_dict["person"] = full_name
    return v_card_array_data_dict or None


def parse_events(events: list) -> list[dict]:
    """
    Extract all events as a list of {"action": str, "date": datetime, "actor": str}
    """
    parsed_events = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        action = clean(event.get("eventAction", "")).lower()
        date = clean(event.get("eventDate", ""))
        if not action or not date:
            continue
        try:
            date = dateutil_parse(date, fuzzy=True)
        except (ValueError, OverflowError):
            continue
        parsed_events.append(
            {"action": action, "date": date, "actor": clean(event.get("eventActor"))}
        )
    return parsed_events


def parse_links(links: list) -> list[dict]:
    """
    Extract all links as a list of {"rel": str, "href": str, "type": str}
    """
    parsed_links = []
    for link in links or []:
        if not isinstance(link, dict):
            continue
        href = clean(link.get("href", ""))
        if href:
            parsed_links.append(
                {
                    "rel": clean(link.get("rel", "")).lower(),
                    "href": href,
                    "type": clean(link.get("type", "")),
                }
            )
    return parsed_links


def find_link(links: list, rels: tuple[str, ...]) -> str:
    """
    Find the first non-HTML link URL with a rel in rels from a list of parsed links.
    """
    for link in links:
        if link["rel"] in rels and not link["type"].startswith("text/html"):
            return link["href"]
    return ""


def parse_remarks(remarks: list) -> list[dict]:
    """
    Extract notices or remarks as a list of
    {"title": str, "type": str, "description": list[str], "links": list[str]}
    """
    parsed_remarks = []
    for remark in remarks or []:
        if not isinstance(remark, dict):
            continue
        description = remark.get("description", []) or []
        if isinstance(description, str):
            description = [description]
        parsed_remarks.append(
            {
                "title": clean(remark.get("title", "")),
                "type": clean(remark.get("type", "")),
                "description": [clean(line) for line in description],
                "links": [
                    link["href"] for link in parse_links(remark.get("links", []))
                ],
            }
        )
    return parsed_remarks


def parse_public_ids(public_ids: list) -> list[dict]:
    """
    Extract public IDs as a list of {"type": str, "identifier": str}
    """
    parsed_public_ids = []
    for public_id in public_ids or []:
        if not isinstance(public_id, dict):
            continue
        identifier = clean(public_id.get("identifier", ""))
        if identifier:
            parsed_public_ids.append(
                {"type": clean(public_id.get("type", "")), "identifier": identifier}
            )
    return parsed_public_ids


def parse_status(status: list) -> list[str]:
    return [clean(s) for s in status or [] if clean(s)]


def parse_network_summaries(networks: list) -> list[dict]:
    """
    Summarise networks embedded in entities as a list of
    {"handle": str, "name": str, "start_address": str, "end_address": str}
    """
    return [
        {
            "handle": clean(network.get("handle", "")),
            "name": clean(network.get("name", "")),
            "start_address": clean(network.get("startAddress", "")),
            "end_address": clean(network.get("endAddress", "")),
        }
        for network in networks or []
        if isinstance(network, dict)
    ]


def parse_autnum_summaries(autnums: list) -> list[dict]:
    """
    Summarise autnums embedded in entities as a list of
    {"handle": str, "name": str, "start_autnum": int, "end_autnum": int}
    """
    return [
        {
            "handle": clean(autnum.get("handle", "")),
            "name": clean(autnum.get("name", "")),
            "start_autnum": autnum.get("startAutnum"),
            "end_autnum": autnum.get("endAutnum"),
        }
        for autnum in autnums or []
        if isinstance(autnum, dict)
    ]


class Parser:
    """
    A Parser extracts the most useful information from an RDAP response for each
    response type (ip, domain, etc.) and returns it as a flat dictionary. This
    parent class extracts generic information available to all entity types where
    available.
    """

    def __init__(
        self,
        bootstrap: _BootstrapWrapper,
        raw_data: dict,
        query: str,
        using_overrides: bool = False,
    ) -> None:
        self.bootstrap = bootstrap
        self.raw_data = raw_data
        self.query = str(query)
        self.parsed = {}
        self.using_overrides = bool(using_overrides)
        self.extract_handle()
        # As a basic check every object must have at least a handle set
        # Permit overridden endpoints to not return a handle
        if not self.parsed["handle"] and not self.using_overrides:
            raise ParseError(
                f"Failed to parse any meaningful data to find a "
                f"handle in raw data: {self.raw_data}"
            )
        self.extract_parent_handle()
        self.extract_name()
        self.extract_whois_server()
        self.extract_response_type()
        self.extract_notices()
        self.extract_description()
        self.extract_dates()
        self.extract_self_link()
        self.extract_entities()
        self.extract_status()
        self.extract_events()
        self.extract_public_ids()
        self.extract_links()
        self.extract_notices_and_remarks()
        self.extract_redacted()

    def parse(self):
        raise NotImplementedError("parse must be implemented")

    def parse_vcard_array(self, vcard: dict | list) -> VCardArrayDataDict | None:
        """
        Extract useful summary information from a VCard array.
        """
        return parse_vcard(vcard)

    def extract_handle(self) -> None:
        # First, try to get the handle from top level results
        handle = clean(self.raw_data.get("handle", ""))
        if handle:
            self.parsed["handle"] = handle.upper()
            return
        # If no top-level handle, look for it in entities (registrar entity usually has it)
        for entity in self.raw_data.get("entities", []):
            entity_handle = clean(entity.get("handle", ""))
            if entity_handle:
                self.parsed["handle"] = entity_handle.upper()
                return
        # If still no handle found, set empty string
        self.parsed["handle"] = ""

    def extract_parent_handle(self) -> None:
        self.parsed["parent_handle"] = clean(
            self.raw_data.get("parentHandle", "")
        ).upper()

    def extract_name(self) -> None:
        self.parsed["name"] = clean(self.raw_data.get("name", ""))

    def extract_whois_server(self) -> None:
        self.parsed["whois_server"] = clean(self.raw_data.get("port43", ""))

    def extract_response_type(self) -> None:
        self.parsed["type"] = clean(self.raw_data.get("objectClassName", ""))

    def extract_notices(self) -> None:
        self.parsed["terms_of_service_url"] = ""
        self.parsed["copyright_notice"] = ""
        for notice in self.raw_data.get("notices", []):
            if isinstance(notice, str):
                title = notice
            else:
                title = clean(notice.get("title", "")).lower()
            if title in ("terms of service", "terms of use", "terms and conditions"):
                links = notice.get("links", [])
                try:
                    link = links[0]
                except (IndexError, KeyError):
                    continue
                self.parsed["terms_of_service_url"] = clean(
                    link.get("href", "")
                ).strip()
            elif title == "copyright notice":
                descriptions = notice.get("description", [])
                try:
                    description = descriptions[0]
                except IndexError:
                    continue
                self.parsed["copyright_notice"] = clean(description)

    def extract_description(self) -> None:
        self.parsed["description"] = []
        remarks = self.raw_data.get("remarks", [])
        for remark in remarks:
            title = clean(remark.get("title", "")).lower()
            description = remark.get("description", [])
            if not description:
                continue
            if len(remarks) == 1:
                # There is only one remark, use it
                self.parsed["description"] = description
            elif title == "description":
                # Multiple remarks, add only the description
                self.parsed["description"] = description

    def extract_dates(self) -> None:
        self.parsed["last_changed_date"] = None
        self.parsed["registration_date"] = None
        self.parsed["expiration_date"] = None
        for event in self.raw_data.get("events", []):
            action = event.get("eventAction").strip().lower()
            if action == "last changed":
                last_changed_date = event.get("eventDate", "")
                if last_changed_date:
                    self.parsed["last_changed_date"] = dateutil_parse(
                        last_changed_date, fuzzy=True
                    )
            elif action == "registration":
                registration_date = event.get("eventDate", "")
                if registration_date:
                    self.parsed["registration_date"] = dateutil_parse(
                        registration_date, fuzzy=True
                    )
            elif action == "expiration":
                expiration_date = event.get("eventDate", "")
                if expiration_date:
                    self.parsed["expiration_date"] = dateutil_parse(
                        expiration_date, fuzzy=True
                    )

    def extract_status(self) -> None:
        self.parsed["status"] = parse_status(self.raw_data.get("status", []))

    def extract_events(self) -> None:
        self.parsed["events"] = parse_events(self.raw_data.get("events", []))

    def extract_public_ids(self) -> None:
        self.parsed["public_ids"] = parse_public_ids(self.raw_data.get("publicIds", []))

    def extract_links(self) -> None:
        self.parsed["links"] = parse_links(self.raw_data.get("links", []))

    def extract_notices_and_remarks(self) -> None:
        self.parsed["notices"] = parse_remarks(self.raw_data.get("notices", []))
        self.parsed["remarks"] = parse_remarks(self.raw_data.get("remarks", []))

    def extract_redacted(self) -> None:
        """
        Extract the names of redacted fields (RFC 9537) as a list of strings.
        """
        self.parsed["redacted"] = []
        for redacted in self.raw_data.get("redacted", []) or []:
            if not isinstance(redacted, dict):
                continue
            name = redacted.get("name", {})
            if isinstance(name, dict):
                name = name.get("description") or name.get("type") or ""
            name = clean(name)
            if name and name not in self.parsed["redacted"]:
                self.parsed["redacted"].append(name)

    def extract_self_link(self) -> None:
        self.parsed["url"] = ""
        for link in self.raw_data.get("links", []):
            if link.get("rel", "").strip().lower() == "self":
                self.parsed["url"] = clean(link.get("href", ""))
        self.parsed["rir"] = ""
        if self.parsed["url"]:
            try:
                self.parsed["rir"] = self.bootstrap.get_rir_name_by_endpoint_url(
                    self.parsed["url"]
                )
            except BootstrapError:
                pass

    def extract_entities(
        self,
        entities: dict | None = None,
        parent_handle: str = "",
        parent_name: str = "",
    ) -> None:
        self.parsed.setdefault("entities", {})
        if not entities:
            entities = self.raw_data.get("entities", [])
        # Keys which only describe where an entity was found, not the entity itself
        location_keys = ("parent_handle", "parent_name")
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            handle = clean(entity.get("handle", "")).upper()
            url = ""
            for link in entity.get("links", []):
                if link.get("rel", "").strip().lower() == "self":
                    url = clean(link.get("href", ""))
            if not url:
                url = entity.get("url", "")
            rir = ""
            if url:
                try:
                    rir = self.bootstrap.get_rir_name_by_endpoint_url(url)
                except BootstrapError:
                    pass
            entity_type = clean(entity.get("objectClassName", ""))
            whois_server = clean(entity.get("port43", ""))
            # Most common use cases care about the name and email address
            vcard = self.parse_vcard_array(entity.get("vcardArray", []))
            status = parse_status(entity.get("status", []))
            events = parse_events(entity.get("events", []))
            public_ids = parse_public_ids(entity.get("publicIds", []))
            remarks = parse_remarks(entity.get("remarks", []))
            networks = parse_network_summaries(entity.get("networks", []))
            autnums = parse_autnum_summaries(entity.get("autnums", []))
            for role in entity.get("roles", []):
                parsed_entity = {}
                if handle:
                    parsed_entity["handle"] = handle
                if url:
                    parsed_entity["url"] = url
                if entity_type:
                    parsed_entity["type"] = entity_type
                if whois_server:
                    parsed_entity["whois_server"] = whois_server
                if rir:
                    parsed_entity["rir"] = rir
                if vcard:
                    parsed_entity.update(vcard)
                if status:
                    parsed_entity["status"] = status
                if events:
                    parsed_entity["events"] = events
                if public_ids:
                    parsed_entity["public_ids"] = public_ids
                if remarks:
                    parsed_entity["remarks"] = remarks
                if networks:
                    parsed_entity["networks"] = networks
                if autnums:
                    parsed_entity["autnums"] = autnums
                if parsed_entity:
                    if parent_handle:
                        parsed_entity["parent_handle"] = parent_handle
                    if parent_name:
                        parsed_entity["parent_name"] = parent_name
                    self.parsed["entities"].setdefault(role, [])
                    # ignore duplicate entity per role, wherever it was found
                    existing = [
                        {k: v for k, v in e.items() if k not in location_keys}
                        for e in self.parsed["entities"].get(role, [])
                    ]
                    comparable = {
                        k: v for k, v in parsed_entity.items() if k not in location_keys
                    }
                    if comparable not in existing:
                        self.parsed["entities"][role.lower()].append(parsed_entity)
            if entity.get("entities"):
                name = vcard.get("name", "") if vcard else ""
                self.extract_entities(
                    entities=entity.get("entities"),
                    parent_handle=handle,
                    parent_name=name or handle,
                )


class ParseAutnum(Parser):
    """
    Additional data extractors for autnum objects.
    """

    def parse(self) -> dict:
        response_type = self.parsed["type"]
        if response_type != "autnum":
            raise ParseError(
                f'Expected response type of "autnum", got reply '
                f'data of type "{response_type}" instead'
            )
        self.extract_asn_range()
        self.extract_assignment_type()
        self.extract_country()
        return self.parsed

    def extract_assignment_type(self) -> None:
        self.parsed["assignment_type"] = clean(self.raw_data.get("type", "")).lower()

    def extract_country(self) -> None:
        self.parsed["country"] = clean(self.raw_data.get("country", ""))

    def extract_asn_range(self) -> None:
        self.parsed["asn_range"] = None
        start_asn_range = self.raw_data.get("startAutnum", 0)
        end_asn_range = self.raw_data.get("endAutnum", 0)
        try:
            start_asn_range = int(start_asn_range)
        except (ValueError, TypeError):
            start_asn_range = 0
        try:
            end_asn_range = int(end_asn_range)
        except (ValueError, TypeError):
            end_asn_range = 0
        if start_asn_range > 0 and end_asn_range > 0:
            self.parsed["asn_range"] = [start_asn_range, end_asn_range]


class ParseDomain(Parser):
    """
    Additional data extractors for domain objects.
    """

    def parse(self) -> dict:
        response_type = self.parsed["type"]
        if response_type != "domain":
            raise ParseError(
                f'Expected response type of "domain", got reply '
                f'data of type "{response_type}" instead'
            )
        self.extract_domain_name()
        self.extract_domain_nameservers()
        self.extract_domain_status()
        self.extract_domain_dnssec()
        self.extract_registrar_url()
        return self.parsed

    def extract_registrar_url(self) -> None:
        """
        The URL of the registrar RDAP service for the domain, if any.
        """
        self.parsed["registrar_url"] = find_link(
            self.parsed["links"], ("related", "registration")
        )

    def extract_domain_name(self) -> None:
        self.parsed["name"] = clean(self.raw_data.get("ldhName", ""))
        self.parsed["unicode_name"] = clean(self.raw_data.get("unicodeName", ""))

    def extract_domain_nameservers(self) -> None:
        """
        Nameserver names as a list and a dict of {name: [ip addresses]}.
        """
        self.parsed["nameservers"] = []
        self.parsed["nameserver_ips"] = {}
        for nameserver in self.raw_data.get("nameservers", []):
            if nameserver.get("objectClassName", "") == "nameserver":
                name = clean(nameserver.get("ldhName", ""))
                if name:
                    self.parsed["nameservers"].append(name)
                    addresses = nameserver.get("ipAddresses", {}) or {}
                    self.parsed["nameserver_ips"][name] = [
                        clean(ip)
                        for ip in (addresses.get("v4", []) or [])
                        + (addresses.get("v6", []) or [])
                    ]

    def extract_domain_status(self) -> None:
        # Status is extracted for all object types, retained for compatibility
        self.extract_status()

    def extract_domain_dnssec(self) -> None:
        """
        SecureDNS.delegationSigned boolean indicates active dnssec.
        """
        self.parsed["dnssec"] = False
        self.parsed["dnssec_ds_data"] = []
        self.parsed["dnssec_key_data"] = []
        secure_dns = self.raw_data.get("secureDNS", {})
        if not isinstance(secure_dns, dict):
            return
        if secure_dns.get("delegationSigned", None):
            self.parsed["dnssec"] = True
        for ds in secure_dns.get("dsData", []) or []:
            if isinstance(ds, dict):
                self.parsed["dnssec_ds_data"].append(
                    {
                        "key_tag": ds.get("keyTag"),
                        "algorithm": ds.get("algorithm"),
                        "digest_type": ds.get("digestType"),
                        "digest": clean(ds.get("digest", "")),
                    }
                )
        for key in secure_dns.get("keyData", []) or []:
            if isinstance(key, dict):
                self.parsed["dnssec_key_data"].append(
                    {
                        "flags": key.get("flags"),
                        "protocol": key.get("protocol"),
                        "algorithm": key.get("algorithm"),
                        "public_key": clean(key.get("publicKey", "")),
                    }
                )


class ParseIPNetwork(Parser):
    """
    Additional data extractors for ip network objects.
    """

    def parse(self) -> dict:
        response_type = self.parsed["type"]
        if response_type != "ip network":
            raise ParseError(
                f'Expected response type of "ip network", got reply '
                f'data of type "{response_type}" instead'
            )
        self.extract_country()
        self.extract_ip_version()
        self.extract_assignment_type()
        self.extract_network()
        self.extract_address_range()
        self.extract_cidrs()
        self.extract_origin_autnums()
        self.extract_parent_url()
        return self.parsed

    def extract_address_range(self) -> None:
        self.parsed["start_address"] = clean(self.raw_data.get("startAddress", ""))
        self.parsed["end_address"] = clean(self.raw_data.get("endAddress", ""))

    def extract_cidrs(self) -> None:
        """
        All networks for the object, the "network" value is only a single network
        which matches the query.
        """
        self.parsed["cidrs"] = []
        cidr = self.raw_data.get("cidr0_cidrs", None)
        if isinstance(cidr, list):
            for cidr_parts in cidr:
                if not isinstance(cidr_parts, dict):
                    continue
                length = cidr_parts.get("length", "")
                prefix = cidr_parts.get("v4prefix", "") or cidr_parts.get(
                    "v6prefix", ""
                )
                if prefix and length != "":
                    try:
                        self.parsed["cidrs"].append(ip_network(f"{prefix}/{length}"))
                    except (TypeError, ValueError):
                        continue
        elif self.parsed["start_address"] and self.parsed["end_address"]:
            try:
                self.parsed["cidrs"] = list(
                    summarize_address_range(
                        ip_address(self.parsed["start_address"]),
                        ip_address(self.parsed["end_address"]),
                    )
                )
            except (TypeError, ValueError):
                pass

    def extract_origin_autnums(self) -> None:
        self.parsed["origin_autnums"] = []
        for autnum in self.raw_data.get("arin_originas0_originautnums", []) or []:
            try:
                self.parsed["origin_autnums"].append(int(autnum))
            except (TypeError, ValueError):
                continue

    def extract_parent_url(self) -> None:
        self.parsed["parent_url"] = find_link(self.parsed["links"], ("up",))

    def extract_country(self) -> None:
        self.parsed["country"] = clean(self.raw_data.get("country", ""))

    def extract_ip_version(self) -> None:
        self.parsed["ip_version"] = None
        ip_version = clean(self.raw_data.get("ipVersion", ""))
        if ip_version == "v4":
            self.parsed["ip_version"] = 4
        elif ip_version == "v6":
            self.parsed["ip_version"] = 6

    def extract_assignment_type(self) -> None:
        self.parsed["assignment_type"] = clean(self.raw_data.get("type", "")).lower()

    def extract_network(self) -> None:
        self.parsed["network"] = None
        cidr = self.raw_data.get("cidr0_cidrs", None)
        if isinstance(cidr, list):
            try:
                query_ip = ip_address(self.query.strip())
            except (ValueError, TypeError):
                query_ip = False
            for cidr_parts in cidr:
                length = cidr_parts.get("length", "")
                v4prefix = cidr_parts.get("v4prefix", "")
                v6prefix = cidr_parts.get("v6prefix", "")
                if length:
                    if v4prefix:
                        try:
                            parsed_network = IPv4Network(f"{v4prefix}/{length}")
                            if query_ip and query_ip.version == parsed_network.version:
                                if query_ip in parsed_network:
                                    self.parsed["network"] = parsed_network
                                    break
                            else:
                                self.parsed["network"] = parsed_network
                                break
                        except (TypeError, ValueError):
                            return
                    elif v6prefix:
                        try:
                            parsed_network = IPv6Network(f"{v6prefix}/{length}")
                            if query_ip and query_ip.version == parsed_network.version:
                                if query_ip in parsed_network:
                                    self.parsed["network"] = parsed_network
                                    break
                            else:
                                self.parsed["network"] = parsed_network
                                break
                        except (TypeError, ValueError):
                            return
        else:
            start_address = self.raw_data.get("startAddress", None)
            end_address = self.raw_data.get("endAddress", None)
            if start_address is not None and end_address is not None:
                try:
                    networks = summarize_address_range(
                        ip_address(start_address), ip_address(end_address)
                    )
                    self.parsed["network"] = next(networks)
                except StopIteration:
                    return


class ParseEntity(Parser):
    """
    Additional data extractors for entity objects.
    """

    def parse(self) -> dict:
        response_type = self.parsed["type"]
        if response_type != "entity":
            raise ParseError(
                f'Expected response type of "entity", got reply '
                f'data of type "{response_type}" instead'
            )
        self.extract_root_vcard()
        self.extract_roles()
        self.extract_networks_and_autnums()
        return self.parsed

    def extract_roles(self) -> None:
        self.parsed["roles"] = [
            clean(r).lower() for r in self.raw_data.get("roles", []) or []
        ]

    def extract_networks_and_autnums(self) -> None:
        self.parsed["networks"] = parse_network_summaries(
            self.raw_data.get("networks", [])
        )
        self.parsed["autnums"] = parse_autnum_summaries(
            self.raw_data.get("autnums", [])
        )

    def extract_root_vcard(self) -> None:
        root_vcard = self.raw_data.get("vcardArray", [])
        if root_vcard:
            parsed = self.parse_vcard_array(root_vcard)
            if parsed:
                self.parsed.update(parsed)


# These map the objectClassName values returned in RDAP responses
parser_map: dict[str, type[Parser]] = {
    "autnum": ParseAutnum,
    "domain": ParseDomain,
    "ip network": ParseIPNetwork,
    "entity": ParseEntity,
}


def parse(
    bootstrap: _BootstrapWrapper,
    data_type: dict,
    query: str,
    raw_data: dict,
    include_raw: bool = False,
) -> dict:
    # Find a parser for the response type, falling back to the request / data type
    response_type = raw_data.get("objectClassName", data_type)
    parser_class = parser_map.get(response_type, None)
    if parser_class is None:
        raise ParseError(f"No parser for response_type: {response_type}")
    log.debug(
        f"Parsing request type {data_type} {getsizeof(raw_data)} byte dict "
        f"with parser: {response_type} / {parser_class}"
    )
    p = parser_class(
        bootstrap, raw_data, query, using_overrides=bootstrap.is_using_overrides()
    )
    parsed = p.parse()
    if include_raw:
        parsed["raw"] = raw_data
    return parsed
