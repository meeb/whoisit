"""
A "whois"-like command line interface for whoisit. Queries RDAP services for
IP addresses, networks, AS numbers, domains and entities and prints the results
in a human-readable format.
"""

import argparse
import copy
import csv
import io
import json
import os
import re
import sys
import time
import warnings
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import ClassVar
from xml.etree import ElementTree

import whoisit

from .errors import (
    QueryError,
    ResourceDoesNotExist,
    UnsupportedError,
    WhoisItError,
)
from .parser import parse, parse_vcard
from .query import Query
from .utils import get_session, recursive_merge

bootstrap_cache_max_age_days = 1  # Re-bootstrap if cached data is older than this
max_sub_queries = 20  # Maximum number of entity sub-queries to make per lookup
label_width = 24  # Width of the "Label:" column in the output
indent = "  "


# Terminal formatting


url_re = re.compile(r"(?:https?|ftp)://[^\s<>\"']+|mailto:[^\s<>\"']+")


class Style:
    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def heading(self, s: str) -> str:
        return self._wrap("1", s)

    def subheading(self, s: str) -> str:
        return self._wrap("1", s)

    def label(self, s: str) -> str:
        return self._wrap("2", s)

    def comment(self, s: str) -> str:
        return self._wrap("2", s)

    def error(self, s: str) -> str:
        return self._wrap("31", s)

    def link(self, s: str) -> str:
        return self._wrap("4;34", s)

    def links(self, s: str) -> str:
        """
        Style any URLs in s as links, underlined blue like a default HTML link.
        """
        if not self.enabled:
            return s
        return url_re.sub(lambda m: self.link(m.group(0)), s)


def use_colour(when: str, stream) -> bool:
    if when == "always":
        return True
    if when == "never" or os.getenv("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


# Bootstrap handling


def get_cache_dir() -> Path:
    base = os.getenv("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "whoisit"


def bootstrap(
    use_cache: bool = True, refresh: bool = False, allow_insecure: bool = False
) -> None:
    """
    Bootstrap whoisit, caching the bootstrap data on disk so subsequent
    calls do not need to re-bootstrap
    """
    cache_file = get_cache_dir() / "bootstrap.json"
    if use_cache and not refresh and cache_file.is_file():
        try:
            whoisit.load_bootstrap_data(
                cache_file.read_text(), overrides=True, allow_insecure=allow_insecure
            )
            if not whoisit.bootstrap_is_older_than(bootstrap_cache_max_age_days):
                return
        except (OSError, ValueError, WhoisItError):
            pass
        whoisit.clear_bootstrapping()
    whoisit.bootstrap(overrides=True, allow_insecure=allow_insecure)
    if use_cache:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(whoisit.save_bootstrap_data())
        except OSError:
            pass


# Query handling


def detect_query_type(query: str) -> tuple[str, str]:
    """
    Guess the type of RDAP query from the query string, returns a tuple of
    (query_type, normalised_query).
    """
    q = query.strip()
    upper = q.upper()
    if upper.startswith("AS") and upper[2:].isdigit():
        return "asn", upper[2:]
    if q.isdigit():
        return "asn", q
    for fn in (ip_address, ip_network):
        try:
            return "ip", str(fn(q))
        except ValueError:
            pass
    if "." in q:
        return "domain", normalise_domain(q)
    return "entity", upper


def normalise_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".").lower()
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


# Map CLI query types to whoisit parser data types
data_types = {"ip": "ip", "asn": "autnum", "domain": "domain", "entity": "entity"}


def lookup(
    query_type: str,
    query: str,
    rir: str | None = None,
    follow: bool = True,
    allow_insecure_ssl: bool = False,
) -> tuple[dict, list[str]]:
    """
    Perform the lookup, returns a tuple of (parsed_response, notes) where the
    parsed response includes the full raw RDAP data under "raw" and notes is a
    list of non-fatal issues encountered while following sub-queries.
    """
    notes = []
    kwargs = {"include_raw": True, "allow_insecure_ssl": allow_insecure_ssl}
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        if query_type == "ip":
            if "/" not in query:
                query = ip_address(query)
            else:
                query = ip_network(query, strict=False)
            result = whoisit.ip(query, rir=rir, **kwargs)
        elif query_type == "asn":
            result = whoisit.asn(int(query), rir=rir, **kwargs)
        elif query_type == "domain":
            result = whoisit.domain(query, follow_related=follow, **kwargs)
        elif query_type == "entity":
            result = whoisit.entity(query, rir=rir, **kwargs)
        else:
            raise WhoisItError(f"Unknown query type: {query_type}")
    notes.extend(str(w.message) for w in caught)
    if follow:
        followed, follow_notes = follow_entities(result["raw"], allow_insecure_ssl)
        notes.extend(follow_notes)
        if followed:
            # Re-parse the response to include the additional entity data
            result = parse(
                whoisit._bootstrap,
                data_types[query_type],
                str(query),
                result["raw"],
                include_raw=True,
            )
    return result, notes


def get_link(obj: dict, rel: str) -> str:
    for link in obj.get("links", []) or []:
        if not isinstance(link, dict):
            continue
        if link.get("rel", "").strip().lower() == rel and not link.get(
            "type", ""
        ).startswith("text/html"):
            return link.get("href", "")
    return ""


def iter_entities(obj: dict):
    for entity in obj.get("entities", []) or []:
        if isinstance(entity, dict):
            yield entity
            yield from iter_entities(entity)


def follow_entities(
    raw: dict, allow_insecure_ssl: bool = False
) -> tuple[int, list[str]]:
    """
    Many RDAP services only return a summary of an entity (a handle and a link)
    in responses. Follow the self links of entities without any contact data to
    fill in the details, merging the results into the raw data in place. Returns
    a tuple of (number of entities updated, notes).
    """
    notes = []
    session = get_session(None, allow_insecure_ssl)
    fetched = {}
    count = 0
    updated = 0
    for entity in list(iter_entities(raw)):
        if entity.get("vcardArray"):
            continue
        url = get_link(entity, "self")
        if not url:
            continue
        if url not in fetched:
            if count >= max_sub_queries:
                break
            count += 1
            try:
                fetched[url] = Query(session, "GET", url).request()
            except QueryError as e:
                notes.append(f"Sub-query for entity failed: {e}")
                fetched[url] = None
        if fetched[url]:
            roles = entity.get("roles")
            recursive_merge(entity, fetched[url])
            # Keep the roles from the parent object's point of view
            if roles:
                entity["roles"] = roles
            updated += 1
    return updated, notes


# Output formatting


def format_date(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def title_case(s: str) -> str:
    s = str(s).replace("_", " ").replace("-", " ").strip()
    return s[:1].upper() + s[1:]


def format_address(address: dict | None) -> str:
    if not address:
        return ""
    if address.get("label"):
        return address["label"]
    parts = (
        "po_box",
        "ext_address",
        "street_address",
        "locality",
        "region",
        "postal_code",
        "country",
    )
    return "\n".join(address[p] for p in parts if address.get(p))


class Formatter:
    """
    Formats parsed whoisit response data into whois-like human readable text.
    """

    event_labels: ClassVar[dict[str, str]] = {
        "registration": "Registered",
        "expiration": "Expires",
        "last changed": "Last Changed",
        "transfer": "Transferred",
        "reregistration": "Re-registered",
        "reinstantiation": "Reinstated",
        "deletion": "Deleted",
        "locked": "Locked",
        "unlocked": "Unlocked",
        "enum validation expiration": "ENUM Validation Expires",
        "registrar expiration": "Registrar Expires",
    }
    rdap_updated_event = "last update of rdap database"

    def __init__(self, style: Style, verbose: bool = False) -> None:
        self.style = style
        self.verbose = verbose
        self.lines = []

    def text(self) -> str:
        return "\n".join(self.lines).rstrip() + "\n"

    def blank(self) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")

    def heading(self, s: str) -> None:
        self.blank()
        self.lines.append(self.style.heading(s))

    def subheading(self, s: str, level: int = 1) -> None:
        self.lines.append(indent * level + self.style.subheading(s))

    def comment(self, s: str) -> None:
        self.lines.append(self.style.comment(f"% {s}"))

    def field(self, label: str, value, level: int = 1) -> None:
        if value is None or value == "" or value == []:
            return
        values = value if isinstance(value, (list, tuple)) else [value]
        lines = []
        for v in values:
            lines.extend(str(v).splitlines() or [""])
        pad = indent * level
        width = max(label_width - len(pad) + len(indent), len(label) + 2)
        first = f"{label}:".ljust(width)
        self.lines.append(pad + self.style.label(first) + self.style.links(lines[0]))
        for line in lines[1:]:
            self.lines.append(pad + " " * width + self.style.links(line))

    def para(self, lines: list, level: int = 1) -> None:
        for line in lines:
            self.lines.append(indent * level + self.style.links(str(line).rstrip()))

    # Shared sections

    def common(self, obj: dict, level: int = 1) -> None:
        self.field("Status", [title_case(s) for s in obj.get("status", [])], level)
        for public_id in obj.get("public_ids", []):
            self.field(public_id["type"] or "Public ID", public_id["identifier"], level)
        self.events(obj, level)
        self.field("WHOIS Server", obj.get("whois_server", ""), level)
        self.field("RDAP URL", obj.get("url", ""), level)

    def events(self, obj: dict, level: int = 1) -> None:
        for event in obj.get("events", []):
            if event["action"] == self.rdap_updated_event:
                continue
            label = self.event_labels.get(event["action"], title_case(event["action"]))
            value = format_date(event["date"])
            if event["actor"]:
                value += f" (by {event['actor']})"
            self.field(label, value, level)

    def remarks(self, obj: dict, level: int = 1) -> None:
        remarks = obj.get("remarks", [])
        if not remarks:
            return
        if level == 1:
            self.heading("Remarks")
        else:
            self.subheading("Remarks:", level)
            level += 1
        for remark in remarks:
            title = remark["title"]
            if title and title.lower() not in ("description", "remarks"):
                self.subheading(title, level)
                self.para(remark["description"], level + 1)
            else:
                self.para(remark["description"], level)
            self.para(remark["links"], level + 1)

    def notices(self, parsed: dict) -> None:
        notices = parsed.get("notices", [])
        if not notices:
            return
        self.heading("Notices")
        for notice in notices:
            self.subheading(notice["title"] or "Notice")
            if self.verbose:
                self.para(notice["description"], 2)
            self.para(notice["links"], 2)

    def redacted(self, parsed: dict) -> None:
        if parsed.get("redacted"):
            self.heading("Redacted Fields")
            self.para(parsed["redacted"])

    def links(self, parsed: dict) -> None:
        if not self.verbose:
            return
        links = [link for link in parsed.get("links", []) if link["rel"] != "self"]
        if not links:
            return
        self.heading("Links")
        for link in links:
            self.field(title_case(link["rel"] or "link"), link["href"])

    def footer(self, parsed: dict) -> None:
        self.redacted(parsed)
        self.remarks(parsed)
        self.notices(parsed)
        self.links(parsed)
        for event in parsed.get("events", []):
            if event["action"] == self.rdap_updated_event:
                self.blank()
                date = format_date(event["date"])
                self.lines.append(f">>> Last update of RDAP database: {date} <<<")

    # Entities

    def entities(self, parsed: dict) -> None:
        """
        Parsed entities are grouped by role, display each entity once with all
        of its roles combined along with which entity they were found under.
        """
        entities = {}
        for role, role_entities in parsed.get("entities", {}).items():
            for entity in role_entities:
                key = entity.get("handle") or json.dumps(
                    {k: v for k, v in entity.items() if not k.startswith("parent_")},
                    sort_keys=True,
                    default=str,
                )
                if key not in entities:
                    entities[key] = ({}, entity)
                entities[key][0].setdefault(
                    title_case(role), entity.get("parent_name", "")
                )
        if not entities:
            return
        self.heading("Contacts")
        for i, (roles, entity) in enumerate(entities.values()):
            if i:
                self.lines.append("")
            self.entity(entity, self._format_roles(roles))

    def _format_roles(self, roles: dict) -> str:
        # Group roles by the parent entity they were found under
        by_parent = {}
        for role, parent in roles.items():
            by_parent.setdefault(parent, []).append(role)
        parts = []
        for parent, parent_roles in by_parent.items():
            joined = ", ".join(parent_roles)
            parts.append(f"{joined} ({parent})" if parent else joined)
        return " / ".join(parts)

    def entity(self, entity: dict, roles: str | None, level: int = 1) -> None:
        handle = entity.get("handle", "")
        if roles is None:
            # Top level entity query, display the handle as a field
            self.field("Handle", handle, level)
        else:
            self.subheading(f"{roles}" + (f" [{handle}]" if handle else ""), level)
            level += 1
        name = entity.get("name", "")
        self.field("Name", name, level)
        for key, label in (("person", "Person"), ("organisation", "Organisation")):
            if entity.get(key) != name:
                self.field(label, entity.get(key), level)
        if self.verbose:
            self.field("Kind", entity.get("kind"), level)
        self.field("Title", entity.get("title"), level)
        self.field("Role", entity.get("role"), level)
        self.field("Address", format_address(entity.get("address")), level)
        self.field("Email", entity.get("emails"), level)
        self.field("Phone", entity.get("phones"), level)
        self.field("Fax", entity.get("fax"), level)
        self.field("Web", entity.get("websites"), level)
        self.field("Contact", entity.get("contact_uris"), level)
        self.common(entity, level)
        for network in entity.get("networks", []):
            self.field("Network", self._network_summary(network), level)
        for autnum in entity.get("autnums", []):
            self.field("ASN", self._autnum_summary(autnum), level)
        if self.verbose:
            self.remarks(entity, level=level)

    # Object types

    def domain(self, parsed: dict) -> None:
        self.heading("Domain")
        self.field("Domain Name", parsed["name"].upper())
        unicode_name = parsed.get("unicode_name", "")
        if unicode_name and unicode_name.lower() != parsed["name"].lower():
            self.field("Unicode Name", unicode_name)
        self.field("Handle", parsed["handle"])
        self.common(parsed)
        self.field("Registrar RDAP URL", parsed.get("registrar_url"))
        self.dnssec(parsed)
        self.nameservers(parsed)
        self.entities(parsed)
        self.footer(parsed)

    def dnssec(self, parsed: dict) -> None:
        self.field("DNSSEC", "signed delegation" if parsed["dnssec"] else "unsigned")
        for ds in parsed.get("dnssec_ds_data", []):
            self.field(
                "DS Record",
                f"{ds['key_tag']} {ds['algorithm']} {ds['digest_type']} {ds['digest']}",
            )
        for key in parsed.get("dnssec_key_data", []):
            self.field(
                "DNSKEY",
                f"{key['flags']} {key['protocol']} {key['algorithm']} "
                f"{key['public_key']}",
            )

    def nameservers(self, parsed: dict) -> None:
        nameservers = parsed.get("nameservers", [])
        if not nameservers:
            return
        self.heading("Nameservers")
        width = max(len(n) for n in nameservers) + 2
        for nameserver in nameservers:
            ips = parsed.get("nameserver_ips", {}).get(nameserver, [])
            name = nameserver.rstrip(".").upper()
            self.lines.append((indent + name.ljust(width) + " ".join(ips)).rstrip())

    def ip(self, parsed: dict) -> None:
        self.heading("Network")
        self.field("Name", parsed["name"])
        self.field("Handle", parsed["handle"])
        start, end = parsed.get("start_address"), parsed.get("end_address")
        if start and end:
            self.field("Range", f"{start} - {end}")
        self.field("CIDR", [str(cidr) for cidr in parsed.get("cidrs", [])])
        self.field("Type", parsed.get("assignment_type", "").upper())
        if parsed.get("ip_version"):
            self.field("IP Version", f"IPv{parsed['ip_version']}")
        self.field("Country", parsed.get("country"))
        self.field("Parent Handle", parsed.get("parent_handle"))
        self.field("Parent RDAP URL", parsed.get("parent_url"))
        self.field("RIR", parsed.get("rir", "").upper())
        self.common(parsed)
        self.field("Origin AS", [f"AS{a}" for a in parsed.get("origin_autnums", [])])
        self.entities(parsed)
        self.footer(parsed)

    def autnum(self, parsed: dict) -> None:
        self.heading("Autonomous System")
        self.field("Name", parsed["name"])
        self.field("Handle", parsed["handle"])
        if parsed.get("asn_range"):
            start, end = parsed["asn_range"]
            if start == end:
                self.field("AS Number", f"AS{start}")
            else:
                self.field("AS Range", f"AS{start} - AS{end}")
        self.field("Type", parsed.get("assignment_type", "").upper())
        self.field("Country", parsed.get("country"))
        self.field("RIR", parsed.get("rir", "").upper())
        self.common(parsed)
        self.entities(parsed)
        self.footer(parsed)

    def entity_object(self, parsed: dict) -> None:
        self.heading("Entity")
        self.entity(parsed, None)
        self.field("Roles", [title_case(r) for r in parsed.get("roles", [])])
        self.entities(parsed)
        self.footer(parsed)

    def _network_summary(self, network: dict) -> str:
        parts = [network["handle"]]
        start, end = network["start_address"], network["end_address"]
        if start and end and network["handle"] != f"{start} - {end}":
            parts.append(f"({start} - {end})")
        parts.append(network["name"])
        return " ".join(p for p in parts if p)

    def _autnum_summary(self, autnum: dict) -> str:
        return " ".join(p for p in (autnum["handle"], autnum["name"]) if p)

    def format(self, query: str, query_type: str, parsed: dict, notes: list) -> str:
        self.comment(
            f"whoisit {whoisit.version} RDAP lookup for: {query} ({query_type})"
        )
        self.comment(f"Source: {parsed.get('url', '')}")
        for note in notes:
            self.comment(note)
        object_type = parsed.get("type", "")
        if object_type == "domain":
            self.domain(parsed)
        elif object_type == "ip network":
            self.ip(parsed)
        elif object_type == "autnum":
            self.autnum(parsed)
        else:
            self.entity_object(parsed)
        return self.text()


# Structured output formats


def json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


def scalar_to_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def simplify_vcards(data):
    """
    Recursively replace jCard "vcardArray" values with a simple "vcard" dict,
    jCard arrays are deeply nested positional lists which are near useless when
    flattened into XML elements or CSV rows.
    """
    if isinstance(data, list):
        return [simplify_vcards(v) for v in data]
    if not isinstance(data, dict):
        return data
    out = {}
    for k, v in data.items():
        if k == "vcardArray":
            out["vcard"] = parse_vcard(v) or {}
        else:
            out[k] = simplify_vcards(v)
    return out


def output_data(parsed: dict, parsed_only: bool, simplify: bool = False):
    """
    Returns the data for structured outputs, either the full RDAP response
    including any sub-query data or the whoisit parsed summary.
    """
    if parsed_only:
        data = {k: v for k, v in parsed.items() if k != "raw"}
    else:
        data = copy.deepcopy(parsed["raw"])
    return simplify_vcards(data) if simplify else data


def format_json(results: list) -> str:
    data = [data for _query, _query_type, data in results]
    # Output a single object for a single query to make piping into jq simple
    data = data[0] if len(data) == 1 else data
    return json.dumps(data, indent=2, default=json_default) + "\n"


xml_name_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def to_xml(parent: ElementTree.Element, key: str, value) -> None:
    if xml_name_re.match(key) and not key.lower().startswith("xml"):
        element = ElementTree.SubElement(parent, key)
    else:
        element = ElementTree.SubElement(parent, "field", name=key)
    if isinstance(value, dict):
        for k, v in value.items():
            to_xml(element, str(k), v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            to_xml(element, "item", v)
    else:
        element.text = scalar_to_str(value)


def format_xml(results: list) -> str:
    root = ElementTree.Element("whoisit", version=whoisit.version)
    for query, query_type, data in results:
        result = ElementTree.SubElement(root, "result", query=query, type=query_type)
        for k, v in data.items():
            to_xml(result, str(k), v)
    ElementTree.indent(root)
    xml = ElementTree.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml}\n'


def flatten_rows(value, prefix: str = ""):
    """
    Flatten nested data into (key, value) rows with dotted keys, for example
    entities.0.vcard.email
    """
    if isinstance(value, dict):
        for k, v in value.items():
            yield from flatten_rows(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from flatten_rows(v, f"{prefix}.{i}" if prefix else str(i))
    else:
        yield prefix, scalar_to_str(value)


def format_csv(results: list) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("key", "value"))
    for query, query_type, data in results:
        # Each result starts with a "query" row to permit multiple queries
        writer.writerow(("query", query))
        writer.writerow(("query_type", query_type))
        writer.writerows(flatten_rows(data))
    return out.getvalue()


structured_formatters = {
    "json": format_json,
    "xml": format_xml,
    "csv": format_csv,
}


# Entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whoisit",
        description="Look up IP addresses, networks, AS numbers, domains and "
        "entities using RDAP, the replacement for WHOIS.",
        epilog="Examples: whoisit example.com | whoisit 1.1.1.1 | "
        "whoisit 2606:4700::/32 | whoisit AS13335 | whoisit -r ripe RIPE-NCC-MNT",
    )
    parser.add_argument(
        "queries", nargs="+", metavar="query", help="the resource to look up"
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=("auto", "ip", "asn", "domain", "entity"),
        default="auto",
        help="query type, detected from the query by default",
    )
    parser.add_argument(
        "-r",
        "--rir",
        help="query a specific RIR RDAP service (afrinic, apnic, arin, lacnic, ripe)",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=("text", "json", "xml", "csv"),
        default="text",
        help="output format (default: text), json, xml and csv output the full "
        "RDAP response including sub-query data, csv is key,value rows",
    )
    parser.add_argument(
        "-p",
        "--parsed",
        action="store_true",
        help="output the whoisit parsed summary instead of the full RDAP response, "
        "implies -o json if no other structured output format is set",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="include full notice text, links and entity remarks",
    )
    parser.add_argument(
        "-n",
        "--no-follow",
        action="store_true",
        help="do not follow related registrar or entity links with sub-queries",
    )
    parser.add_argument(
        "--insecure-ssl",
        action="store_true",
        help="permit weak SSL ciphers when connecting to RDAP services",
    )
    parser.add_argument(
        "--allow-insecure-endpoints",
        action="store_true",
        help="permit RDAP services using plain HTTP",
    )
    parser.add_argument(
        "--proxy", help="proxy to use, in proto://[user:pass@]host:port format"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="do not read or write cached bootstrap data",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="force a refresh of the cached bootstrap data",
    )
    parser.add_argument(
        "--color",
        "--colour",
        dest="colour",
        choices=("auto", "always", "never"),
        default="auto",
        help="colourise output (default: auto)",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"whoisit {whoisit.version}"
    )
    return parser


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    style = Style(use_colour(args.colour, sys.stdout))
    err_style = Style(use_colour(args.colour, sys.stderr))
    if args.parsed and args.output == "text":
        args.output = "json"
    if args.proxy:
        whoisit.set_proxy(args.proxy)
    try:
        bootstrap(
            use_cache=not args.no_cache,
            refresh=args.refresh,
            allow_insecure=args.allow_insecure_endpoints,
        )
    except WhoisItError as e:
        print(err_style.error(f"whoisit: failed to bootstrap: {e}"), file=sys.stderr)
        return 2
    exit_code = 0
    results = []
    for i, query in enumerate(args.queries):
        query_type, normalised = detect_query_type(query)
        if args.type != "auto":
            query_type = args.type
            if query_type == "domain":
                normalised = normalise_domain(query)
            elif query_type == "asn":
                normalised = (
                    normalised
                    if normalised.isdigit()
                    else query.strip().upper().removeprefix("AS")
                )
            elif query_type == "entity":
                normalised = query.strip().upper()
        try:
            parsed, notes = lookup(
                query_type,
                normalised,
                rir=args.rir,
                follow=not args.no_follow,
                allow_insecure_ssl=args.insecure_ssl,
            )
        except ResourceDoesNotExist:
            print(f'No match for "{query}".', file=sys.stderr)
            exit_code = 1
            continue
        except UnsupportedError:
            print(
                err_style.error(
                    f'whoisit: no RDAP service is known for {query_type} "{query}"'
                ),
                file=sys.stderr,
            )
            exit_code = 1
            continue
        except (WhoisItError, ValueError) as e:
            print(err_style.error(f"whoisit: {query}: {e}"), file=sys.stderr)
            exit_code = 1
            continue
        if args.output == "text":
            if i:
                print()
            formatter = Formatter(style, verbose=args.verbose)
            sys.stdout.write(formatter.format(query, query_type, parsed, notes))
            sys.stdout.flush()
        else:
            # Keep stdout parseable, report any notes on stderr instead
            for note in notes:
                print(f"whoisit: {query}: {note}", file=sys.stderr)
            data = output_data(parsed, args.parsed, simplify=args.output != "json")
            results.append((query, query_type, data))
        if i < len(args.queries) - 1:
            time.sleep(0.1)  # Be gentle with RDAP services when making many queries
    if results:
        sys.stdout.write(structured_formatters[args.output](results))
    return exit_code


def run() -> None:
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # Output was piped into something that exited early, e.g. "| head"
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)


if __name__ == "__main__":
    run()
