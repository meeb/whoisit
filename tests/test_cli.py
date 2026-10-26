import csv
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree

import whoisit
from whoisit import cli

BASE_DIR = Path(__file__).resolve().parent


def load_parsed(filename, data_type, query):
    with open(BASE_DIR / filename) as f:
        raw = json.loads(f.read())
    return whoisit.parser.parse(whoisit._bootstrap, data_type, query, raw, True)


class CLITestCase(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        whoisit.clear_bootstrapping()
        with open(BASE_DIR / "data_bootstrap.json", "rt") as f:
            whoisit.load_bootstrap_data(f.read())

    def format(self, filename, data_type, query, verbose=False):
        parsed = load_parsed(filename, data_type, query)
        formatter = cli.Formatter(cli.Style(False), verbose=verbose)
        return formatter.format(query, data_type, parsed, [])

    def test_detect_query_type(self):
        self.assertEqual(cli.detect_query_type("1.1.1.1"), ("ip", "1.1.1.1"))
        self.assertEqual(cli.detect_query_type("1.1.1.0/24"), ("ip", "1.1.1.0/24"))
        self.assertEqual(cli.detect_query_type("2606:4700::"), ("ip", "2606:4700::"))
        self.assertEqual(
            cli.detect_query_type("2606:4700::/32"), ("ip", "2606:4700::/32")
        )
        self.assertEqual(cli.detect_query_type("AS13335"), ("asn", "13335"))
        self.assertEqual(cli.detect_query_type("as13335"), ("asn", "13335"))
        self.assertEqual(cli.detect_query_type("13335"), ("asn", "13335"))
        self.assertEqual(
            cli.detect_query_type("Example.COM."), ("domain", "example.com")
        )
        self.assertEqual(
            cli.detect_query_type("bücher.de"), ("domain", "xn--bcher-kva.de")
        )
        self.assertEqual(
            cli.detect_query_type("ripe-ncc-mnt"), ("entity", "RIPE-NCC-MNT")
        )

    def test_format_date(self):
        tz = timezone(timedelta(hours=2))
        self.assertEqual(
            cli.format_date(datetime(2021, 1, 1, 12, 0, 0, tzinfo=tz)),
            "2021-01-01 10:00:00 UTC",
        )
        self.assertEqual(
            cli.format_date(datetime(2021, 1, 1, 12, 0, 0)), "2021-01-01 12:00:00"
        )
        self.assertEqual(cli.format_date(None), "")

    def test_format_address(self):
        self.assertEqual(cli.format_address(None), "")
        self.assertEqual(
            cli.format_address(
                {"street_address": "1 Street", "country": "", "label": ""}
            ),
            "1 Street",
        )
        self.assertEqual(
            cli.format_address({"street_address": "1 Street", "label": "A\nB"}),
            "A\nB",
        )

    def test_format_domain(self):
        out = self.format("data_rdap_response_domain1.json", "domain", "google.com")
        self.assertIn("Domain Name:", out)
        self.assertIn("GOOGLE.COM", out)
        self.assertIn("Nameservers", out)
        self.assertIn("NS1.GOOGLE.COM", out)
        self.assertIn("Registrar", out)
        self.assertIn("MarkMonitor Inc.", out)
        self.assertIn("Registered:", out)
        self.assertIn("1997-09-15 04:00:00 UTC", out)
        self.assertIn("DNSSEC:", out)

    def test_format_ip(self):
        out = self.format("data_rdap_response_ip_v4.json", "ip", "1.1.1.1")
        self.assertIn("Network", out)
        self.assertIn("APNIC-LABS", out)
        self.assertIn("1.1.1.0 - 1.1.1.255", out)
        self.assertIn("1.1.1.0/24", out)
        self.assertIn("Country:", out)
        self.assertIn("Abuse", out)
        self.assertIn("Routed globally by AS13335/Cloudflare", out)

    def test_format_asn(self):
        out = self.format("data_rdap_response_asn.json", "autnum", "13335")
        self.assertIn("Autonomous System", out)
        self.assertIn("CLOUDFLARENET", out)
        self.assertIn("AS13335", out)
        self.assertIn("RIR:", out)
        self.assertIn("ARIN", out)

    def test_format_entity(self):
        out = self.format("data_rdap_response_entity.json", "entity", "AS-RIPENCC")
        self.assertIn("Entity", out)
        self.assertIn("Handle:", out)

    def test_entities_are_merged_by_handle(self):
        raw = {
            "objectClassName": "autnum",
            "handle": "AS1",
            "entities": [
                {"handle": "A-1", "roles": ["technical"]},
                {
                    "handle": "B-1",
                    "roles": ["registrant"],
                    "entities": [{"handle": "A-1", "roles": ["technical", "abuse"]}],
                },
            ],
        }
        parsed = whoisit.parser.parse(whoisit._bootstrap, "autnum", "1", raw)
        formatter = cli.Formatter(cli.Style(False))
        formatter.entities(parsed)
        out = "\n".join(formatter.lines)
        self.assertEqual(out.count("[A-1]"), 1)
        self.assertIn("Technical / Abuse (B-1) [A-1]", out)

    def test_format_entity_contact_fields(self):
        parsed = load_parsed("data_rdap_response_ip_v4.json", "ip", "1.1.1.1")
        formatter = cli.Formatter(cli.Style(False))
        formatter.entities(parsed)
        out = "\n".join(formatter.lines)
        # AR302-AP has a voice and a fax number
        self.assertIn("Phone:                +61-7-3858-3188", out)
        self.assertIn("Fax:                  +61-7-3858-3199", out)

    def test_follow_entities(self):
        raw = {
            "entities": [
                {
                    "handle": "TEST-1",
                    "roles": ["abuse"],
                    "links": [{"rel": "self", "href": "https://example.com/e/TEST-1"}],
                },
                {"handle": "TEST-2", "vcardArray": ["vcard", []]},
            ]
        }
        fetched = {
            "handle": "TEST-1",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Test"]]],
        }
        with mock.patch.object(cli.Query, "request", return_value=fetched) as req:
            updated, notes = cli.follow_entities(raw)
        self.assertEqual(req.call_count, 1)
        self.assertEqual(updated, 1)
        self.assertEqual(notes, [])
        self.assertEqual(raw["entities"][0]["vcardArray"], fetched["vcardArray"])
        # Roles are retained from the parent object's point of view
        self.assertEqual(raw["entities"][0]["roles"], ["abuse"])

    def test_lookup_reparses_followed_entities(self):
        with open(BASE_DIR / "data_rdap_response_asn.json") as f:
            raw = json.loads(f.read())
        parsed = whoisit.parser.parse(whoisit._bootstrap, "autnum", "13335", raw, True)
        fetched = {
            "handle": "CLOUD14",
            "vcardArray": ["vcard", [["fn", {}, "text", "Followed Name"]]],
        }
        del raw["entities"][0]["vcardArray"]
        with (
            mock.patch.object(whoisit, "asn", return_value=parsed),
            mock.patch.object(cli.Query, "request", return_value=fetched),
        ):
            result, _notes = cli.lookup("asn", "13335")
        names = [e.get("name") for e in result["entities"]["registrant"]]
        self.assertIn("Followed Name", names)

    def test_main(self):
        parsed = load_parsed("data_rdap_response_ip_v4.json", "ip", "1.1.1.1")
        with (
            mock.patch.object(cli, "bootstrap"),
            mock.patch.object(cli, "lookup", return_value=(parsed, [])) as lookup,
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(cli.main(["--color", "never", "1.1.1.1"]), 0)
            lookup.assert_called_once_with(
                "ip", "1.1.1.1", rir=None, follow=True, allow_insecure_ssl=False
            )
            self.assertIn("APNIC-LABS", stdout.getvalue())
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(cli.main(["-o", "json", "1.1.1.1"]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["name"], "APNIC-LABS")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(cli.main(["-o", "json", "1.1.1.1", "1.1.1.1"]), 0)
            self.assertEqual(len(json.loads(stdout.getvalue())), 2)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(cli.main(["--parsed", "1.1.1.1"]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["rir"], "apnic")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(cli.main(["-o", "xml", "1.1.1.1"]), 0)
            root = ElementTree.fromstring(stdout.getvalue().split("\n", 1)[1])
            self.assertEqual(root.tag, "whoisit")
            result = root.find("result")
            self.assertEqual(result.get("query"), "1.1.1.1")
            self.assertEqual(result.findtext("name"), "APNIC-LABS")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(cli.main(["-o", "csv", "1.1.1.1"]), 0)
            rows = list(csv.reader(io.StringIO(stdout.getvalue())))
            self.assertEqual(rows[0], ["key", "value"])
            self.assertTrue(all(len(row) == 2 for row in rows))
            self.assertIn(["query", "1.1.1.1"], rows)
            self.assertIn(["name", "APNIC-LABS"], rows)

    def test_flatten_rows(self):
        data = {"a": {"b": [1, None]}, "c": True, "d": "x"}
        self.assertEqual(
            list(cli.flatten_rows(data)),
            [("a.b.0", "1"), ("a.b.1", ""), ("c", "true"), ("d", "x")],
        )

    def test_simplify_vcards(self):
        data = {
            "entities": [
                {
                    "handle": "A-1",
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Test"],
                            ["email", {}, "text", "a@example.com"],
                            ["email", {}, "text", "b@example.com"],
                        ],
                    ],
                }
            ]
        }
        self.assertEqual(
            cli.simplify_vcards(data),
            {
                "entities": [
                    {
                        "handle": "A-1",
                        "vcard": whoisit.parser.parse_vcard(
                            data["entities"][0]["vcardArray"]
                        ),
                    }
                ]
            },
        )

    def test_xml_invalid_names(self):
        root = ElementTree.Element("root")
        cli.to_xml(root, "1bad name", "x")
        self.assertEqual(root.find("field").get("name"), "1bad name")
        self.assertEqual(root.find("field").text, "x")

    def test_main_not_found(self):
        error = whoisit.errors.ResourceDoesNotExist("not found")
        with (
            mock.patch.object(cli, "bootstrap"),
            mock.patch.object(cli, "lookup", side_effect=error),
        ):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(cli.main(["nothing.com"]), 1)
            self.assertIn('No match for "nothing.com"', stderr.getvalue())

    def test_style_links(self):
        style = cli.Style(True)
        self.assertEqual(
            style.links("see https://example.com/a for info"),
            "see \033[4;34mhttps://example.com/a\033[0m for info",
        )
        self.assertEqual(
            style.links("mailto:a@example.com"), "\033[4;34mmailto:a@example.com\033[0m"
        )
        self.assertEqual(
            cli.Style(False).links("https://example.com/"), "https://example.com/"
        )
