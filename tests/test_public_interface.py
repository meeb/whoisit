import unittest
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path

import pytest
import responses
import yaml
from dateutil.tz import tzoffset
from responses import _recorder

import whoisit


BASE_DIR = Path(__file__).resolve().parent
RESPONSES = BASE_DIR / "responses"
UTC = timezone.utc


class SyncPublicInterfaceTestCase(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        whoisit.clear_bootstrapping()

    def test_version(self):
        self.assertRegex(whoisit.version, r"\d+\.\d+\.\d+")

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'boostrap.yaml')
    def test_bootstrap_interface(self):
        responses._add_from_file(RESPONSES / "boostrap.yaml")
        whoisit.bootstrap()
        self.assertTrue(whoisit.is_bootstrapped())

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'asn-1.yaml')
    def test_asn_interface_1(self):
        responses._add_from_file(RESPONSES / "asn-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.asn(13335)
        self.assertEqual(resp["type"], "autnum")
        self.assertEqual(resp["handle"], "AS13335")
        self.assertEqual(resp["name"], "CLOUDFLARENET")
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/autnum/13335")
        self.assertEqual(resp["handle"], "AS13335")
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["asn_range"], [13335, 13335])
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(resp["copyright_notice"], "Copyright 1997-2024, American Registry for Internet Numbers, Ltd.")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["registration_date"], datetime(2010, 7, 14, 18, 35, 57, tzinfo=tzoffset(None, -14400)))
        self.assertTrue(isinstance(resp["entities"]["registrant"], list))
        self.assertTrue(len(resp["entities"]["registrant"]) > 0)
        self.assertTrue(isinstance(resp["entities"]["abuse"], list))
        self.assertTrue(len(resp["entities"]["abuse"]) > 0)
        self.assertTrue(isinstance(resp["entities"]["noc"], list))
        self.assertTrue(len(resp["entities"]["noc"]) > 0)
        self.assertTrue(isinstance(resp["entities"]["technical"], list))
        self.assertTrue(len(resp["entities"]["technical"]) > 0)

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'domain-1.yaml')
    def test_domain_interface_1(self):
        responses._add_from_file(RESPONSES / "domain-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.domain("google.com")
        self.assertEqual(resp["type"], "domain")
        self.assertEqual(resp["name"], "GOOGLE.COM")
        self.assertEqual(resp["handle"], "2138514_DOMAIN_COM-VRSN")
        self.assertEqual(resp["rir"], "")
        self.assertEqual(resp["registration_date"], datetime(1997, 9, 15, 4, 0, tzinfo=UTC))
        self.assertEqual(resp["url"], "https://rdap.verisign.com/com/v1/domain/GOOGLE.COM")
        self.assertEqual(
            resp["terms_of_service_url"],
            "https://www.verisign.com/domain-names/registration-data-access-protocol/terms-service/index.xhtml",
        )
        self.assertEqual(resp["whois_server"], "")
        self.assertEqual(resp["copyright_notice"], "")
        self.assertEqual(resp["dnssec"], False)
        self.assertEqual(resp["nameservers"], ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM", "NS3.GOOGLE.COM", "NS4.GOOGLE.COM"])
        self.assertEqual(
            resp["status"],
            [
                "client delete prohibited",
                "client transfer prohibited",
                "client update prohibited",
                "server delete prohibited",
                "server transfer prohibited",
                "server update prohibited",
            ],
        )
        self.assertTrue(isinstance(resp["entities"]["registrar"], list))
        self.assertTrue(len(resp["entities"]["registrar"]) > 0)

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'ip-v4-1.yaml')
    def test_ip_interface_v4_1(self):
        responses._add_from_file(RESPONSES / "ip-v4-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.ip("1.1.1.1")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "APNIC-LABS")
        self.assertEqual(resp["handle"], "1.1.1.0 - 1.1.1.255")
        self.assertEqual(resp["network"], IPv4Network("1.1.1.0/24"))
        self.assertEqual(resp["rir"], "apnic")
        self.assertEqual(resp["registration_date"], datetime(2011, 8, 10, 23, 12, 35, tzinfo=UTC))
        self.assertEqual(resp["url"], "https://rdap.apnic.net/ip/1.1.1.0/24")
        self.assertEqual(resp["terms_of_service_url"], "http://www.apnic.net/db/dbcopyright.html")
        self.assertEqual(resp["whois_server"], "whois.apnic.net")
        self.assertEqual(resp["copyright_notice"], "")
        self.assertEqual(
            resp["description"],
            [
                "APNIC and Cloudflare DNS Resolver project",
                "Routed globally by AS13335/Cloudflare",
                "Research prefix for APNIC Labs",
            ],
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'ip-v6-1.yaml')
    def test_ip_interface_v6_1(self):
        responses._add_from_file(RESPONSES / "ip-v6-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.ip("2606:4700:4700::1111")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "CLOUDFLARENET")
        self.assertEqual(resp["handle"], "NET6-2606-4700-1")
        self.assertEqual(resp["network"], IPv6Network("2606:4700::/32"))
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["registration_date"], datetime(2011, 11, 1, 15, 59, 58, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/ip/2606:4700::")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(
            resp["description"], ["All Cloudflare abuse reporting can be done via https://www.cloudflare.com/abuse"]
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'ip-v4-cidr-1.yaml')
    def test_ip_interface_v4_cidr_1(self):
        responses._add_from_file(RESPONSES / "ip-v4-cidr-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.ip("1.1.1.0/24")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "APNIC-LABS")
        self.assertEqual(resp["handle"], "1.1.1.0 - 1.1.1.255")
        self.assertEqual(resp["rir"], "apnic")
        self.assertEqual(resp["registration_date"], datetime(2011, 8, 10, 23, 12, 35, tzinfo=UTC))
        self.assertEqual(resp["url"], "https://rdap.apnic.net/ip/1.1.1.0/24")
        self.assertEqual(resp["terms_of_service_url"], "http://www.apnic.net/db/dbcopyright.html")
        self.assertEqual(resp["whois_server"], "whois.apnic.net")
        self.assertEqual(resp["copyright_notice"], "")
        self.assertEqual(resp["assignment_type"], "assigned portable")
        self.assertEqual(resp["country"], "AU")
        self.assertEqual(resp["ip_version"], 4)
        self.assertEqual(resp["network"], IPv4Network("1.1.1.0/24"))
        self.assertEqual(
            resp["description"],
            [
                "APNIC and Cloudflare DNS Resolver project",
                "Routed globally by AS13335/Cloudflare",
                "Research prefix for APNIC Labs",
            ],
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'ip-v6-cidr-1.yaml')
    def test_ip_interface_v6_cidr_1(self):
        responses._add_from_file(RESPONSES / "ip-v6-cidr-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.ip("2606:4700::/32")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "CLOUDFLARENET")
        self.assertEqual(resp["handle"], "NET6-2606-4700-1")
        self.assertEqual(resp["network"], IPv6Network("2606:4700::/32"))
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["registration_date"], datetime(2011, 11, 1, 15, 59, 58, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/ip/2606:4700::")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(
            resp["description"], ["All Cloudflare abuse reporting can be done via https://www.cloudflare.com/abuse"]
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @responses.activate
    # @_recorder.record(file_path=RESPONSES / 'entity-1.yaml')
    def test_entity_interface_1(self):
        responses._add_from_file(RESPONSES / "entity-1.yaml")
        whoisit.bootstrap()
        resp = whoisit.entity("GOVI", rir="arin")
        self.assertEqual(resp["type"], "entity")
        self.assertEqual(resp["name"], "Govital Internet Inc.")
        self.assertEqual(resp["handle"], "GOVI")
        self.assertEqual(resp["parent_handle"], "")
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["registration_date"], datetime(2001, 5, 8, 0, 0, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(resp["expiration_date"], None)
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/entity/GOVI")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(
            resp["description"], ["http://www.govital.net\r", "Standard NOC hours are 10am to 6pm EST M-F"]
        )
        self.assertTrue(isinstance(resp["entities"]["technical"], list))
        self.assertTrue(len(resp["entities"]["technical"]) > 0)


#############################################
################### Async ###################
#############################################


def load_sync_responses_to_httpx_mock(file, httpx_mock):
    with open(file) as fh:
        data = yaml.safe_load(fh)

    for item in data["responses"]:
        response = item["response"]
        httpx_mock.add_response(
            url=response["url"],
            method=response["method"],
            status_code=response["status"],
            text=response["body"],
            headers=response["headers"],
        )


@pytest.fixture(scope="function")
def mock_httpx(request, httpx_mock):
    request.cls.httpx_mock = httpx_mock


class AsyncPublicInterfaceTestCase(unittest.IsolatedAsyncioTestCase):
    maxDiff = None

    def setUp(self):
        whoisit.clear_bootstrapping()

    def test_version(self):
        self.assertRegex(whoisit.version, r"\d+\.\d+\.\d+")

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_bootstrap_interface(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "boostrap.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        self.assertTrue(whoisit.is_bootstrapped())

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_asn_interface_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "asn-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.asn_async(13335)
        self.assertEqual(resp["type"], "autnum")
        self.assertEqual(resp["handle"], "AS13335")
        self.assertEqual(resp["name"], "CLOUDFLARENET")
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/autnum/13335")
        self.assertEqual(resp["handle"], "AS13335")
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["asn_range"], [13335, 13335])
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(resp["copyright_notice"], "Copyright 1997-2024, American Registry for Internet Numbers, Ltd.")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["registration_date"], datetime(2010, 7, 14, 18, 35, 57, tzinfo=tzoffset(None, -14400)))
        self.assertTrue(isinstance(resp["entities"]["registrant"], list))
        self.assertTrue(len(resp["entities"]["registrant"]) > 0)
        self.assertTrue(isinstance(resp["entities"]["abuse"], list))
        self.assertTrue(len(resp["entities"]["abuse"]) > 0)
        self.assertTrue(isinstance(resp["entities"]["noc"], list))
        self.assertTrue(len(resp["entities"]["noc"]) > 0)
        self.assertTrue(isinstance(resp["entities"]["technical"], list))
        self.assertTrue(len(resp["entities"]["technical"]) > 0)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_domain_interface_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "domain-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.domain_async("google.com")
        self.assertEqual(resp["type"], "domain")
        self.assertEqual(resp["name"], "GOOGLE.COM")
        self.assertEqual(resp["handle"], "2138514_DOMAIN_COM-VRSN")
        self.assertEqual(resp["rir"], "")
        self.assertEqual(resp["registration_date"], datetime(1997, 9, 15, 4, 0, tzinfo=UTC))
        self.assertEqual(resp["url"], "https://rdap.verisign.com/com/v1/domain/GOOGLE.COM")
        self.assertEqual(
            resp["terms_of_service_url"],
            "https://www.verisign.com/domain-names/registration-data-access-protocol/terms-service/index.xhtml",
        )
        self.assertEqual(resp["whois_server"], "")
        self.assertEqual(resp["copyright_notice"], "")
        self.assertEqual(resp["dnssec"], False)
        self.assertEqual(resp["nameservers"], ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM", "NS3.GOOGLE.COM", "NS4.GOOGLE.COM"])
        self.assertEqual(
            resp["status"],
            [
                "client delete prohibited",
                "client transfer prohibited",
                "client update prohibited",
                "server delete prohibited",
                "server transfer prohibited",
                "server update prohibited",
            ],
        )
        self.assertTrue(isinstance(resp["entities"]["registrar"], list))
        self.assertTrue(len(resp["entities"]["registrar"]) > 0)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_ip_interface_v4_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "ip-v4-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.ip_async("1.1.1.1")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "APNIC-LABS")
        self.assertEqual(resp["handle"], "1.1.1.0 - 1.1.1.255")
        self.assertEqual(resp["network"], IPv4Network("1.1.1.0/24"))
        self.assertEqual(resp["rir"], "apnic")
        self.assertEqual(resp["registration_date"], datetime(2011, 8, 10, 23, 12, 35, tzinfo=UTC))
        self.assertEqual(resp["url"], "https://rdap.apnic.net/ip/1.1.1.0/24")
        self.assertEqual(resp["terms_of_service_url"], "http://www.apnic.net/db/dbcopyright.html")
        self.assertEqual(resp["whois_server"], "whois.apnic.net")
        self.assertEqual(resp["copyright_notice"], "")
        self.assertEqual(
            resp["description"],
            [
                "APNIC and Cloudflare DNS Resolver project",
                "Routed globally by AS13335/Cloudflare",
                "Research prefix for APNIC Labs",
            ],
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_ip_interface_v6_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "ip-v6-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.ip_async("2606:4700:4700::1111")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "CLOUDFLARENET")
        self.assertEqual(resp["handle"], "NET6-2606-4700-1")
        self.assertEqual(resp["network"], IPv6Network("2606:4700::/32"))
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["registration_date"], datetime(2011, 11, 1, 15, 59, 58, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/ip/2606:4700::")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(
            resp["description"], ["All Cloudflare abuse reporting can be done via https://www.cloudflare.com/abuse"]
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_ip_interface_v4_cidr_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "ip-v4-cidr-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.ip_async("1.1.1.0/24")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "APNIC-LABS")
        self.assertEqual(resp["handle"], "1.1.1.0 - 1.1.1.255")
        self.assertEqual(resp["rir"], "apnic")
        self.assertEqual(resp["registration_date"], datetime(2011, 8, 10, 23, 12, 35, tzinfo=UTC))
        self.assertEqual(resp["url"], "https://rdap.apnic.net/ip/1.1.1.0/24")
        self.assertEqual(resp["terms_of_service_url"], "http://www.apnic.net/db/dbcopyright.html")
        self.assertEqual(resp["whois_server"], "whois.apnic.net")
        self.assertEqual(resp["copyright_notice"], "")
        self.assertEqual(resp["assignment_type"], "assigned portable")
        self.assertEqual(resp["country"], "AU")
        self.assertEqual(resp["ip_version"], 4)
        self.assertEqual(resp["network"], IPv4Network("1.1.1.0/24"))
        self.assertEqual(
            resp["description"],
            [
                "APNIC and Cloudflare DNS Resolver project",
                "Routed globally by AS13335/Cloudflare",
                "Research prefix for APNIC Labs",
            ],
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_ip_interface_v6_cidr_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "ip-v6-cidr-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.ip_async("2606:4700::/32")
        self.assertEqual(resp["type"], "ip network")
        self.assertEqual(resp["name"], "CLOUDFLARENET")
        self.assertEqual(resp["handle"], "NET6-2606-4700-1")
        self.assertEqual(resp["network"], IPv6Network("2606:4700::/32"))
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["registration_date"], datetime(2011, 11, 1, 15, 59, 58, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/ip/2606:4700::")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(
            resp["description"], ["All Cloudflare abuse reporting can be done via https://www.cloudflare.com/abuse"]
        )
        self.assertTrue(isinstance(resp["entities"]["administrative"], list))
        self.assertTrue(len(resp["entities"]["administrative"]) > 0)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("mock_httpx")
    async def test_entity_interface_1(self):
        load_sync_responses_to_httpx_mock(RESPONSES / "entity-1.yaml", self.httpx_mock)
        await whoisit.bootstrap_async()
        resp = await whoisit.entity_async("GOVI", rir="arin")
        self.assertEqual(resp["type"], "entity")
        self.assertEqual(resp["name"], "Govital Internet Inc.")
        self.assertEqual(resp["handle"], "GOVI")
        self.assertEqual(resp["parent_handle"], "")
        self.assertEqual(resp["rir"], "arin")
        self.assertEqual(resp["registration_date"], datetime(2001, 5, 8, 0, 0, tzinfo=tzoffset(None, -14400)))
        self.assertEqual(resp["expiration_date"], None)
        self.assertEqual(resp["url"], "https://rdap.arin.net/registry/entity/GOVI")
        self.assertEqual(resp["terms_of_service_url"], "https://www.arin.net/resources/registry/whois/tou/")
        self.assertEqual(resp["whois_server"], "whois.arin.net")
        self.assertEqual(
            resp["description"], ["http://www.govital.net\r", "Standard NOC hours are 10am to 6pm EST M-F"]
        )
        self.assertTrue(isinstance(resp["entities"]["technical"], list))
        self.assertTrue(len(resp["entities"]["technical"]) > 0)
