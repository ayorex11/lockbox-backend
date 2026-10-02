from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from core.utils import get_client_ip, rate_limit_ident, truncate_ip


def request_with(**meta):
    return RequestFactory().get("/", **meta)


@override_settings(CLIENT_IP_HEADER="", TRUSTED_PROXY_COUNT=0)
class SocketOnlyTests(SimpleTestCase):
    def test_uses_remote_addr_and_ignores_forwarding_headers(self):
        request = request_with(
            REMOTE_ADDR="10.1.2.3", HTTP_X_FORWARDED_FOR="9.9.9.9", HTTP_CF_CONNECTING_IP="8.8.8.8"
        )
        self.assertEqual(get_client_ip(request), "10.1.2.3")


@override_settings(CLIENT_IP_HEADER="", TRUSTED_PROXY_COUNT=1)
class ForwardedForTests(SimpleTestCase):
    def test_trusts_only_the_right_most_n_entries(self):
        request = request_with(REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="6.6.6.6, 203.0.113.9")
        self.assertEqual(get_client_ip(request), "203.0.113.9")

    @override_settings(TRUSTED_PROXY_COUNT=2)
    def test_render_chain_with_two_hops_resolves_the_client(self):
        # Render appends: "<client>, <cloudflare edge>"; count=2 reaches the client.
        request = request_with(REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="198.51.100.7, 172.70.1.1")
        self.assertEqual(get_client_ip(request), "198.51.100.7")


@override_settings(CLIENT_IP_HEADER="CF-Connecting-IP", TRUSTED_PROXY_COUNT=1)
class ClientIpHeaderTests(SimpleTestCase):
    def test_header_wins_over_forwarded_for(self):
        request = request_with(
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_FORWARDED_FOR="198.51.100.7, 172.70.1.1",
            HTTP_CF_CONNECTING_IP="198.51.100.7",
        )
        self.assertEqual(get_client_ip(request), "198.51.100.7")

    def test_garbage_header_falls_back(self):
        request = request_with(
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_FORWARDED_FOR="198.51.100.7, 172.70.1.1",
            HTTP_CF_CONNECTING_IP="not-an-ip",
        )
        self.assertEqual(get_client_ip(request), "172.70.1.1")

    def test_missing_header_falls_back(self):
        request = request_with(REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="1.1.1.1, 2.2.2.2")
        self.assertEqual(get_client_ip(request), "2.2.2.2")

    @override_settings(CLIENT_IP_HEADER="")
    def test_header_is_ignored_when_not_configured(self):
        request = request_with(REMOTE_ADDR="10.0.0.1", HTTP_CF_CONNECTING_IP="8.8.8.8")
        self.assertNotEqual(get_client_ip(request), "8.8.8.8")


class RateLimitIdentTests(SimpleTestCase):
    def test_ipv4_is_unchanged(self):
        self.assertEqual(rate_limit_ident("203.0.113.5"), "203.0.113.5")

    def test_ipv6_addresses_in_one_slash_64_share_a_bucket(self):
        a = rate_limit_ident("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
        b = rate_limit_ident("2001:db8:1:2:1111:2222:3333:4444")
        c = rate_limit_ident("2001:db8:1:3::1")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_garbage_never_crashes(self):
        self.assertEqual(rate_limit_ident(""), "unknown")
        self.assertEqual(truncate_ip("junk"), "")


class WhoAmITests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def get(self, secret=None, **extra):
        headers = {"HTTP_X_CLEANUP_SECRET": secret} if secret is not None else {}
        return self.client.get("/internal/whoami/", **headers, **extra)

    def test_hidden_without_the_secret(self):
        self.assertEqual(self.get().status_code, 404)
        self.assertEqual(self.get("wrong").status_code, 404)

    @override_settings(CLIENT_IP_HEADER="CF-Connecting-IP")
    def test_reports_what_the_app_sees(self):
        response = self.get(
            "test-cleanup-secret",
            REMOTE_ADDR="10.1.1.1",
            HTTP_X_FORWARDED_FOR="198.51.100.7, 172.70.1.1",
            HTTP_CF_CONNECTING_IP="198.51.100.7",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["resolved_ip"], "198.51.100.7")
        self.assertEqual(body["stored_in_audit_log_as"], "198.51.100.0/24")
        self.assertEqual(body["remote_addr"], "10.1.1.1")
        self.assertEqual(body["client_ip_header_setting"], "CF-Connecting-IP")
