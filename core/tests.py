from django.test import RequestFactory, SimpleTestCase, override_settings

from core.utils import get_client_ip, truncate_ip


class ClientIPTests(SimpleTestCase):
    def request(self, xff=None, remote="10.0.0.1"):
        extra = {"REMOTE_ADDR": remote}
        if xff:
            extra["HTTP_X_FORWARDED_FOR"] = xff
        return RequestFactory().get("/", **extra)

    @override_settings(TRUSTED_PROXY_COUNT=0)
    def test_ignores_forwarded_header_without_trusted_proxies(self):
        self.assertEqual(get_client_ip(self.request("1.1.1.1")), "10.0.0.1")

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_uses_rightmost_entry_and_ignores_spoofed_prefix(self):
        self.assertEqual(get_client_ip(self.request("6.6.6.6, 203.0.113.5")), "203.0.113.5")

    @override_settings(TRUSTED_PROXY_COUNT=2)
    def test_two_proxies(self):
        self.assertEqual(get_client_ip(self.request("6.6.6.6, 203.0.113.5, 172.16.0.1")), "203.0.113.5")

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_falls_back_to_remote_when_header_missing_or_garbage(self):
        self.assertEqual(get_client_ip(self.request()), "10.0.0.1")
        self.assertEqual(get_client_ip(self.request("not-an-ip")), "10.0.0.1")


class TruncateTests(SimpleTestCase):
    def test_ipv4_to_slash_24(self):
        self.assertEqual(truncate_ip("198.51.100.77"), "198.51.100.0/24")

    def test_ipv6_to_slash_48(self):
        self.assertEqual(truncate_ip("2001:db8:abcd:1234::1"), "2001:db8:abcd::/48")

    def test_garbage_returns_empty(self):
        self.assertEqual(truncate_ip("nope"), "")
