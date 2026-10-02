from django.test import RequestFactory

from vault import services
from vault.models import AuditEvent
from vault.tests.base import VaultTestCase


class OpenedDedupeTests(VaultTestCase):
    def request(self, ua="Mozilla/5.0 Chrome", ip="203.0.113.5"):
        return RequestFactory().get("/", REMOTE_ADDR=ip, HTTP_USER_AGENT=ua)

    def test_same_client_is_collapsed_into_one_event(self):
        link = self.make_link()
        services.log_opened_once(link, self.request())
        services.log_opened_once(link, self.request())
        self.assertEqual(link.events.filter(event_type=AuditEvent.Type.OPENED).count(), 1)

    def test_different_clients_are_counted_separately(self):
        link = self.make_link()
        services.log_opened_once(link, self.request(ip="203.0.113.5"))
        services.log_opened_once(link, self.request(ip="198.51.100.9"))
        self.assertEqual(link.events.filter(event_type=AuditEvent.Type.OPENED).count(), 2)

    def test_dedupe_key_is_stable_across_processes(self):
        """The key must not depend on Python's per-process randomised hash()."""
        import hashlib
        from unittest import mock

        link = self.make_link()
        with mock.patch("vault.services.cache") as fake_cache:
            fake_cache.add.return_value = True
            services.log_opened_once(link, self.request())
        key = fake_cache.add.call_args[0][0]
        ident = f"{link.pk}|203.0.113.5|Mozilla/5.0 Chrome"
        self.assertEqual(key, "opened:" + hashlib.sha256(ident.encode()).hexdigest())
