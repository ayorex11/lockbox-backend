import threading
from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.db import connection
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from vault.models import AuditEvent, File, ShareLink

from .base import VaultTestCase, VaultTransactionTestCase


class MetaTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def meta(self, link):
        return self.client.get(f"/api/s/{link.pk}/")

    def test_active_link_returns_metadata_with_sender_email_by_default(self):
        link = self.make_link(password="hunter22", mode="one_time")
        response = self.meta(link)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["name"], "tax.pdf")
        self.assertEqual(body["mode"], "one_time")
        self.assertTrue(body["requires_password"])
        self.assertEqual(body["sender_email"], "sender@example.com")
        self.assertNotIn("password_hash", body)

    def test_sender_can_hide_their_email(self):
        link = self.make_link(show_sender_email=False)
        self.assertIsNone(self.meta(link).json()["sender_email"])

    def test_meta_never_consumes_a_one_time_link(self):
        link = self.make_link(mode="one_time")
        for _ in range(5):
            self.assertEqual(self.meta(link).status_code, 200)
        link.refresh_from_db()
        self.assertIsNone(link.consumed_at)
        self.assertEqual(link.download_count, 0)

    def test_dead_links_leak_no_metadata(self):
        now = timezone.now()
        cases = {
            "expired": self.make_link(expires_at=now - timedelta(minutes=1)),
            "unavailable-revoked": self.make_link(revoked_at=now),
            "unavailable-used": self.make_link(mode="one_time", consumed_at=now),
            "unavailable-capped": self.make_link(max_downloads=1, download_count=1),
        }
        for label, link in cases.items():
            response = self.meta(link)
            self.assertEqual(response.status_code, 410, label)
            self.assertEqual(
                response.json(),
                {"available": False, "reason": label.split("-")[0]},
                label,
            )
            self.assertNotIn("tax.pdf", response.content.decode())
            self.assertNotIn("sender@", response.content.decode())

    def test_unknown_token_is_indistinguishable_from_revoked(self):
        revoked = self.make_link(revoked_at=timezone.now())
        a = self.client.get(f"/api/s/{revoked.pk}/")
        b = self.client.get("/api/s/doesnotexist1234567890/")
        self.assertEqual((a.status_code, a.json()), (b.status_code, b.json()))

    def test_repeated_views_collapse_into_one_opened_event(self):
        link = self.make_link()
        for _ in range(3):
            self.meta(link)
        self.assertEqual(link.events.filter(event_type=AuditEvent.Type.OPENED).count(), 1)

    def test_audit_event_stores_truncated_ip(self):
        link = self.make_link()
        self.client.get(f"/api/s/{link.pk}/", REMOTE_ADDR="198.51.100.77", HTTP_USER_AGENT="X" * 500)
        event = link.events.get(event_type=AuditEvent.Type.OPENED)
        self.assertEqual(event.ip_truncated, "198.51.100.0/24")
        self.assertEqual(len(event.user_agent), 200)

    def test_sender_can_see_opened_event_but_not_full_ip(self):
        link = self.make_link()
        self.client.get(f"/api/s/{link.pk}/", REMOTE_ADDR="203.0.113.9")
        events = self.auth_client(link.file.owner).get(f"/api/links/{link.pk}/events/").json()
        self.assertNotIn("203.0.113.9", str(events))


class ClaimTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def claim(self, link, password=None):
        body = {"password": password} if password is not None else {}
        return self.client.post(f"/api/s/{link.pk}/claim/", body, format="json")

    # -- timed -------------------------------------------------------------------
    def test_timed_claim_returns_short_lived_presigned_url(self):
        link = self.make_link()
        response = self.claim(link)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn(link.file.storage_key or f"files/{link.file_id}", body["download_url"])
        self.assertEqual(body["expires_in"], settings.CLAIM_URL_TTL_SECONDS)
        link.refresh_from_db()
        self.assertEqual(link.download_count, 1)
        self.assertTrue(link.events.filter(event_type=AuditEvent.Type.CLAIMED).exists())

    def test_timed_link_without_cap_allows_repeat_claims(self):
        link = self.make_link()
        for _ in range(3):
            self.assertEqual(self.claim(link).status_code, 200)

    def test_max_downloads_enforced(self):
        link = self.make_link(max_downloads=2)
        self.assertEqual([self.claim(link).status_code for _ in range(3)], [200, 200, 410])
        self.assertEqual(self.client.get(f"/api/s/{link.pk}/").json()["reason"], "unavailable")

    def test_expired_link_cannot_be_claimed(self):
        link = self.make_link(expires_at=timezone.now() - timedelta(seconds=1))
        response = self.claim(link)
        self.assertEqual((response.status_code, response.json()["reason"]), (410, "expired"))

    # -- one time ----------------------------------------------------------------
    def test_one_time_link_works_exactly_once(self):
        link = self.make_link(mode="one_time")
        self.assertEqual(self.claim(link).status_code, 200)
        second = self.claim(link)
        self.assertEqual((second.status_code, second.json()["reason"]), (410, "unavailable"))
        link.refresh_from_db()
        self.assertEqual(link.compute_status().value, "used")
        self.assertIsNotNone(link.consumed_at)

    def test_one_time_link_deleted_after_grace_delay(self):
        link = self.make_link(mode="one_time")
        with self.settings(ONE_TIME_DELETE_DELAY_SECONDS=90), mock.patch(
            "vault.services.threading.Timer"
        ) as timer:
            self.claim(link)
        timer.assert_called_once()
        self.assertEqual(timer.call_args.args[0], 90)
        timer.return_value.start.assert_called_once()
        # Object must still exist right after the claim so the download can finish.
        self.assertIn(f"files/{link.file_id}", self.storage.objects)

    def test_expired_one_time_link_cannot_be_claimed(self):
        link = self.make_link(mode="one_time", expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.claim(link).status_code, 410)
        link.refresh_from_db()
        self.assertIsNone(link.consumed_at)

    def test_revoked_link_cannot_be_claimed(self):
        link = self.make_link(revoked_at=timezone.now())
        self.assertEqual(self.claim(link).status_code, 410)

    # -- passwords ---------------------------------------------------------------
    def test_password_required_and_correct_password_works(self):
        link = self.make_link(password="opensesame")
        no_pw = self.claim(link)
        self.assertEqual((no_pw.status_code, no_pw.json()["detail"]), (401, "password_required"))
        self.assertEqual(self.claim(link, "opensesame").status_code, 200)

    def test_wrong_password_never_burns_a_one_time_link(self):
        link = self.make_link(mode="one_time", password="opensesame")
        for _ in range(settings.LINK_PASSWORD_MAX_ATTEMPTS - 1):
            self.assertEqual(self.claim(link, "nope-nope").status_code, 401)
        link.refresh_from_db()
        self.assertIsNone(link.consumed_at)
        self.assertEqual(link.download_count, 0)
        self.assertEqual(self.claim(link, "opensesame").status_code, 200)

    def test_attempts_left_counts_down_then_locks(self):
        link = self.make_link(password="opensesame")
        limit = settings.LINK_PASSWORD_MAX_ATTEMPTS
        for i in range(limit - 1):
            response = self.claim(link, "wrong-pass")
            self.assertEqual(response.json()["attempts_left"], limit - 1 - i)
        locked = self.claim(link, "wrong-pass")
        self.assertEqual(locked.status_code, 423)
        self.assertGreater(locked.json()["retry_after"], 0)
        # correct password is refused while locked
        self.assertEqual(self.claim(link, "opensesame").status_code, 423)
        types = set(link.events.values_list("event_type", flat=True))
        self.assertTrue({"password_failed", "locked_out"} <= types)

    def test_lock_expires(self):
        link = self.make_link(password="opensesame")
        link.locked_until = timezone.now() - timedelta(seconds=1)
        link.save()
        self.assertEqual(self.claim(link, "opensesame").status_code, 200)

    def test_successful_password_resets_failed_attempts(self):
        link = self.make_link(password="opensesame")
        self.claim(link, "wrong-pass")
        self.claim(link, "opensesame")
        link.refresh_from_db()
        self.assertEqual(link.failed_attempts, 0)

    def test_non_string_password_rejected(self):
        link = self.make_link(password="opensesame")
        response = self.client.post(f"/api/s/{link.pk}/claim/", {"password": {"a": 1}}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_gone_takes_priority_over_password_prompt(self):
        link = self.make_link(password="opensesame", revoked_at=timezone.now())
        self.assertEqual(self.claim(link).status_code, 410)

    # -- throttling ---------------------------------------------------------------
    def test_per_token_claim_throttle(self):
        link = self.make_link()
        with mock.patch.dict(SimpleRateThrottle.THROTTLE_RATES, {"claim_token": "2/min"}):
            codes = [self.claim(link).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    def test_ip_throttle_uses_trusted_proxy_ip_not_spoofed_header(self):
        link = self.make_link()
        with mock.patch.dict(SimpleRateThrottle.THROTTLE_RATES, {"claim": "2/min"}), self.settings(
            TRUSTED_PROXY_COUNT=1
        ):
            codes = [
                self.client.post(
                    f"/api/s/{link.pk}/claim/",
                    {},
                    format="json",
                    HTTP_X_FORWARDED_FOR=f"1.2.3.{i}, 9.9.9.9",  # attacker rotates leftmost value
                ).status_code
                for i in range(3)
            ]
        self.assertEqual(codes, [200, 200, 429])


class ConcurrencyTests(VaultTransactionTestCase):
    """The headline guarantee: N simultaneous claims, exactly one winner."""

    def run_parallel_claims(self, link, n=20, password=None):
        results, barrier = [], threading.Barrier(n)

        def worker():
            try:
                client = APIClient()
                barrier.wait(timeout=10)
                body = {"password": password} if password else {}
                results.append(client.post(f"/api/s/{link.pk}/claim/", body, format="json").status_code)
            finally:
                connection.close()

        threads = [threading.Thread(target=worker) for _ in range(n)]
        [t.start() for t in threads]
        [t.join(timeout=60) for t in threads]
        return results

    def test_one_time_link_has_exactly_one_winner(self):
        link = self.make_link(mode="one_time")
        results = self.run_parallel_claims(link, 20)
        self.assertEqual(len(results), 20)
        self.assertEqual(results.count(200), 1, results)
        self.assertEqual(results.count(410), 19, results)
        link.refresh_from_db()
        self.assertEqual(link.download_count, 1)

    def test_capped_timed_link_never_exceeds_max_downloads(self):
        link = self.make_link(max_downloads=3)
        results = self.run_parallel_claims(link, 20)
        self.assertEqual(results.count(200), 3, results)
        link.refresh_from_db()
        self.assertEqual(link.download_count, 3)

    def test_one_time_with_password_still_one_winner(self):
        link = self.make_link(mode="one_time", password="opensesame")
        results = self.run_parallel_claims(link, 10, password="opensesame")
        self.assertEqual(results.count(200), 1, results)
