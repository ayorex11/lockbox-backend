"""Tests for the security-review fixes: link password policy, atomic attempt limits,
auto-revoke, and the claim re-issue window."""

import threading
from datetime import timedelta

from django.conf import settings
from django.db import connection
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from vault.models import AuditEvent, File, ShareLink

from .base import VaultTestCase, VaultTransactionTestCase

Type = AuditEvent.Type


class LinkPasswordPolicyTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user()
        self.client = self.auth_client(self.owner)

    def create(self, password):
        file = self.make_ready_file(self.owner)
        return self.client.post(
            "/api/links/",
            {"file_id": str(file.pk), "mode": "timed", "ttl": "1h", "password": password},
            format="json",
        )

    def test_short_password_rejected(self):
        response = self.create("abc1234")  # 7 characters
        self.assertEqual(response.status_code, 400)
        self.assertIn("password_too_short", str(response.json()))

    def test_common_password_rejected(self):
        for weak in ("password", "12345678", "qwertyuiop"):
            response = self.create(weak)
            self.assertEqual(response.status_code, 400, weak)
            self.assertIn("password_too_common", str(response.json()), weak)

    def test_strong_password_accepted(self):
        self.assertEqual(self.create("tangerine-lamp-42").status_code, 201)


class AttemptLimitTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def claim(self, link, password):
        return self.client.post(f"/api/s/{link.pk}/claim/", {"password": password}, format="json")

    def exhaust(self, link):
        for _ in range(settings.LINK_PASSWORD_MAX_ATTEMPTS):
            last = self.claim(link, "definitely-wrong")
        return last

    def test_correct_password_on_the_last_attempt_still_works_and_clears_the_lock(self):
        link = self.make_link(password="opensesame-1")
        for _ in range(settings.LINK_PASSWORD_MAX_ATTEMPTS - 1):
            self.claim(link, "wrong-pass-1")
        self.assertEqual(self.claim(link, "opensesame-1").status_code, 200)
        link.refresh_from_db()
        self.assertEqual(link.failed_attempts, 0)
        self.assertIsNone(link.locked_until)
        self.assertEqual(link.lockout_count, 0)

    def test_lockout_is_counted_once_per_lock(self):
        link = self.make_link(password="opensesame-1")
        self.assertEqual(self.exhaust(link).status_code, 423)
        link.refresh_from_db()
        self.assertEqual(link.lockout_count, 1)
        self.assertEqual(link.events.filter(event_type=Type.LOCKED_OUT).count(), 1)
        # still locked: more attempts are refused and don't pile up lockouts
        self.assertEqual(self.claim(link, "definitely-wrong").status_code, 423)
        link.refresh_from_db()
        self.assertEqual(link.lockout_count, 1)

    def test_link_is_revoked_and_file_deleted_after_repeated_lockouts(self):
        link = self.make_link(password="opensesame-1")
        key = link.file.storage_key
        for round_number in range(1, settings.LINK_MAX_LOCKOUTS + 1):
            self.exhaust(link)
            link.refresh_from_db()
            if round_number < settings.LINK_MAX_LOCKOUTS:
                self.assertIsNone(link.revoked_at)
                # wait out the lock
                ShareLink.objects.filter(pk=link.pk).update(
                    locked_until=timezone.now() - timedelta(seconds=1)
                )
        link.refresh_from_db()
        self.assertIsNotNone(link.revoked_at)
        self.assertEqual(link.lockout_count, settings.LINK_MAX_LOCKOUTS)
        self.assertTrue(link.events.filter(event_type=Type.AUTO_REVOKED).exists())
        self.assertNotIn(key, self.storage.objects)
        self.assertEqual(File.objects.get(pk=link.file_id).status, File.Status.DELETED)
        # even the right password can no longer get anything
        self.assertEqual(self.claim(link, "opensesame-1").status_code, 410)

    def test_expired_lock_starts_a_fresh_window(self):
        link = self.make_link(password="opensesame-1")
        self.exhaust(link)
        ShareLink.objects.filter(pk=link.pk).update(locked_until=timezone.now() - timedelta(seconds=1))
        response = self.claim(link, "definitely-wrong")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["attempts_left"], settings.LINK_PASSWORD_MAX_ATTEMPTS - 1)


class ParallelGuessingTests(VaultTransactionTestCase):
    """A burst of simultaneous wrong guesses must not get more than the allowed attempts."""

    def test_parallel_wrong_passwords_never_exceed_the_attempt_limit(self):
        link = self.make_link(password="opensesame-1")
        n, results, barrier = 30, [], threading.Barrier(30)

        def worker():
            try:
                client = APIClient()
                barrier.wait(timeout=20)
                response = client.post(
                    f"/api/s/{link.pk}/claim/", {"password": "wrong-guess-1"}, format="json"
                )
                results.append(response.status_code)
            finally:
                connection.close()

        threads = [threading.Thread(target=worker) for _ in range(n)]
        [t.start() for t in threads]
        [t.join(timeout=90) for t in threads]

        self.assertEqual(len(results), n, results)
        self.assertNotIn(200, results)
        verified = link.events.filter(event_type=Type.PASSWORD_FAILED).count()
        self.assertEqual(verified, settings.LINK_PASSWORD_MAX_ATTEMPTS, results)
        self.assertEqual(results.count(423), n - settings.LINK_PASSWORD_MAX_ATTEMPTS + 1, results)
        link.refresh_from_db()
        self.assertEqual(link.lockout_count, 1)


class ReissueTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()

    def claim(self, link, password=None):
        body = {"password": password} if password else {}
        return self.client.post(f"/api/s/{link.pk}/claim/", body, format="json")

    def reissue(self, link, token):
        return self.client.post(
            f"/api/s/{link.pk}/reissue/", {"reissue_token": token}, format="json"
        )

    def test_claim_returns_a_reissue_token_and_stores_only_its_hash(self):
        link = self.make_link(mode="one_time")
        token = self.claim(link).json()["reissue_token"]
        self.assertGreaterEqual(len(token), 30)
        link.refresh_from_db()
        self.assertNotEqual(link.reissue_hash, token)
        self.assertEqual(len(link.reissue_hash), 64)

    def test_a_failed_download_on_a_one_time_link_can_be_retried(self):
        link = self.make_link(mode="one_time")
        token = self.claim(link).json()["reissue_token"]
        retry = self.reissue(link, token)
        self.assertEqual(retry.status_code, 200)
        self.assertIn("download_url", retry.json())
        link.refresh_from_db()
        self.assertEqual(link.download_count, 1)  # a retry is not another download
        self.assertEqual(link.compute_status(), ShareLink.Status.USED)
        self.assertTrue(link.events.filter(event_type=Type.REISSUED).exists())
        # ...but the link itself still cannot be claimed again
        self.assertEqual(self.claim(link).status_code, 410)

    def test_someone_holding_only_the_link_cannot_reissue(self):
        link = self.make_link(mode="one_time")
        self.claim(link)
        for bad in (None, "", "guess", 123):
            self.assertEqual(self.reissue(link, bad).status_code, 410, bad)

    def test_token_from_another_link_is_useless(self):
        first, second = self.make_link(mode="one_time"), self.make_link(mode="one_time")
        token = self.claim(first).json()["reissue_token"]
        self.claim(second)
        self.assertEqual(self.reissue(second, token).status_code, 410)

    def test_reissue_window_expires(self):
        link = self.make_link(mode="one_time")
        token = self.claim(link).json()["reissue_token"]
        ShareLink.objects.filter(pk=link.pk).update(
            reissue_expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertEqual(self.reissue(link, token).status_code, 410)

    def test_reissue_count_is_capped(self):
        link = self.make_link(mode="one_time")
        token = self.claim(link).json()["reissue_token"]
        for _ in range(settings.CLAIM_REISSUE_MAX):
            self.assertEqual(self.reissue(link, token).status_code, 200)
        self.assertEqual(self.reissue(link, token).status_code, 410)

    def test_revoked_link_cannot_be_reissued(self):
        link = self.make_link(mode="one_time")
        token = self.claim(link).json()["reissue_token"]
        owner_client = self.auth_client(link.file.owner)
        self.assertEqual(owner_client.post(f"/api/links/{link.pk}/revoke/").status_code, 200)
        self.assertEqual(self.reissue(link, token).status_code, 410)

    def test_deleted_file_cannot_be_reissued(self):
        link = self.make_link(mode="one_time")
        token = self.claim(link).json()["reissue_token"]
        File.objects.filter(pk=link.file_id).update(status=File.Status.DELETED)
        self.assertEqual(self.reissue(link, token).status_code, 410)

    def test_next_claim_on_a_timed_link_replaces_the_token(self):
        link = self.make_link()
        old = self.claim(link).json()["reissue_token"]
        new = self.claim(link).json()["reissue_token"]
        self.assertNotEqual(old, new)
        self.assertEqual(self.reissue(link, old).status_code, 410)
        self.assertEqual(self.reissue(link, new).status_code, 200)

    def test_object_outlives_the_retry_window(self):
        # The delayed delete and cleanup grace must cover window + URL lifetime.
        needed = settings.CLAIM_REISSUE_SECONDS + settings.CLAIM_URL_TTL_SECONDS
        with override_settings():
            from importlib import reload

            import config.settings as base

            reload(base)
            self.assertGreater(base.ONE_TIME_DELETE_DELAY_SECONDS, needed)
            self.assertGreater(base.CLAIM_GRACE_SECONDS, needed)
