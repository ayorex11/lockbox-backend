from datetime import timedelta

from django.conf import settings
from django.test import Client
from django.utils import timezone

from accounts.models import User
from vault.models import AuditEvent, File
from vault.services import run_cleanup

from .base import VaultTestCase


class CleanupTests(VaultTestCase):
    def test_deletes_only_dead_links(self):
        now = timezone.now()
        grace = timedelta(seconds=settings.CLAIM_GRACE_SECONDS + 5)
        alive = self.make_link()
        expired = self.make_link(expires_at=now - timedelta(minutes=1))
        revoked = self.make_link(revoked_at=now)
        consumed = self.make_link(mode="one_time", consumed_at=now - grace, last_claimed_at=now - grace)
        just_consumed = self.make_link(mode="one_time", consumed_at=now, last_claimed_at=now)
        capped = self.make_link(
            max_downloads=1, download_count=1, last_claimed_at=now - grace
        )

        stats = run_cleanup()

        self.assertEqual(stats["links"], 4)
        for link in (expired, revoked, consumed, capped):
            link.file.refresh_from_db()
            self.assertEqual(link.file.status, File.Status.DELETED)
            self.assertNotIn(f"files/{link.file_id}", self.storage.objects)
        for link in (alive, just_consumed):  # grace period protects in-flight downloads
            link.file.refresh_from_db()
            self.assertEqual(link.file.status, File.Status.READY)
            self.assertIn(f"files/{link.file_id}", self.storage.objects)

    def test_expired_links_get_a_cleanup_event_once(self):
        link = self.make_link(expires_at=timezone.now() - timedelta(minutes=1))
        run_cleanup()
        run_cleanup()
        self.assertEqual(link.events.filter(event_type=AuditEvent.Type.EXPIRED_CLEANUP).count(), 1)

    def test_abandoned_uploads_removed(self):
        user = self.make_user()
        old = timezone.now() - timedelta(seconds=settings.PENDING_UPLOAD_MAX_AGE_SECONDS + 60)
        stale_pending = File.objects.create(
            owner=user, name="a", size_bytes=1, storage_key="files/stale"
        )
        stale_ready_no_link = self.make_ready_file(user)
        fresh_pending = File.objects.create(owner=user, name="b", size_bytes=1, storage_key="files/fresh")
        File.objects.filter(pk__in=[stale_pending.pk, stale_ready_no_link.pk]).update(created_at=old)

        stats = run_cleanup()

        self.assertEqual(stats["abandoned_uploads"], 2)
        fresh_pending.refresh_from_db()
        self.assertEqual(fresh_pending.status, File.Status.PENDING)

    def test_storage_errors_are_counted_and_do_not_stop_the_run(self):
        from unittest import mock

        self.make_link(revoked_at=timezone.now())
        second = self.make_link(revoked_at=timezone.now())
        calls = {"n": 0}

        def flaky(key):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("b2 hiccup")
            self.storage.objects.pop(key, None)

        with mock.patch("vault.storage.delete_object", side_effect=flaky):
            stats = run_cleanup()
        self.assertEqual((stats["links"], stats["errors"]), (1, 1))
        # The failed one stays READY, so the next run retries it.
        self.assertEqual(File.objects.filter(status=File.Status.READY).count(), 1)
        self.assertIsNotNone(second)

    def test_expired_refresh_tokens_are_purged(self):
        from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
        from rest_framework_simplejwt.tokens import RefreshToken

        user = self.make_user()
        RefreshToken.for_user(user)
        OutstandingToken.objects.update(expires_at=timezone.now() - timedelta(days=1))
        self.assertEqual(run_cleanup()["tokens"], 1)


class InternalEndpointTests(VaultTestCase):
    def test_cleanup_requires_secret(self):
        client = Client()
        self.assertEqual(client.post("/internal/cleanup/").status_code, 404)
        self.assertEqual(
            client.post("/internal/cleanup/", HTTP_X_CLEANUP_SECRET="wrong").status_code, 404
        )
        self.assertEqual(client.get("/internal/cleanup/", HTTP_X_CLEANUP_SECRET="test-cleanup-secret").status_code, 405)

    def test_cleanup_runs_with_secret(self):
        self.make_link(revoked_at=timezone.now())
        response = Client().post("/internal/cleanup/", HTTP_X_CLEANUP_SECRET="test-cleanup-secret")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["links"], 1)

    def test_cleanup_disabled_when_secret_unset(self):
        with self.settings(CLEANUP_SECRET=""):
            response = Client().post("/internal/cleanup/", HTTP_X_CLEANUP_SECRET="")
        self.assertEqual(response.status_code, 404)

    def test_health_checks_database(self):
        response = Client().get("/health/")
        self.assertEqual((response.status_code, response.json()), (200, {"status": "ok"}))
        self.assertEqual(response["Cache-Control"], "no-store") if response.get("Cache-Control") else None
