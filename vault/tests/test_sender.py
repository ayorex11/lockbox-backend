from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.utils import timezone

from vault.models import AuditEvent, File, ShareLink

from .base import VaultTestCase


class UploadFlowTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()
        self.client = self.auth_client(self.user)

    def init(self, name="tax.pdf", size=5000):
        return self.client.post("/api/files/", {"name": name, "size": size}, format="json")

    def test_init_returns_presigned_put_and_creates_pending_file(self):
        response = self.init()
        self.assertEqual(response.status_code, 201)
        body = response.json()
        file = File.objects.get(pk=body["file_id"])
        self.assertEqual(file.status, File.Status.PENDING)
        self.assertEqual(file.storage_key, f"files/{file.pk}")
        self.assertIn(file.storage_key, body["upload_url"])
        self.assertEqual(body["expires_in"], settings.UPLOAD_URL_TTL_SECONDS)

    def test_storage_key_never_contains_filename(self):
        body = self.init(name="passport-scan.png").json()
        self.assertNotIn("passport", File.objects.get(pk=body["file_id"]).storage_key)

    def test_init_rejects_oversize_and_bad_names(self):
        self.assertEqual(self.init(size=settings.MAX_UPLOAD_BYTES + 1).status_code, 400)
        self.assertEqual(self.init(size=0).status_code, 400)
        self.assertEqual(self.init(name="../../etc/passwd").status_code, 400)
        self.assertEqual(self.init(name="   ").status_code, 400)

    def test_per_user_file_limit(self):
        with self.settings(MAX_ACTIVE_FILES_PER_USER=2):
            self.assertEqual(self.init().status_code, 201)
            self.assertEqual(self.init().status_code, 201)
            self.assertEqual(self.init().status_code, 409)

    def test_complete_marks_ready_and_records_real_size(self):
        file_id = self.init(size=5000).json()["file_id"]
        self.storage.objects[f"files/{file_id}"] = 5016
        response = self.client.post(f"/api/files/{file_id}/complete/")
        self.assertEqual(response.status_code, 200)
        file = File.objects.get(pk=file_id)
        self.assertEqual((file.status, file.size_bytes), (File.Status.READY, 5016))

    def test_complete_fails_if_object_missing(self):
        file_id = self.init().json()["file_id"]
        response = self.client.post(f"/api/files/{file_id}/complete/")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(File.objects.get(pk=file_id).status, File.Status.PENDING)

    def test_complete_deletes_oversize_object_even_if_size_was_understated(self):
        file_id = self.init(size=100).json()["file_id"]
        key = f"files/{file_id}"
        self.storage.objects[key] = settings.MAX_UPLOAD_BYTES + 5
        response = self.client.post(f"/api/files/{file_id}/complete/")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(key, self.storage.objects)
        self.assertEqual(File.objects.get(pk=file_id).status, File.Status.DELETED)

    def test_cannot_complete_someone_elses_file(self):
        file_id = self.init().json()["file_id"]
        other = self.auth_client(self.make_user("other@example.com"))
        self.assertEqual(other.post(f"/api/files/{file_id}/complete/").status_code, 404)

    def test_unverified_and_anonymous_users_are_blocked(self):
        unverified = self.auth_client(self.make_user("new@example.com", verified=False))
        self.assertEqual(
            unverified.post("/api/files/", {"name": "a", "size": 1}, format="json").status_code, 403
        )
        from rest_framework.test import APIClient

        self.assertEqual(APIClient().get("/api/links/").status_code, 401)


class LinkCreationTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()
        self.client = self.auth_client(self.user)
        self.file = self.make_ready_file(self.user)

    def create(self, **overrides):
        payload = {"file_id": str(self.file.pk), "mode": "timed", "ttl": "24h"}
        payload.update(overrides)
        return self.client.post("/api/links/", payload, format="json")

    def test_timed_link_created_with_defaults(self):
        response = self.create()
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual((body["mode"], body["status"]), ("timed", "active"))
        self.assertTrue(body["show_sender_email"])
        self.assertFalse(body["requires_password"])
        self.assertTrue(body["url"].startswith(f"{settings.FRONTEND_URL}/s/"))
        self.assertNotIn("#", body["url"])
        link = ShareLink.objects.get(pk=body["id"])
        self.assertAlmostEqual(
            (link.expires_at - timezone.now()).total_seconds(), 86400, delta=5
        )
        self.assertTrue(link.events.filter(event_type=AuditEvent.Type.LINK_CREATED).exists())

    def test_one_time_link_still_has_expiry(self):
        body = self.create(mode="one_time", ttl="7d").json()
        link = ShareLink.objects.get(pk=body["id"])
        self.assertIsNone(link.max_downloads)
        self.assertAlmostEqual((link.expires_at - timezone.now()).days, 6, delta=1)

    def test_one_time_rejects_max_downloads(self):
        self.assertEqual(self.create(mode="one_time", max_downloads=3).status_code, 400)

    def test_password_is_stored_hashed_and_never_returned(self):
        response = self.create(password="s3cret-pass")
        self.assertNotIn("s3cret-pass", response.content.decode())
        link = ShareLink.objects.get(pk=response.json()["id"])
        self.assertNotEqual(link.password_hash, "s3cret-pass")
        self.assertTrue(link.check_link_password("s3cret-pass"))
        self.assertTrue(response.json()["requires_password"])

    def test_short_password_rejected(self):
        self.assertEqual(self.create(password="abc").status_code, 400)

    def test_hide_sender_email_option(self):
        body = self.create(show_sender_email=False).json()
        self.assertFalse(body["show_sender_email"])

    def test_invalid_ttl_and_mode(self):
        self.assertEqual(self.create(ttl="30d").status_code, 400)
        self.assertEqual(self.create(mode="forever").status_code, 400)

    def test_one_link_per_file(self):
        self.assertEqual(self.create().status_code, 201)
        self.assertEqual(self.create().status_code, 400)

    def test_cannot_link_pending_or_foreign_files(self):
        pending = File.objects.create(owner=self.user, name="p", size_bytes=1)
        self.assertEqual(self.create(file_id=str(pending.pk)).status_code, 400)
        foreign = self.make_ready_file(self.make_user("other@example.com"))
        self.assertEqual(self.create(file_id=str(foreign.pk)).status_code, 400)


class DashboardTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()
        self.client = self.auth_client(self.user)
        now = timezone.now()
        self.active = self.make_link(self.user)
        self.used = self.make_link(self.user, mode="one_time", consumed_at=now, download_count=1)
        self.capped = self.make_link(self.user, max_downloads=2, download_count=2)
        self.expired = self.make_link(self.user, expires_at=now - timedelta(hours=1))
        self.revoked = self.make_link(self.user, revoked_at=now, download_count=3)
        self.other = self.make_link(self.make_user("other@example.com"))

    def test_stats_and_isolation(self):
        body = self.client.get("/api/links/").json()
        self.assertEqual(body["count"], 5)  # never includes the other user's link
        self.assertEqual(
            body["stats"],
            {"total": 5, "active": 1, "used": 2, "expired": 1, "revoked": 1, "total_claims": 6},
        )

    def test_status_filter_matches_computed_status(self):
        for wanted, expected in [("active", 1), ("used", 2), ("expired", 1), ("revoked", 1)]:
            body = self.client.get(f"/api/links/?status={wanted}").json()
            self.assertEqual(body["count"], expected, wanted)
            self.assertTrue(all(r["status"] == wanted for r in body["results"]), wanted)
        self.assertEqual(self.client.get("/api/links/?status=bogus").status_code, 400)

    def test_cannot_read_or_revoke_someone_elses_link(self):
        for method, path in [
            ("get", f"/api/links/{self.other.pk}/"),
            ("get", f"/api/links/{self.other.pk}/events/"),
            ("post", f"/api/links/{self.other.pk}/revoke/"),
        ]:
            response = getattr(self.client, method)(path)
            self.assertIn(response.status_code, (404, 200))
            if response.status_code == 200:  # events endpoint returns an empty page
                self.assertEqual(response.json()["count"], 0)
        self.other.refresh_from_db()
        self.assertIsNone(self.other.revoked_at)

    def test_events_timeline_newest_first(self):
        from vault.services import log_event

        log_event(self.active, AuditEvent.Type.LINK_CREATED)
        log_event(self.active, AuditEvent.Type.OPENED)
        events = self.client.get(f"/api/links/{self.active.pk}/events/").json()["results"]
        self.assertEqual([e["event_type"] for e in events], ["opened", "link_created"])


class RevokeTests(VaultTestCase):
    def test_revoke_deletes_ciphertext_and_is_idempotent(self):
        user = self.make_user()
        client = self.auth_client(user)
        link = self.make_link(user)
        key = link.file.storage_key
        self.assertIn(key, self.storage.objects)

        first = client.post(f"/api/links/{link.pk}/revoke/")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["status"], "revoked")
        self.assertNotIn(key, self.storage.objects)
        link.file.refresh_from_db()
        self.assertEqual(link.file.status, File.Status.DELETED)
        self.assertIsNone(link.file.storage_key)

        self.assertEqual(client.post(f"/api/links/{link.pk}/revoke/").status_code, 200)
        self.assertEqual(link.events.filter(event_type=AuditEvent.Type.REVOKED).count(), 1)

    def test_revoke_survives_storage_failure_and_leaves_file_for_cleanup(self):
        user = self.make_user()
        link = self.make_link(user)
        with mock.patch("vault.storage.delete_object", side_effect=RuntimeError("b2 down")):
            response = self.auth_client(user).post(f"/api/links/{link.pk}/revoke/")
        self.assertEqual(response.status_code, 200)
        link.refresh_from_db()
        self.assertIsNotNone(link.revoked_at)
        self.assertEqual(link.file.status, File.Status.READY)  # cleanup will retry
