from unittest import mock

from django.core.cache import cache
from django.test import TestCase, TransactionTestCase
from rest_framework.test import APIClient

from accounts.models import User
from vault.models import File, ShareLink


class FakeStorage:
    """In-memory stand-in for vault.storage. Records what would hit B2."""

    def __init__(self):
        self.objects = {}  # key -> size in bytes

    def presign_put(self, key, ttl):
        return f"https://b2.test/put/{key}?ttl={ttl}"

    def presign_get(self, key, ttl):
        return f"https://b2.test/get/{key}?ttl={ttl}"

    def head_size(self, key):
        return self.objects.get(key)

    def delete_object(self, key):
        self.objects.pop(key, None)


class StorageMixin:
    def setUp(self):
        super().setUp()
        cache.clear()
        self.storage = FakeStorage()
        for name in ("presign_put", "presign_get", "head_size", "delete_object"):
            patcher = mock.patch(f"vault.storage.{name}", getattr(self.storage, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    # -- helpers ---------------------------------------------------------------
    def make_user(self, email="sender@example.com", verified=True):
        user, _ = User.objects.get_or_create(email=email, defaults={"is_email_verified": verified})
        if not user.has_usable_password():
            user.set_password("correct-horse-9")
            user.save(update_fields=["password"])
        return user

    def auth_client(self, user):
        from rest_framework_simplejwt.tokens import AccessToken

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {AccessToken.for_user(user)}")
        return client

    def make_ready_file(self, owner, name="tax.pdf", size=1000):
        file = File.objects.create(owner=owner, name=name, size_bytes=size, status=File.Status.READY)
        file.storage_key = f"files/{file.pk}"
        file.save(update_fields=["storage_key"])
        self.storage.objects[file.storage_key] = size
        return file

    def make_link(self, owner=None, **overrides):
        from datetime import timedelta

        from django.contrib.auth.hashers import make_password
        from django.utils import timezone

        owner = owner or self.make_user()
        file = self.make_ready_file(owner)
        password = overrides.pop("password", None)
        kwargs = {
            "file": file,
            "mode": ShareLink.Mode.TIMED,
            "expires_at": timezone.now() + timedelta(hours=24),
        }
        if password:
            kwargs["password_hash"] = make_password(password)
        kwargs.update(overrides)
        return ShareLink.objects.create(**kwargs)


class VaultTestCase(StorageMixin, TestCase):
    pass


class VaultTransactionTestCase(StorageMixin, TransactionTestCase):
    pass
