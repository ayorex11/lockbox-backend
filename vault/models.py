import secrets
import uuid

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.db import models
from django.db.models import Q
from django.utils import timezone


def generate_link_token():
    # 128 bits of randomness -> 22 url-safe characters. Unguessable by design.
    return secrets.token_urlsafe(16)


class File(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending"
        READY = "ready"
        DELETED = "deleted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="files"
    )
    storage_key = models.CharField(max_length=255, null=True, blank=True, unique=True)
    name = models.CharField(max_length=255)  # plaintext in v1 (see contract, decision 5)
    size_bytes = models.BigIntegerField()  # ciphertext size
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["owner", "status"])]

    def __str__(self):
        return f"{self.name} ({self.status})"


class ShareLink(models.Model):
    class Mode(models.TextChoices):
        TIMED = "timed"
        ONE_TIME = "one_time"

    class Status(models.TextChoices):
        ACTIVE = "active"
        USED = "used"
        EXPIRED = "expired"
        REVOKED = "revoked"

    id = models.CharField(
        primary_key=True, max_length=32, default=generate_link_token, editable=False
    )
    # One link per file: a one-time claim deletes the file, so sharing one file
    # through several links would break the others.
    file = models.OneToOneField(File, on_delete=models.CASCADE, related_name="link")
    mode = models.CharField(max_length=10, choices=Mode.choices)
    expires_at = models.DateTimeField(db_index=True)
    max_downloads = models.PositiveIntegerField(null=True, blank=True)
    download_count = models.PositiveIntegerField(default=0)
    password_hash = models.CharField(max_length=256, blank=True, default="")
    failed_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    lockout_count = models.PositiveSmallIntegerField(default=0)
    # Retry window after a claim: only the claimer holds the secret behind reissue_hash.
    reissue_hash = models.CharField(max_length=64, blank=True, default="")
    reissue_expires_at = models.DateTimeField(null=True, blank=True)
    reissue_count = models.PositiveSmallIntegerField(default=0)
    consumed_at = models.DateTimeField(null=True, blank=True)  # one_time only
    last_claimed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    show_sender_email = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(mode="timed") | Q(max_downloads__isnull=True),
                name="one_time_links_have_no_max_downloads",
            )
        ]

    def __str__(self):
        return f"{self.id} [{self.mode}]"

    @property
    def requires_password(self):
        return bool(self.password_hash)

    def check_link_password(self, raw):
        return check_password(raw, self.password_hash)

    def compute_status(self, now=None):
        """First match wins: revoked > used > expired > active."""
        now = now or timezone.now()
        if self.revoked_at:
            return self.Status.REVOKED
        if self.consumed_at or (
            self.max_downloads is not None and self.download_count >= self.max_downloads
        ):
            return self.Status.USED
        if now >= self.expires_at:
            return self.Status.EXPIRED
        return self.Status.ACTIVE


class AuditEvent(models.Model):
    class Type(models.TextChoices):
        LINK_CREATED = "link_created"
        OPENED = "opened"
        PASSWORD_FAILED = "password_failed"
        LOCKED_OUT = "locked_out"
        CLAIMED = "claimed"
        REVOKED = "revoked"
        AUTO_REVOKED = "auto_revoked"  # too many password lockouts
        REISSUED = "reissued"  # download URL re-issued after a failed download
        EXPIRED_CLEANUP = "expired_cleanup"

    link = models.ForeignKey(ShareLink, on_delete=models.CASCADE, related_name="events")
    event_type = models.CharField(max_length=20, choices=Type.choices)
    ip_truncated = models.CharField(max_length=64, blank=True, default="")
    user_agent = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["link", "-created_at"]),
            # Admin dashboard: counts and daily series filtered by type and date.
            models.Index(fields=["event_type", "created_at"], name="audit_type_created_idx"),
        ]
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"{self.event_type} @ {self.created_at:%Y-%m-%d %H:%M:%S}"
