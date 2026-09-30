"""Business rules for share links. Views stay thin; the guarantees live here.

The two properties that matter most:
  1. A wrong password never consumes a link (password is checked before consume).
  2. Consuming is a single atomic conditional UPDATE, so concurrent claims on a
     one-time link have exactly one winner.
"""

import logging
import threading
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import close_old_connections
from django.db.models import F, Q
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from core.utils import get_client_ip, truncate_ip, truncate_user_agent

from . import storage
from .exceptions import LinkGone, LinkLocked, PasswordRequired, WrongPassword
from .models import AuditEvent, File, ShareLink

logger = logging.getLogger(__name__)

Status = ShareLink.Status
Mode = ShareLink.Mode
Event = AuditEvent.Type


# ------------------------------------------------------------------ status queries
def status_q(status, now):
    """Q object equivalent of ShareLink.compute_status(), for filtering and counting."""
    used = Q(consumed_at__isnull=False) | Q(
        max_downloads__isnull=False, download_count__gte=F("max_downloads")
    )
    not_revoked = Q(revoked_at__isnull=True)
    if status == Status.REVOKED:
        return Q(revoked_at__isnull=False)
    if status == Status.USED:
        return not_revoked & used
    if status == Status.EXPIRED:
        return not_revoked & ~used & Q(expires_at__lte=now)
    if status == Status.ACTIVE:
        return not_revoked & ~used & Q(expires_at__gt=now)
    raise ValueError(f"unknown status {status!r}")


def gone_reason(status):
    return "expired" if status == Status.EXPIRED else "unavailable"


# ---------------------------------------------------------------------- audit log
def log_event(link, event_type, request=None):
    ip = truncate_ip(get_client_ip(request)) if request is not None else ""
    ua = truncate_user_agent(request) if request is not None else ""
    return AuditEvent.objects.create(
        link=link, event_type=event_type, ip_truncated=ip, user_agent=ua
    )


def log_opened_once(link, request):
    """'opened' fires on the metadata GET, which link previewers also hit. Collapse
    repeat views from the same client within 10 minutes into one event."""
    ident = f"{link.pk}|{get_client_ip(request)}|{truncate_user_agent(request)}"
    key = "opened:" + str(hash(ident))
    if cache.add(key, 1, timeout=600):
        log_event(link, Event.OPENED, request)


# ------------------------------------------------------------------ atomic consume
def consume(link, now):
    """Claim one download. Returns True only for the caller that wins the update."""
    base = ShareLink.objects.filter(pk=link.pk, revoked_at__isnull=True, expires_at__gt=now)
    if link.mode == Mode.ONE_TIME:
        updated = base.filter(mode=Mode.ONE_TIME, consumed_at__isnull=True).update(
            consumed_at=now, last_claimed_at=now, download_count=F("download_count") + 1
        )
    else:
        updated = (
            base.filter(mode=Mode.TIMED)
            .filter(Q(max_downloads__isnull=True) | Q(download_count__lt=F("max_downloads")))
            .update(last_claimed_at=now, download_count=F("download_count") + 1)
        )
    return updated == 1


# ------------------------------------------------------------------------- claim
def _locked_seconds(link, now):
    if link.locked_until and link.locked_until > now:
        return max(1, int((link.locked_until - now).total_seconds()) + 1)
    return 0


def _register_password_failure(link, now, request):
    ShareLink.objects.filter(pk=link.pk).update(failed_attempts=F("failed_attempts") + 1)
    link.refresh_from_db(fields=["failed_attempts"])
    log_event(link, Event.PASSWORD_FAILED, request)
    limit = settings.LINK_PASSWORD_MAX_ATTEMPTS
    if link.failed_attempts >= limit:
        ShareLink.objects.filter(pk=link.pk).update(
            failed_attempts=0,
            locked_until=now + timedelta(seconds=settings.LINK_LOCK_SECONDS),
        )
        log_event(link, Event.LOCKED_OUT, request)
        raise LinkLocked(settings.LINK_LOCK_SECONDS)
    raise WrongPassword(limit - link.failed_attempts)


def claim(link_id, password, request):
    """Run the full claim sequence and return a short-lived presigned download URL.

    Order matters: existence -> status -> lock -> password -> atomic consume.
    Raises LinkGone, LinkLocked, PasswordRequired or WrongPassword.
    """
    now = timezone.now()
    link = ShareLink.objects.select_related("file").filter(pk=link_id).first()
    if link is None:
        raise LinkGone("unavailable")

    status = link.compute_status(now)
    if status != Status.ACTIVE or link.file.status != File.Status.READY:
        raise LinkGone(gone_reason(status) if status != Status.ACTIVE else "unavailable")

    remaining = _locked_seconds(link, now)
    if remaining:
        raise LinkLocked(remaining)

    if link.requires_password:
        if not password:
            raise PasswordRequired()
        if not link.check_link_password(password):
            _register_password_failure(link, now, request)  # always raises
        if link.failed_attempts:
            ShareLink.objects.filter(pk=link.pk).update(failed_attempts=0)

    if not consume(link, now):
        link.refresh_from_db()
        raise LinkGone(gone_reason(link.compute_status(timezone.now())))

    log_event(link, Event.CLAIMED, request)
    url = storage.presign_get(link.file.storage_key, settings.CLAIM_URL_TTL_SECONDS)

    link.refresh_from_db(fields=["consumed_at", "download_count", "max_downloads", "revoked_at"])
    if link.compute_status(now) == Status.USED:
        schedule_object_deletion(link.file_id, settings.ONE_TIME_DELETE_DELAY_SECONDS)
    return url


# --------------------------------------------------------------- deleting objects
def delete_file_object(file):
    """Remove the ciphertext from B2 and mark the file deleted."""
    if file.storage_key:
        storage.delete_object(file.storage_key)
    file.status = File.Status.DELETED
    file.deleted_at = timezone.now()
    file.storage_key = None
    file.save(update_fields=["status", "deleted_at", "storage_key"])


def _delete_file_by_id(file_id):
    close_old_connections()
    try:
        file = File.objects.filter(pk=file_id).exclude(status=File.Status.DELETED).first()
        if file:
            delete_file_object(file)
    except Exception:  # noqa: BLE001 - the cleanup job retries
        logger.exception("Delayed deletion failed for file %s", file_id)
    finally:
        close_old_connections()


def schedule_object_deletion(file_id, delay):
    """Best-effort delayed delete after a final claim (the URL needs time to work).
    If the process restarts before the timer fires, the cleanup job catches it."""
    if not delay:
        return
    timer = threading.Timer(delay, _delete_file_by_id, args=(file_id,))
    timer.daemon = True
    timer.start()


# ------------------------------------------------------------------------ revoke
def revoke_link(link, request):
    """Idempotent. Marks the link revoked and deletes the ciphertext."""
    now = timezone.now()
    updated = ShareLink.objects.filter(pk=link.pk, revoked_at__isnull=True).update(revoked_at=now)
    if updated:
        log_event(link, Event.REVOKED, request)
    file = link.file
    if file.status != File.Status.DELETED:
        try:
            delete_file_object(file)
        except Exception:  # noqa: BLE001 - revoked_at is set; cleanup retries deletion
            logger.exception("Deleting object for revoked link %s failed", link.pk)
    link.refresh_from_db()


# ------------------------------------------------------------------------ cleanup
def run_cleanup(now=None, limit=200):
    """Delete ciphertext for dead links and abandoned uploads. Safe to run repeatedly."""
    now = now or timezone.now()
    grace = now - timedelta(seconds=settings.CLAIM_GRACE_SECONDS)
    abandoned = now - timedelta(seconds=settings.PENDING_UPLOAD_MAX_AGE_SECONDS)
    stats = {"links": 0, "abandoned_uploads": 0, "tokens": 0, "errors": 0}

    dead_links = (
        File.objects.filter(status=File.Status.READY, link__isnull=False)
        .filter(
            Q(link__revoked_at__isnull=False)
            | Q(link__expires_at__lte=now)
            | Q(link__consumed_at__lte=grace)
            | Q(
                link__max_downloads__isnull=False,
                link__download_count__gte=F("link__max_downloads"),
                link__last_claimed_at__lte=grace,
            )
        )
        .select_related("link")[:limit]
    )
    for file in dead_links:
        try:
            link = file.link
            was_expired = link.compute_status(now) == Status.EXPIRED
            delete_file_object(file)
            if was_expired:
                log_event(link, Event.EXPIRED_CLEANUP)
            stats["links"] += 1
        except Exception:  # noqa: BLE001
            logger.exception("Cleanup failed for file %s", file.pk)
            stats["errors"] += 1

    orphaned = File.objects.filter(
        Q(status=File.Status.PENDING) | Q(status=File.Status.READY, link__isnull=True),
        created_at__lte=abandoned,
    )[:limit]
    for file in orphaned:
        try:
            delete_file_object(file)
            stats["abandoned_uploads"] += 1
        except Exception:  # noqa: BLE001
            logger.exception("Cleanup failed for file %s", file.pk)
            stats["errors"] += 1

    deleted, _ = OutstandingToken.objects.filter(expires_at__lt=now).delete()
    stats["tokens"] = deleted
    return stats
