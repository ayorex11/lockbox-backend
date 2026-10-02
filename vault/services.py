"""Business rules for share links. Views stay thin; the guarantees live here.

The two properties that matter most:
  1. A wrong password never consumes a link (password is checked before consume).
  2. Consuming is a single atomic conditional UPDATE, so concurrent claims on a
     one-time link have exactly one winner.
"""

import hashlib
import hmac
import logging
import secrets
import threading
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import close_old_connections, transaction
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
    # hashlib, not hash(): Python's hash() is randomised per process, so with
    # several gunicorn workers the same visitor would never dedupe.
    key = "opened:" + hashlib.sha256(ident.encode()).hexdigest()
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


def _reserve_password_attempt(link_id, now):
    """Count a password attempt BEFORE the password is checked.

    The row is locked while we read and bump the counter, so parallel requests can't all
    pass the "not locked yet" check and each get a free guess: at most
    LINK_PASSWORD_MAX_ATTEMPTS passwords are ever verified per lock window, however many
    requests arrive at once. The attempt that reaches the limit sets the lock up front
    (a successful password clears it again), so everything after it is refused.
    Returns the attempt number (1-based).
    """
    limit = settings.LINK_PASSWORD_MAX_ATTEMPTS
    with transaction.atomic():
        row = ShareLink.objects.select_for_update().get(pk=link_id)
        remaining = _locked_seconds(row, now)
        if remaining:
            raise LinkLocked(remaining)
        if row.locked_until:  # a previous lock has run out: start a fresh window
            row.failed_attempts = 0
            row.locked_until = None
        row.failed_attempts += 1
        if row.failed_attempts >= limit:
            row.locked_until = now + timedelta(seconds=settings.LINK_LOCK_SECONDS)
        row.save(update_fields=["failed_attempts", "locked_until"])
        return row.failed_attempts


def _register_password_failure(link, attempt, request):
    """Always raises: WrongPassword, or LinkLocked once the attempt limit is reached."""
    log_event(link, Event.PASSWORD_FAILED, request)
    limit = settings.LINK_PASSWORD_MAX_ATTEMPTS
    if attempt < limit:
        raise WrongPassword(limit - attempt)

    # This was the last allowed attempt: the lock is already set. Count the lockout, and
    # kill the link if someone keeps coming back to guess.
    ShareLink.objects.filter(pk=link.pk).update(lockout_count=F("lockout_count") + 1)
    link.refresh_from_db(fields=["lockout_count"])
    log_event(link, Event.LOCKED_OUT, request)
    if link.lockout_count >= settings.LINK_MAX_LOCKOUTS:
        revoke_link(link, request, event=Event.AUTO_REVOKED)
    raise LinkLocked(settings.LINK_LOCK_SECONDS)


def _hash_reissue_token(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


class ClaimGrant:
    """What a successful claim hands back: the download URL plus the retry secret."""

    def __init__(self, url, reissue_token):
        self.url = url
        self.reissue_token = reissue_token


def claim(link_id, password, request):
    """Run the full claim sequence and return a ClaimGrant (short-lived presigned URL).

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
        attempt = _reserve_password_attempt(link.pk, now)
        if not link.check_link_password(password):
            _register_password_failure(link, attempt, request)  # always raises
        ShareLink.objects.filter(pk=link.pk).update(failed_attempts=0, locked_until=None)

    if not consume(link, now):
        link.refresh_from_db()
        raise LinkGone(gone_reason(link.compute_status(timezone.now())))

    log_event(link, Event.CLAIMED, request)
    url = storage.presign_get(link.file.storage_key, settings.CLAIM_URL_TTL_SECONDS)

    # Only the winner of the atomic consume gets here, so only one caller holds the token.
    raw_token = secrets.token_urlsafe(24)
    ShareLink.objects.filter(pk=link.pk).update(
        reissue_hash=_hash_reissue_token(raw_token),
        reissue_expires_at=now + timedelta(seconds=settings.CLAIM_REISSUE_SECONDS),
        reissue_count=0,
    )

    link.refresh_from_db(fields=["consumed_at", "download_count", "max_downloads", "revoked_at"])
    if link.compute_status(now) == Status.USED:
        schedule_object_deletion(link.file_id, settings.ONE_TIME_DELETE_DELAY_SECONDS)
    return ClaimGrant(url, raw_token)


def reissue(link_id, reissue_token, request):
    """Hand out a fresh download URL for a claim whose download failed midway.

    No download is counted. Needs the secret returned by the claim, so someone who merely
    holds the link can't use it, and works only briefly and a few times. Any failure raises
    LinkGone (one answer for every reason, so nothing leaks).
    """
    now = timezone.now()
    link = ShareLink.objects.select_related("file").filter(pk=link_id).first()
    if (
        link is None
        or not link.reissue_hash
        or link.revoked_at is not None
        or link.file.status != File.Status.READY
        or link.reissue_expires_at is None
        or now > link.reissue_expires_at
        or not isinstance(reissue_token, str)
        or not hmac.compare_digest(_hash_reissue_token(reissue_token), link.reissue_hash)
    ):
        raise LinkGone("unavailable")

    # Bump the counter conditionally so parallel retries can't exceed the cap.
    updated = ShareLink.objects.filter(
        pk=link.pk, reissue_hash=link.reissue_hash, reissue_count__lt=settings.CLAIM_REISSUE_MAX
    ).update(reissue_count=F("reissue_count") + 1)
    if not updated:
        raise LinkGone("unavailable")
    log_event(link, Event.REISSUED, request)
    return storage.presign_get(link.file.storage_key, settings.CLAIM_URL_TTL_SECONDS)


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
def revoke_link(link, request, event=Event.REVOKED):
    """Idempotent. Marks the link revoked and deletes the ciphertext."""
    now = timezone.now()
    updated = ShareLink.objects.filter(pk=link.pk, revoked_at__isnull=True).update(revoked_at=now)
    if updated:
        log_event(link, event, request)
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
