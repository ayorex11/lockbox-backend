"""Read-only aggregations for the admin dashboard.

Rules this module follows:
  * Staff accounts are excluded everywhere, so your own testing never skews the numbers.
  * Aggregate only. No file names (plaintext in v1) and no per-event IPs leave this module.
  * "Opened" fires on the metadata GET, which link previewers and bots also hit, so
    `opens` excludes known bot user agents. "Claimed" is the trustworthy number.
"""

from datetime import timedelta

from django.db.models import Count, Max, Q, Sum
from django.db.models.functions import Coalesce, TruncDate
from django.utils import timezone

from accounts.models import User
from vault import services
from vault.models import AuditEvent, File, ShareLink

Event = AuditEvent.Type
Status = ShareLink.Status

MAX_DAYS = 90
TOP_METRICS = {"links": "links", "claims": "claims", "bytes": "bytes_shared"}

# Lower-case substrings that mark non-human user agents (previewers, crawlers, scripts).
BOT_MARKERS = (
    "bot", "crawler", "spider", "preview", "slack", "whatsapp", "telegram", "discord",
    "facebookexternalhit", "linkedin", "twitter", "skype", "curl", "wget",
    "python-requests", "go-http-client", "headless",
)


def bot_q():
    """Q matching events whose user agent looks automated (or is empty)."""
    q = Q(user_agent="")
    for marker in BOT_MARKERS:
        q |= Q(user_agent__icontains=marker)
    return q


# ------------------------------------------------------------------------- scopes
# AuditEvent has a default ordering; queries that use .distinct() call .order_by()
# first, otherwise the ordering columns leak into SELECT DISTINCT and break the count.
def customers():
    return User.objects.filter(is_staff=False)


def files():
    return File.objects.filter(owner__is_staff=False)


def links():
    return ShareLink.objects.filter(file__owner__is_staff=False)


def events():
    return AuditEvent.objects.filter(link__file__owner__is_staff=False)


def human_opens():
    return events().filter(event_type=Event.OPENED).exclude(bot_q())


def _rate(part, whole):
    return round(part / whole, 4) if whole else None


def clamp_days(value, default=30, maximum=MAX_DAYS):
    try:
        days = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(days, maximum))


# ---------------------------------------------------------------------- overview
def overview(now=None):
    now = now or timezone.now()
    d7, d30 = now - timedelta(days=7), now - timedelta(days=30)

    users = customers().aggregate(
        total=Count("pk"),
        verified=Count("pk", filter=Q(is_email_verified=True)),
        new_7d=Count("pk", filter=Q(created_at__gte=d7)),
        new_30d=Count("pk", filter=Q(created_at__gte=d30)),
    )
    # "Active" = created at least one link in the window (last_login isn't tracked).
    users["senders_ever"] = links().values("file__owner").distinct().count()
    users["active_senders_7d"] = (
        links().filter(created_at__gte=d7).values("file__owner").distinct().count()
    )
    users["active_senders_30d"] = (
        links().filter(created_at__gte=d30).values("file__owner").distinct().count()
    )

    link_stats = links().aggregate(
        total=Count("pk"),
        active=Count("pk", filter=services.status_q(Status.ACTIVE, now)),
        used=Count("pk", filter=services.status_q(Status.USED, now)),
        expired=Count("pk", filter=services.status_q(Status.EXPIRED, now)),
        revoked=Count("pk", filter=services.status_q(Status.REVOKED, now)),
        one_time=Count("pk", filter=Q(mode=ShareLink.Mode.ONE_TIME)),
        timed=Count("pk", filter=Q(mode=ShareLink.Mode.TIMED)),
        password_protected=Count("pk", filter=~Q(password_hash="")),
        created_7d=Count("pk", filter=Q(created_at__gte=d7)),
        created_30d=Count("pk", filter=Q(created_at__gte=d30)),
    )

    event_stats = events().aggregate(
        claims=Count("pk", filter=Q(event_type=Event.CLAIMED)),
        opens=Count("pk", filter=Q(event_type=Event.OPENED) & ~bot_q()),
        opens_incl_bots=Count("pk", filter=Q(event_type=Event.OPENED)),
        password_failed=Count("pk", filter=Q(event_type=Event.PASSWORD_FAILED)),
        locked_out=Count("pk", filter=Q(event_type=Event.LOCKED_OUT)),
    )

    opened_links = human_opens().order_by().values("link").distinct().count()
    claimed_links = (
        events().filter(event_type=Event.CLAIMED).order_by().values("link").distinct().count()
    )
    expired_never_opened = (
        links()
        .filter(services.status_q(Status.EXPIRED, now))
        .exclude(pk__in=human_opens().values("link"))
        .count()
    )

    file_stats = files().aggregate(
        started=Count("pk"),
        never_linked=Count("pk", filter=Q(link__isnull=True)),
    )
    stored = files().filter(status=File.Status.READY).aggregate(
        files=Count("pk"), bytes=Coalesce(Sum("size_bytes"), 0)
    )
    shared_bytes = files().filter(link__isnull=False).aggregate(
        bytes=Coalesce(Sum("size_bytes"), 0)
    )["bytes"]

    return {
        "generated_at": now,
        "users": users,
        "links": link_stats,
        "engagement": event_stats,
        "funnels": {
            "users": {
                "signed_up": users["total"],
                "verified": users["verified"],
                "created_a_link": users["senders_ever"],
                "verify_rate": _rate(users["verified"], users["total"]),
                "link_rate": _rate(users["senders_ever"], users["verified"]),
            },
            "links": {
                "created": link_stats["total"],
                "opened": opened_links,
                "claimed": claimed_links,
                "open_rate": _rate(opened_links, link_stats["total"]),
                "claim_rate": _rate(claimed_links, link_stats["total"]),
                "never_opened": link_stats["total"] - opened_links,
                "expired_never_opened": expired_never_opened,
            },
            "uploads": {
                "files_started": file_stats["started"],
                "files_never_linked": file_stats["never_linked"],
                "link_rate": _rate(
                    file_stats["started"] - file_stats["never_linked"], file_stats["started"]
                ),
            },
        },
        "storage": {
            "files_in_storage": stored["files"],
            "bytes_in_storage": stored["bytes"],
            "bytes_shared_all_time": shared_bytes,
        },
    }


# ---------------------------------------------------------------------- timeseries
def _daily_counts(qs, start):
    rows = (
        qs.filter(created_at__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(n=Count("pk"))
        .order_by("day")
    )
    return {row["day"]: row["n"] for row in rows}


def _day_range(days, now):
    today = now.date()  # USE_TZ with TIME_ZONE=UTC, so this matches TruncDate
    return [today - timedelta(days=offset) for offset in range(days - 1, -1, -1)]


def timeseries(days=30, now=None):
    now = now or timezone.now()
    days = clamp_days(days)
    day_list = _day_range(days, now)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)

    signups = _daily_counts(customers(), start)
    created = _daily_counts(links(), start)
    opens = _daily_counts(human_opens(), start)
    claims = _daily_counts(events().filter(event_type=Event.CLAIMED), start)

    return {
        "days": days,
        "series": [
            {
                "date": day.isoformat(),
                "signups": signups.get(day, 0),
                "links_created": created.get(day, 0),
                "opens": opens.get(day, 0),
                "claims": claims.get(day, 0),
            }
            for day in day_list
        ],
    }


# ---------------------------------------------------------------------- top users
def top_users(metric="links", limit=10):
    field = TOP_METRICS[metric]
    limit = max(1, min(int(limit), 50))
    # users -> files -> link is one row per file (a link belongs to exactly one file),
    # so these Counts/Sums don't double count.
    qs = customers().annotate(
        links=Count("files__link", distinct=True),
        claims=Coalesce(Sum("files__link__download_count"), 0),
        bytes_shared=Coalesce(Sum("files__size_bytes", filter=Q(files__link__isnull=False)), 0),
        last_link_at=Max("files__link__created_at"),
    )
    rows = qs.filter(**{f"{field}__gt": 0}).order_by(f"-{field}", "email")[:limit]
    return {
        "metric": metric,
        "results": [
            {
                "email": user.email,
                "links": user.links,
                "claims": user.claims,
                "bytes_shared": user.bytes_shared,
                "last_link_at": user.last_link_at,
                "joined_at": user.created_at,
            }
            for user in rows
        ],
    }


# ------------------------------------------------------------------------ security
def security(now=None, days=14):
    now = now or timezone.now()
    windows = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}

    counts = {}
    for label, delta in windows.items():
        since = now - delta
        counts[label] = events().filter(created_at__gte=since).aggregate(
            password_failed=Count("pk", filter=Q(event_type=Event.PASSWORD_FAILED)),
            locked_out=Count("pk", filter=Q(event_type=Event.LOCKED_OUT)),
        )

    since_7d = now - windows["7d"]
    links_with_failures_7d = (
        events()
        .filter(event_type=Event.PASSWORD_FAILED, created_at__gte=since_7d)
        .order_by()
        .values("link")
        .distinct()
        .count()
    )

    days = clamp_days(days, default=14)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    failed = _daily_counts(events().filter(event_type=Event.PASSWORD_FAILED), start)
    locked = _daily_counts(events().filter(event_type=Event.LOCKED_OUT), start)

    return {
        "windows": counts,
        "links_with_failures_7d": links_with_failures_7d,
        "series": [
            {
                "date": day.isoformat(),
                "password_failed": failed.get(day, 0),
                "locked_out": locked.get(day, 0),
            }
            for day in _day_range(days, now)
        ],
    }
