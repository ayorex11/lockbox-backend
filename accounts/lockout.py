"""Login lockout keyed by email hash, so nonexistent and real accounts behave alike."""

import hashlib
import time

from django.conf import settings
from django.core.cache import cache


def _key(email):
    return "login_lock:" + hashlib.sha256(email.encode()).hexdigest()


def seconds_locked(email):
    """Seconds remaining on the lock, or 0 if not locked."""
    state = cache.get(_key(email))
    if not state:
        return 0
    return max(0, int(state.get("locked_until", 0) - time.time()))


def record_failure(email):
    key = _key(email)
    state = cache.get(key) or {"count": 0, "locked_until": 0}
    state["count"] += 1
    if state["count"] >= settings.LOGIN_MAX_ATTEMPTS:
        state["locked_until"] = time.time() + settings.LOGIN_LOCK_SECONDS
        state["count"] = 0
    cache.set(key, state, timeout=settings.LOGIN_LOCK_SECONDS)


def clear(email):
    cache.delete(_key(email))
