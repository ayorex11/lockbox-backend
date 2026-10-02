import logging
import threading
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail

from .tokens import make_reset_token, make_verification_token

logger = logging.getLogger(__name__)


def _deliver(subject, body, to):
    try:
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [to])
    except Exception:  # noqa: BLE001 - deliberately broad, see _dispatch
        logger.exception("Failed to send %r email", subject)


def _dispatch(subject, body, to):
    """Send without ever raising, and (by default) off the request thread.

    Callers return the same generic response whether or not the address is registered, so
    neither SMTP errors nor the time a send takes may leak that fact.
    """
    if settings.EMAIL_SEND_ASYNC:
        threading.Thread(target=_deliver, args=(subject, body, to), daemon=True).start()
    else:
        _deliver(subject, body, to)


def send_verification_email(user):
    token = make_verification_token(user)
    url = f"{settings.FRONTEND_URL}/verify-email?token={quote(token)}"
    hours = settings.EMAIL_VERIFICATION_MAX_AGE_SECONDS // 3600
    body = (
        "Welcome to Lockbox.\n\n"
        f"Confirm your email and choose your password to start sending files:\n{url}\n\n"
        f"This link can be used once and expires in {hours} hours. If you didn't create an "
        "account, you can ignore this email."
    )
    _dispatch("Confirm your email", body, user.email)


def send_password_reset_email(user):
    token = make_reset_token(user)
    url = f"{settings.FRONTEND_URL}/reset-password?token={quote(token)}"
    minutes = settings.PASSWORD_RESET_MAX_AGE_SECONDS // 60
    body = (
        "Someone asked to reset the password on your Lockbox account.\n\n"
        f"Choose a new password:\n{url}\n\n"
        f"This link can be used once and expires in {minutes} minutes. If this wasn't you, "
        "ignore this email: your password has not changed."
    )
    _dispatch("Reset your Lockbox password", body, user.email)
