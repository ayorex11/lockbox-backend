from django.conf import settings
from rest_framework.exceptions import PermissionDenied


def set_refresh_cookie(response, refresh_token):
    response.set_cookie(
        settings.REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path=settings.REFRESH_COOKIE_PATH,
    )


def clear_refresh_cookie(response):
    response.delete_cookie(
        settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


def enforce_trusted_origin(request):
    """Cookie-authenticated endpoints reject browser requests from unknown origins.

    Requests without an Origin header (curl, server-to-server) can't be CSRF'd
    from a victim's browser, so they pass.
    """
    origin = request.META.get("HTTP_ORIGIN")
    if origin and origin not in settings.CORS_ALLOWED_ORIGINS:
        raise PermissionDenied("untrusted_origin")
