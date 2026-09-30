"""Test settings: fast hashers, generous throttles, no background timers."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

from .settings import *  # noqa: E402,F401,F403

DEBUG = False
SECRET_KEY = "test-secret-key"
ALLOWED_HOSTS = ["testserver", "localhost"]
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db_for_tests.sqlite3",
        # File-backed test DB so the threaded concurrency test shares one database.
        "TEST": {"NAME": BASE_DIR / "test_db.sqlite3"},
        "OPTIONS": {"timeout": 30},
    }
}

REST_FRAMEWORK = {
    **REST_FRAMEWORK,  # noqa: F405
    "DEFAULT_THROTTLE_RATES": {
        key: "100000/min" for key in REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]  # noqa: F405
    },
}

TRUSTED_PROXY_COUNT = 0
ONE_TIME_DELETE_DELAY_SECONDS = 0
REFRESH_COOKIE_SECURE = False
REFRESH_COOKIE_SAMESITE = "Lax"
FRONTEND_URL = "https://app.lockbox.test"
CORS_ALLOWED_ORIGINS = ["https://app.lockbox.test"]
CLEANUP_SECRET = "test-cleanup-secret"
B2_BUCKET_NAME = "test-bucket"
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
