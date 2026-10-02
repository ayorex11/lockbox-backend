import os
from datetime import timedelta
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env(name, default=None):
    return os.environ.get(name, default)


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default):
    value = os.environ.get(name)
    return int(value) if value not in (None, "") else default


def env_list(name, default=""):
    return [item.strip() for item in env(name, default).split(",") if item.strip()]


# --------------------------------------------------------------------------- core
DEBUG = env_bool("DEBUG", False)

# Django admin lives at a configurable path. Set ADMIN_URL to something unguessable in
# production (e.g. "ops-7f3k2x/"), so the default /admin/ doesn't exist.
ADMIN_URL = env("ADMIN_URL", "admin/").strip("/") + "/"
# Swagger/Redoc are for development. In production they are OFF unless explicitly enabled,
# and even then only a logged-in staff user (Django admin session) can open them.
ENABLE_API_DOCS = env_bool("ENABLE_API_DOCS", DEBUG)

SECRET_KEY = env("SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"
    else:
        raise ImproperlyConfigured("SECRET_KEY must be set when DEBUG is off.")

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1" if DEBUG else "")
if env("RENDER_EXTERNAL_HOSTNAME"):
    ALLOWED_HOSTS.append(env("RENDER_EXTERNAL_HOSTNAME"))

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "accounts",
    "vault",
    "core",
    "insights",
    'drf_yasg',
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.NoStoreAPIMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

AUTH_USER_MODEL = "accounts.User"

# ----------------------------------------------------------------------- database
DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=env_int("DB_CONN_MAX_AGE", 0),
    )
}
if "postgresql" in DATABASES["default"]["ENGINE"]:
    # Required when connecting through Supabase's pgbouncer pooler.
    DATABASES["default"]["DISABLE_SERVER_SIDE_CURSORS"] = True
    DATABASES["default"].setdefault("OPTIONS", {}).setdefault("sslmode", "require")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Cache lives in the database so throttles and login lockouts are shared across
# gunicorn workers and survive restarts. Create it with `manage.py createcachetable`.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "lockbox_cache",
    }
}

# --------------------------------------------------------------------------- auth
PASSWORD_HASHERS = [
    "accounts.hashers.LockboxArgon2PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
    {"NAME": "accounts.validators.LetterAndNumberValidator"},
]

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": False,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# Refresh token cookie. Cross-site deployments (Vercel + onrender.com) need
# SameSite=None; same-site deployments (app.x.com + api.x.com) should use Lax.
REFRESH_COOKIE_NAME = env("REFRESH_COOKIE_NAME", "lockbox_refresh")
REFRESH_COOKIE_SAMESITE = env("REFRESH_COOKIE_SAMESITE", "Lax" if DEBUG else "None")
REFRESH_COOKIE_SECURE = env_bool("REFRESH_COOKIE_SECURE", not DEBUG)
REFRESH_COOKIE_PATH = "/api/auth/"

EMAIL_VERIFICATION_MAX_AGE_SECONDS = env_int("EMAIL_VERIFICATION_MAX_AGE_SECONDS", 60 * 60 * 48)
PASSWORD_RESET_MAX_AGE_SECONDS = env_int("PASSWORD_RESET_MAX_AGE_SECONDS", 60 * 60)
# Send account emails from a background thread so response time doesn't reveal whether an
# address is registered. Tests turn this off.
EMAIL_SEND_ASYNC = env_bool("EMAIL_SEND_ASYNC", True)
LOGIN_MAX_ATTEMPTS = env_int("LOGIN_MAX_ATTEMPTS", 5)
LOGIN_LOCK_SECONDS = env_int("LOGIN_LOCK_SECONDS", 15 * 60)

# --------------------------------------------------------------------------- DRF
_renderers = ["rest_framework.renderers.JSONRenderer"]
if DEBUG:
    _renderers.append("rest_framework.renderers.BrowsableAPIRenderer")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": _renderers,
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_THROTTLE_CLASSES": ["core.throttles.GlobalIPThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "global": "240/min",
        "register": "5/hour",
        "login": "10/min",
        "resend": "3/hour",
        "refresh": "30/min",
        "meta": "60/min",
        "claim": "10/min",
        "claim_token": "20/min",
        "upload": "30/hour",
        "admin": "60/min",
    },
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
}

# --------------------------------------------------------------------- CORS / URLs
FRONTEND_URL = env("FRONTEND_URL", "http://localhost:5173").rstrip("/")
CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", FRONTEND_URL)
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", "")

# ------------------------------------------------------------------- proxy / IPs
# Number of reverse proxies in front of Django whose X-Forwarded-For entry we trust.
# Render: verify with a test request (see README) before relying on audit-log IPs.
TRUSTED_PROXY_COUNT = env_int("TRUSTED_PROXY_COUNT", 1 if not DEBUG else 0)
# Header a TRUSTED edge proxy sets to the real client address, e.g. "CF-Connecting-IP" on
# Render (which sits behind Cloudflare). Preferred over X-Forwarded-For when present and
# valid, because Render's proxy APPENDS to X-Forwarded-For, so no fixed
# TRUSTED_PROXY_COUNT is reliable. Verify with /internal/whoami/ (see README).
CLIENT_IP_HEADER = env("CLIENT_IP_HEADER", "")

# -------------------------------------------------------------------- vault rules
MAX_UPLOAD_BYTES = env_int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024)  # ciphertext size
MAX_ACTIVE_FILES_PER_USER = env_int("MAX_ACTIVE_FILES_PER_USER", 25)
LINK_PASSWORD_MIN_LENGTH = env_int("LINK_PASSWORD_MIN_LENGTH", 8)
LINK_PASSWORD_MAX_ATTEMPTS = env_int("LINK_PASSWORD_MAX_ATTEMPTS", 5)
LINK_LOCK_SECONDS = env_int("LINK_LOCK_SECONDS", 15 * 60)
# After this many lockouts the link is revoked and its file deleted: someone holding the
# link is guessing, and a few dozen guesses total is all they should ever get.
LINK_MAX_LOCKOUTS = env_int("LINK_MAX_LOCKOUTS", 3)
UPLOAD_URL_TTL_SECONDS = env_int("UPLOAD_URL_TTL_SECONDS", 15 * 60)
CLAIM_URL_TTL_SECONDS = env_int("CLAIM_URL_TTL_SECONDS", 60)
# A failed download can be retried with the secret token returned by the claim, for this
# long and at most this many times. No counter is consumed by a retry.
CLAIM_REISSUE_SECONDS = env_int("CLAIM_REISSUE_SECONDS", 120)
CLAIM_REISSUE_MAX = env_int("CLAIM_REISSUE_MAX", 3)
# The object must outlive the last possible retry plus the life of the URL it hands out,
# so both the delayed delete and the cleanup job's grace default to that sum + margin.
_object_lifetime = CLAIM_REISSUE_SECONDS + CLAIM_URL_TTL_SECONDS + 20
ONE_TIME_DELETE_DELAY_SECONDS = env_int("ONE_TIME_DELETE_DELAY_SECONDS", _object_lifetime)
CLAIM_GRACE_SECONDS = env_int("CLAIM_GRACE_SECONDS", _object_lifetime)
PENDING_UPLOAD_MAX_AGE_SECONDS = env_int("PENDING_UPLOAD_MAX_AGE_SECONDS", 60 * 60)
CLEANUP_SECRET = env("CLEANUP_SECRET", "")

# ------------------------------------------------------------------ Backblaze B2
B2_ENDPOINT_URL = env("B2_ENDPOINT_URL", "")  # e.g. https://s3.us-west-004.backblazeb2.com
B2_REGION = env("B2_REGION", "us-west-004")
B2_KEY_ID = env("B2_KEY_ID", "")
B2_APP_KEY = env("B2_APP_KEY", "")
B2_BUCKET_NAME = env("B2_BUCKET_NAME", "")

# -------------------------------------------------------------------------- email
EMAIL_HOST = env("EMAIL_HOST", "")
# Preferred on Render's free tier (SMTP ports are blocked there): Brevo's HTTPS API.
BREVO_API_KEY = env("BREVO_API_KEY", "")
if BREVO_API_KEY:
    EMAIL_BACKEND = "core.email_backend.BrevoAPIEmailBackend"
elif EMAIL_HOST:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_PORT = env_int("EMAIL_PORT", 587)
    EMAIL_HOST_USER = env("EMAIL_HOST_USER", "")
    EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", "")
    EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", True)
    EMAIL_TIMEOUT = 10
else:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "Lockbox <no-reply@localhost>")

# ------------------------------------------------------------- static / security
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

SECURE_REFERRER_POLICY = "same-origin"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", True)
    SECURE_REDIRECT_EXEMPT = [r"^health/$"]
    SECURE_HSTS_SECONDS = env_int("SECURE_HSTS_SECONDS", 60 * 60 * 24 * 365)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
}


SWAGGER_SETTINGS = {
    'PERSIST_AUTH': True,  
    'USE_SESSION_AUTH': False, 
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'Enter your JWT token with `Bearer ` prefix, e.g. Bearer <token>',
        }
    },
}