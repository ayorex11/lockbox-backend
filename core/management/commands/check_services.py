"""Check every external service from your own machine.

    python manage.py check_services
    python manage.py check_services --email you@example.com
    python manage.py check_services --origin http://localhost:5173
"""

import urllib.error
import urllib.request

from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.db import connection

from vault import storage

PROBE_KEY = "files/_check_services_probe"


class Command(BaseCommand):
    help = "Test the database, cache table, Backblaze B2 and email configuration."

    def add_arguments(self, parser):
        parser.add_argument("--email", help="Send a test email to this address.")
        parser.add_argument(
            "--origin",
            default=settings.FRONTEND_URL,
            help="Frontend origin to test B2 CORS against (default: FRONTEND_URL).",
        )

    def handle(self, *args, **opts):
        self.failed = False
        self.run_check("Database", self.check_db)
        self.run_check("Cache table", self.check_cache)
        self.run_check("Backblaze B2 upload/download/delete", self.check_b2)
        self.run_check(f"B2 CORS for {opts['origin']}", lambda: self.check_cors(opts["origin"]))
        self.run_check("Email", lambda: self.check_email(opts["email"]))
        self.stdout.write("")
        if self.failed:
            self.stdout.write(self.style.ERROR("Some checks failed. Fix those before deploying."))
        else:
            self.stdout.write(self.style.SUCCESS("Nothing failed."))

    def run_check(self, label, fn):
        try:
            detail = fn()
        except Exception as exc:  # noqa: BLE001
            self.failed = True
            self.stdout.write(self.style.ERROR(f"[FAIL] {label}: {type(exc).__name__}: {exc}"))
            return
        if detail and detail.startswith("SKIP"):
            self.stdout.write(self.style.WARNING(f"[SKIP] {label}: {detail[5:]}"))
        else:
            self.stdout.write(self.style.SUCCESS(f"[ OK ] {label}" + (f": {detail}" if detail else "")))

    # ---------------------------------------------------------------- checks
    def check_db(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return f"{connection.vendor} at {connection.settings_dict.get('HOST') or 'local file'}"

    def check_cache(self):
        cache.set("check_services", "ok", 30)
        if cache.get("check_services") != "ok":
            raise RuntimeError("cache write did not read back; run: python manage.py createcachetable")
        return "read/write works"

    def _b2_configured(self):
        return all(
            [settings.B2_ENDPOINT_URL, settings.B2_KEY_ID, settings.B2_APP_KEY, settings.B2_BUCKET_NAME]
        )

    def check_b2(self):
        if not self._b2_configured():
            return "SKIP B2_* variables are not all set"
        data = b"lockbox-check-services"
        put = urllib.request.Request(
            storage.presign_put(PROBE_KEY, 60),
            data=data,
            method="PUT",
            headers={"Content-Type": storage.OCTET_STREAM},
        )
        try:
            urllib.request.urlopen(put, timeout=20).read()
            size = storage.head_size(PROBE_KEY)
            if size != len(data):
                raise RuntimeError(f"uploaded {len(data)} bytes but B2 reports {size}")
            got = urllib.request.urlopen(storage.presign_get(PROBE_KEY, 60), timeout=20).read()
            if got != data:
                raise RuntimeError("downloaded bytes differ from uploaded bytes")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"B2 returned HTTP {exc.code}: {exc.read().decode()[:300]}") from exc
        finally:
            try:
                storage.delete_object(PROBE_KEY)
            except Exception:  # noqa: BLE001
                pass
        if storage.head_size(PROBE_KEY) is not None:
            raise RuntimeError("probe object still exists after delete")
        return "presigned PUT, HEAD, presigned GET and delete all worked"

    def check_cors(self, origin):
        if not self._b2_configured():
            return "SKIP B2_* variables are not all set"
        preflight = urllib.request.Request(
            storage.presign_put(PROBE_KEY, 60),
            method="OPTIONS",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        try:
            response = urllib.request.urlopen(preflight, timeout=20)
            headers = response.headers
        except urllib.error.HTTPError as exc:
            headers = exc.headers
        allowed = headers.get("Access-Control-Allow-Origin")
        if allowed in (origin, "*"):
            return f"preflight allows {allowed} (methods: {headers.get('Access-Control-Allow-Methods')})"
        raise RuntimeError(
            "B2 did not allow this origin in a preflight. Add it to the bucket's CORS rules. "
            "If you believe the rule is right, confirm with a real upload from the browser."
        )

    def check_email(self, to):
        backend = settings.EMAIL_BACKEND.rsplit(".", 2)[-2]
        if not to:
            return f"SKIP backend is {settings.EMAIL_BACKEND}; pass --email you@example.com to send a test"
        sent = send_mail(
            "Lockbox test email",
            "If you can read this, email is configured correctly.",
            settings.DEFAULT_FROM_EMAIL,
            [to],
        )
        if not sent:
            raise RuntimeError("the email backend reported 0 messages sent")
        return f"handed 1 message to {backend} backend (check the inbox and spam folder)"