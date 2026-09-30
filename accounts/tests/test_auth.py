from unittest import mock

from django.conf import settings
from django.core import mail
from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from accounts.models import User
from accounts.tokens import make_verification_token

GOOD_PASSWORD = "correct-horse-9"


class AuthTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def register(self, email="ayo@example.com", password=GOOD_PASSWORD):
        return self.client.post("/api/auth/register", {"email": email, "password": password}, format="json")

    def verify(self, user):
        return self.client.post(
            "/api/auth/verify-email", {"token": make_verification_token(user)}, format="json"
        )

    def login(self, email="ayo@example.com", password=GOOD_PASSWORD):
        return self.client.post("/api/auth/login", {"email": email, "password": password}, format="json")

    def verified_user(self, email="ayo@example.com"):
        return User.objects.create_user(email, GOOD_PASSWORD, is_email_verified=True)

    # --- registration & verification ------------------------------------------
    def test_register_sends_verification_email_and_creates_unverified_user(self):
        response = self.register()
        self.assertEqual(response.status_code, 202)
        user = User.objects.get(email="ayo@example.com")
        self.assertFalse(user.is_email_verified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("/verify-email?token=", mail.outbox[0].body)

    def test_register_response_identical_for_existing_email(self):
        self.verified_user()
        fresh = self.register("new@example.com")
        existing = self.register("ayo@example.com")
        self.assertEqual(fresh.status_code, existing.status_code)
        self.assertEqual(fresh.json(), existing.json())

    def test_register_does_not_overwrite_existing_password(self):
        user = self.verified_user()
        old_hash = user.password
        self.register("ayo@example.com", "another-pass-77")
        user.refresh_from_db()
        self.assertEqual(user.password, old_hash)

    def test_email_is_normalised_to_lowercase(self):
        self.register("Ayo@Example.COM")
        self.assertTrue(User.objects.filter(email="ayo@example.com").exists())

    def test_weak_passwords_rejected(self):
        for bad in ["short1", "onlyletterslongenough", "12345678901234", "password123456"]:
            self.assertEqual(self.register("x@example.com", bad).status_code, 400, bad)

    def test_verify_email_flow(self):
        self.register()
        user = User.objects.get(email="ayo@example.com")
        self.assertEqual(self.verify(user).status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)

    def test_verify_email_rejects_garbage_and_tampered_tokens(self):
        for token in ["nonsense", make_verification_token(User(pk=999, email="x@y.com"))]:
            response = self.client.post("/api/auth/verify-email", {"token": token}, format="json")
            self.assertEqual(response.status_code, 400)

    def test_verify_email_token_expires(self):
        user = User.objects.create_user("ayo@example.com", GOOD_PASSWORD)
        token = make_verification_token(user)
        with self.settings(EMAIL_VERIFICATION_MAX_AGE_SECONDS=-1):
            response = self.client.post("/api/auth/verify-email", {"token": token}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_resend_is_generic(self):
        self.verified_user()
        User.objects.create_user("pending@example.com", GOOD_PASSWORD)
        responses = [
            self.client.post("/api/auth/resend-verification", {"email": e}, format="json")
            for e in ["ghost@example.com", "ayo@example.com", "pending@example.com"]
        ]
        self.assertEqual({r.status_code for r in responses}, {202})
        self.assertEqual(len(mail.outbox), 1)  # only the unverified account got mail

    # --- login ------------------------------------------------------------------
    def test_login_success_sets_httponly_refresh_cookie(self):
        self.verified_user()
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.json())
        self.assertNotIn("refresh", response.json())
        cookie = response.cookies[settings.REFRESH_COOKIE_NAME]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["path"], "/api/auth/")

    def test_login_blocked_until_email_verified(self):
        User.objects.create_user("ayo@example.com", GOOD_PASSWORD)
        response = self.login()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"], "email_not_verified")

    def test_login_errors_do_not_reveal_which_part_was_wrong(self):
        self.verified_user()
        wrong_pw = self.login(password="wrong-password-1")
        no_user = self.login(email="ghost@example.com")
        self.assertEqual(wrong_pw.status_code, 401)
        self.assertEqual(wrong_pw.json(), no_user.json())

    def test_login_lockout_after_repeated_failures(self):
        self.verified_user()
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            self.assertEqual(self.login(password="wrong-password-1").status_code, 401)
        locked = self.login()  # even the right password is refused while locked
        self.assertEqual(locked.status_code, 423)
        self.assertGreater(locked.json()["retry_after"], 0)

    def test_lockout_applies_to_unknown_emails_too(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            self.login(email="ghost@example.com")
        self.assertEqual(self.login(email="ghost@example.com").status_code, 423)

    def test_successful_login_resets_failure_count(self):
        self.verified_user()
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            self.login(password="wrong-password-1")
        self.assertEqual(self.login().status_code, 200)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            self.assertEqual(self.login(password="wrong-password-1").status_code, 401)

    def test_login_throttle(self):
        with mock.patch.dict(SimpleRateThrottle.THROTTLE_RATES, {"login": "2/min"}):
            codes = [self.login(email=f"u{i}@example.com").status_code for i in range(3)]
        self.assertEqual(codes[-1], 429)

    # --- refresh / logout ---------------------------------------------------------
    def _logged_in(self):
        self.verified_user()
        return self.login().cookies[settings.REFRESH_COOKIE_NAME].value

    def test_refresh_rotates_token_and_blacklists_the_old_one(self):
        old = self._logged_in()
        self.client.cookies[settings.REFRESH_COOKIE_NAME] = old
        first = self.client.post("/api/auth/refresh")
        self.assertEqual(first.status_code, 200)
        new = first.cookies[settings.REFRESH_COOKIE_NAME].value
        self.assertNotEqual(new, old)

        replay = APIClient()
        replay.cookies[settings.REFRESH_COOKIE_NAME] = old
        self.assertEqual(replay.post("/api/auth/refresh").status_code, 401)

    def test_refresh_without_cookie_is_401(self):
        self.assertEqual(self.client.post("/api/auth/refresh").status_code, 401)

    def test_refresh_rejects_untrusted_origin(self):
        refresh = self._logged_in()
        self.client.cookies[settings.REFRESH_COOKIE_NAME] = refresh
        response = self.client.post("/api/auth/refresh", HTTP_ORIGIN="https://evil.example")
        self.assertEqual(response.status_code, 403)
        ok = self.client.post("/api/auth/refresh", HTTP_ORIGIN="https://app.lockbox.test")
        self.assertEqual(ok.status_code, 200)

    def test_logout_blacklists_refresh_token(self):
        refresh = self._logged_in()
        self.client.cookies[settings.REFRESH_COOKIE_NAME] = refresh
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 204)
        replay = APIClient()
        replay.cookies[settings.REFRESH_COOKIE_NAME] = refresh
        self.assertEqual(replay.post("/api/auth/refresh").status_code, 401)

    def test_me_requires_auth(self):
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        user = self.verified_user()
        access = self.login().json()["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        self.assertEqual(self.client.get("/api/auth/me").json()["email"], user.email)


class HasherTests(TestCase):
    def test_argon2id_with_low_memory_parameters(self):
        from django.contrib.auth.hashers import make_password

        from accounts.hashers import LockboxArgon2PasswordHasher

        encoded = LockboxArgon2PasswordHasher().encode("pw-for-test-1", "somesalt")
        self.assertTrue(encoded.startswith("argon2$argon2id$"))
        self.assertIn("m=19456,t=2,p=1", encoded)
        self.assertTrue(LockboxArgon2PasswordHasher().verify("pw-for-test-1", encoded))
        self.assertFalse(LockboxArgon2PasswordHasher().verify("other", encoded))


class VerificationTokenFormatTests(TestCase):
    """The emailed link URL-encodes the token; a token pasted in that form must work."""

    def test_url_encoded_token_is_accepted(self):
        from urllib.parse import quote

        from accounts.tokens import make_verification_token, read_verification_token

        user = User.objects.create_user(email="enc@example.com", password="Sup3rSecret99")
        token = make_verification_token(user)
        self.assertEqual(read_verification_token(token)["uid"], user.pk)
        self.assertEqual(read_verification_token(quote(token))["uid"], user.pk)
        self.assertIsNone(read_verification_token(token + "x"))