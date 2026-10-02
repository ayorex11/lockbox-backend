"""Pre-account-takeover protection, password reset, and email abuse limits."""

import re
from unittest import mock
from urllib.parse import unquote

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from accounts.models import User

STRONG = "tangerine-lamp-42"
NEWER = "walrus-bicycle-77"


def token_from_last_email(prefix):
    body = mail.outbox[-1].body
    return unquote(re.search(rf"{prefix}\?token=(\S+)", body).group(1))


class PreAccountTakeoverTests(TestCase):
    """The attack: register someone else's address, hope they click the emailed link."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def post(self, path, body):
        return self.client.post(f"/api/auth/{path}", body, format="json")

    def test_attacker_cannot_know_the_victims_password(self):
        # Attacker signs up with the victim's address. There is no password field at all.
        self.assertEqual(self.post("register", {"email": "victim@example.com"}).status_code, 202)
        victim = User.objects.get(email="victim@example.com")
        self.assertFalse(victim.has_usable_password())
        # Even an attacker-supplied password in the request is ignored.
        self.post("register", {"email": "victim@example.com", "password": "attacker-Pass-1"})
        victim.refresh_from_db()
        self.assertFalse(victim.has_usable_password())
        self.assertEqual(
            self.post("login", {"email": "victim@example.com", "password": "attacker-Pass-1"}).status_code,
            401,
        )

        # The victim opens the link in THEIR inbox and chooses their own password.
        token = token_from_last_email("/verify-email")
        self.assertEqual(self.post("verify-email", {"token": token, "password": STRONG}).status_code, 200)
        login = self.post("login", {"email": "victim@example.com", "password": STRONG})
        self.assertEqual(login.status_code, 200)
        self.assertEqual(
            self.post("login", {"email": "victim@example.com", "password": "attacker-Pass-1"}).status_code,
            401,
        )

    def test_verify_requires_a_password(self):
        self.post("register", {"email": "a@example.com"})
        token = token_from_last_email("/verify-email")
        self.assertEqual(self.post("verify-email", {"token": token}).status_code, 400)
        self.assertFalse(User.objects.get(email="a@example.com").is_email_verified)

    def test_register_is_throttled_per_address_not_just_per_ip(self):
        for _ in range(4):
            self.post("register", {"email": "flood@example.com"})
        self.assertEqual(len(mail.outbox), 1)  # one email per address per cooldown

    def test_resend_shares_the_same_per_address_cooldown(self):
        self.post("register", {"email": "flood@example.com"})
        self.post("resend-verification", {"email": "flood@example.com"})
        self.assertEqual(len(mail.outbox), 1)


class PasswordResetTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user("ayo@example.com", STRONG, is_email_verified=True)

    def post(self, path, body):
        return self.client.post(f"/api/auth/{path}", body, format="json")

    def start(self):
        self.assertEqual(self.post("forgot-password", {"email": "ayo@example.com"}).status_code, 202)
        return token_from_last_email("/reset-password")

    def test_full_reset_flow(self):
        token = self.start()
        response = self.post("reset-password", {"token": token, "password": NEWER})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.post("login", {"email": "ayo@example.com", "password": NEWER}).status_code, 200)
        self.assertEqual(self.post("login", {"email": "ayo@example.com", "password": STRONG}).status_code, 401)

    def test_response_is_identical_for_unknown_and_unverified_addresses(self):
        User.objects.create_user("pending@example.com", STRONG)
        known = self.post("forgot-password", {"email": "ayo@example.com"})
        unknown = self.post("forgot-password", {"email": "nobody@example.com"})
        pending = self.post("forgot-password", {"email": "pending@example.com"})
        self.assertEqual(known.json(), unknown.json())
        self.assertEqual(known.json(), pending.json())
        self.assertEqual(len(mail.outbox), 1)  # only the real, verified account got mail

    def test_reset_link_works_only_once(self):
        token = self.start()
        self.assertEqual(self.post("reset-password", {"token": token, "password": NEWER}).status_code, 200)
        again = self.post("reset-password", {"token": token, "password": "hijack-Pass-9"})
        self.assertEqual(again.status_code, 400)
        self.assertEqual(self.post("login", {"email": "ayo@example.com", "password": NEWER}).status_code, 200)

    def test_reset_link_expires(self):
        token = self.start()
        with override_settings(PASSWORD_RESET_MAX_AGE_SECONDS=-1):
            response = self.post("reset-password", {"token": token, "password": NEWER})
        self.assertEqual(response.status_code, 400)

    def test_verification_token_cannot_be_used_to_reset(self):
        from accounts.tokens import make_verification_token

        response = self.post(
            "reset-password", {"token": make_verification_token(self.user), "password": NEWER}
        )
        self.assertEqual(response.status_code, 400)

    def test_weak_new_password_rejected_and_token_still_usable(self):
        token = self.start()
        self.assertEqual(self.post("reset-password", {"token": token, "password": "short"}).status_code, 400)
        self.assertEqual(self.post("reset-password", {"token": token, "password": NEWER}).status_code, 200)

    def test_reset_ends_every_existing_session(self):
        login = self.post("login", {"email": "ayo@example.com", "password": STRONG})
        self.assertEqual(login.status_code, 200)
        self.assertEqual(OutstandingToken.objects.filter(user=self.user).count(), 1)
        token = self.start()
        self.post("reset-password", {"token": token, "password": NEWER})
        self.assertEqual(BlacklistedToken.objects.filter(token__user=self.user).count(), 1)
        refresh = self.post("refresh", {})
        self.assertEqual(refresh.status_code, 401)

    def test_reset_clears_a_login_lockout(self):
        for _ in range(5):
            self.post("login", {"email": "ayo@example.com", "password": "wrong-Pass-1"})
        self.assertEqual(self.post("login", {"email": "ayo@example.com", "password": STRONG}).status_code, 423)
        cache.delete("mail:reset:ayo@example.com")
        token = self.start()
        self.post("reset-password", {"token": token, "password": NEWER})
        self.assertEqual(self.post("login", {"email": "ayo@example.com", "password": NEWER}).status_code, 200)

    def test_reset_emails_are_rate_limited_per_address(self):
        for _ in range(4):
            self.post("forgot-password", {"email": "ayo@example.com"})
        self.assertEqual(len(mail.outbox), 1)


class AsyncEmailTests(TestCase):
    def test_sending_does_not_block_the_request_when_async(self):
        cache.clear()
        started = []

        class FakeThread:
            def __init__(self, target, args, daemon):
                started.append((target, args, daemon))

            def start(self):
                pass

        with override_settings(EMAIL_SEND_ASYNC=True), mock.patch("accounts.emails.threading.Thread", FakeThread):
            response = APIClient().post("/api/auth/register", {"email": "z@example.com"}, format="json")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(len(started), 1)
        self.assertTrue(started[0][2])  # daemon thread
        self.assertEqual(len(mail.outbox), 0)  # nothing sent inline

    def test_a_failing_mail_backend_never_breaks_signup(self):
        cache.clear()
        with mock.patch("accounts.emails.send_mail", side_effect=RuntimeError("smtp down")):
            response = APIClient().post("/api/auth/register", {"email": "z@example.com"}, format="json")
        self.assertEqual(response.status_code, 202)
