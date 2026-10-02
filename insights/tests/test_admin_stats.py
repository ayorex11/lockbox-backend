from datetime import timedelta

from django.utils import timezone

from accounts.models import User
from vault.models import AuditEvent, ShareLink
from vault.tests.base import VaultTestCase

Event = AuditEvent.Type
BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36 Chrome/120 Safari/537.36"
BOT_UA = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
PASSWORD = "correct-horse-9"

ENDPOINTS = [
    "/api/admin/overview/",
    "/api/admin/timeseries/",
    "/api/admin/top-users/",
    "/api/admin/security/",
]


class AdminTestCase(VaultTestCase):
    def make_staff(self, email="boss@example.com", verified=True):
        return User.objects.create_user(
            email, PASSWORD, is_staff=True, is_email_verified=verified
        )

    def staff_client(self):
        return self.auth_client(self.make_staff())

    def event(self, link, event_type, ua=BROWSER_UA, when=None):
        event = AuditEvent.objects.create(link=link, event_type=event_type, user_agent=ua)
        if when:
            AuditEvent.objects.filter(pk=event.pk).update(created_at=when)
        return event


class AdminAccessTests(AdminTestCase):
    def test_anonymous_gets_401(self):
        from rest_framework.test import APIClient

        for url in ENDPOINTS:
            self.assertEqual(APIClient().get(url).status_code, 401, url)

    def test_regular_user_gets_403(self):
        client = self.auth_client(self.make_user())
        for url in ENDPOINTS:
            response = client.get(url)
            self.assertEqual(response.status_code, 403, url)
            self.assertEqual(response.json()["detail"], "staff_only")

    def test_unverified_staff_gets_403(self):
        client = self.auth_client(self.make_staff(verified=False))
        for url in ENDPOINTS:
            self.assertEqual(client.get(url).status_code, 403, url)

    def test_removing_staff_revokes_access_immediately(self):
        staff = self.make_staff()
        client = self.auth_client(staff)
        self.assertEqual(client.get(ENDPOINTS[0]).status_code, 200)
        User.objects.filter(pk=staff.pk).update(is_staff=False)
        self.assertEqual(client.get(ENDPOINTS[0]).status_code, 403)

    def test_login_and_me_expose_is_staff(self):
        from rest_framework.test import APIClient

        self.make_staff("boss@example.com")
        User.objects.create_user("plain@example.com", PASSWORD, is_email_verified=True)

        client = APIClient()
        staff_login = client.post(
            "/api/auth/login", {"email": "boss@example.com", "password": PASSWORD}, format="json"
        ).json()
        self.assertTrue(staff_login["user"]["is_staff"])
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {staff_login['access']}")
        self.assertTrue(client.get("/api/auth/me").json()["is_staff"])

        plain_login = APIClient().post(
            "/api/auth/login", {"email": "plain@example.com", "password": PASSWORD}, format="json"
        ).json()
        self.assertFalse(plain_login["user"]["is_staff"])


class OverviewTests(AdminTestCase):
    def test_empty_database_returns_zeros_and_null_rates(self):
        data = self.staff_client().get("/api/admin/overview/").json()
        self.assertEqual(data["users"]["total"], 0)  # the staff user is excluded
        self.assertEqual(data["links"]["total"], 0)
        self.assertIsNone(data["funnels"]["links"]["open_rate"])
        self.assertEqual(data["storage"]["bytes_in_storage"], 0)

    def test_counts_users_links_and_funnel(self):
        alice = self.make_user("alice@example.com")
        self.make_user("bob@example.com", verified=False)
        one = self.make_link(alice)
        two = self.make_link(alice, mode=ShareLink.Mode.ONE_TIME, password="secret-pw")
        self.make_link(alice)  # third link, never opened

        self.event(one, Event.OPENED)
        self.event(one, Event.CLAIMED)
        self.event(two, Event.OPENED)

        data = self.staff_client().get("/api/admin/overview/").json()
        self.assertEqual(data["users"]["total"], 2)
        self.assertEqual(data["users"]["verified"], 1)
        self.assertEqual(data["users"]["senders_ever"], 1)
        self.assertEqual(data["links"]["total"], 3)
        self.assertEqual(data["links"]["active"], 3)
        self.assertEqual(data["links"]["one_time"], 1)
        self.assertEqual(data["links"]["password_protected"], 1)
        funnel = data["funnels"]["links"]
        self.assertEqual((funnel["created"], funnel["opened"], funnel["claimed"]), (3, 2, 1))
        self.assertEqual(funnel["never_opened"], 1)
        self.assertEqual(data["engagement"]["claims"], 1)

    def test_bot_opens_are_excluded_from_opens(self):
        link = self.make_link(self.make_user("alice@example.com"))
        self.event(link, Event.OPENED, ua=BROWSER_UA)
        self.event(link, Event.OPENED, ua=BOT_UA)
        self.event(link, Event.OPENED, ua="")
        data = self.staff_client().get("/api/admin/overview/").json()
        self.assertEqual(data["engagement"]["opens"], 1)
        self.assertEqual(data["engagement"]["opens_incl_bots"], 3)
        self.assertEqual(data["funnels"]["links"]["opened"], 1)

    def test_staff_data_is_excluded(self):
        staff = self.make_staff()
        link = self.make_link(staff)
        self.event(link, Event.OPENED)
        self.event(link, Event.CLAIMED)
        # reuse the staff user above: staff_client() would create a second boss@example.com
        data = self.auth_client(staff).get("/api/admin/overview/").json()
        self.assertEqual(data["links"]["total"], 0)
        self.assertEqual(data["engagement"]["claims"], 0)
        self.assertEqual(data["engagement"]["opens"], 0)

    def test_expired_never_opened(self):
        owner = self.make_user("alice@example.com")
        self.make_link(owner, expires_at=timezone.now() - timedelta(hours=1))
        opened = self.make_link(owner, expires_at=timezone.now() - timedelta(hours=1))
        self.event(opened, Event.OPENED)
        data = self.staff_client().get("/api/admin/overview/").json()
        self.assertEqual(data["links"]["expired"], 2)
        self.assertEqual(data["funnels"]["links"]["expired_never_opened"], 1)

    def test_storage_counts_ready_files_only(self):
        owner = self.make_user("alice@example.com")
        self.make_link(owner)  # make_ready_file default size 1000
        data = self.staff_client().get("/api/admin/overview/").json()
        self.assertEqual(data["storage"]["files_in_storage"], 1)
        self.assertEqual(data["storage"]["bytes_in_storage"], 1000)
        self.assertEqual(data["storage"]["bytes_shared_all_time"], 1000)


class TimeseriesTests(AdminTestCase):
    def test_zero_filled_and_ordered(self):
        data = self.staff_client().get("/api/admin/timeseries/?days=7").json()
        self.assertEqual(data["days"], 7)
        self.assertEqual(len(data["series"]), 7)
        dates = [row["date"] for row in data["series"]]
        self.assertEqual(dates, sorted(dates))
        self.assertEqual(dates[-1], timezone.now().date().isoformat())
        self.assertTrue(all(row["claims"] == 0 for row in data["series"]))

    def test_counts_land_on_the_right_day(self):
        owner = self.make_user("alice@example.com")
        link = self.make_link(owner)
        self.event(link, Event.CLAIMED)
        self.event(link, Event.CLAIMED, when=timezone.now() - timedelta(days=2))
        data = self.staff_client().get("/api/admin/timeseries/?days=7").json()
        today = data["series"][-1]
        two_days_ago = data["series"][-3]
        self.assertEqual(today["claims"], 1)
        self.assertEqual(two_days_ago["claims"], 1)
        self.assertEqual(today["links_created"], 1)
        self.assertEqual(today["signups"], 1)

    def test_days_is_clamped_and_bad_input_defaults(self):
        client = self.staff_client()
        self.assertEqual(client.get("/api/admin/timeseries/?days=9999").json()["days"], 90)
        self.assertEqual(client.get("/api/admin/timeseries/?days=0").json()["days"], 1)
        self.assertEqual(client.get("/api/admin/timeseries/?days=abc").json()["days"], 30)


class TopUsersTests(AdminTestCase):
    def test_ranks_by_metric_and_skips_zero(self):
        heavy = self.make_user("heavy@example.com")
        light = self.make_user("light@example.com")
        self.make_user("idle@example.com")
        for _ in range(3):
            self.make_link(heavy, download_count=2)
        self.make_link(light, download_count=9)

        client = self.staff_client()
        by_links = client.get("/api/admin/top-users/?metric=links").json()
        self.assertEqual([r["email"] for r in by_links["results"]], ["heavy@example.com", "light@example.com"])
        self.assertEqual(by_links["results"][0]["links"], 3)

        by_claims = client.get("/api/admin/top-users/?metric=claims").json()
        self.assertEqual(by_claims["results"][0]["email"], "light@example.com")
        self.assertEqual(by_claims["results"][0]["claims"], 9)
        self.assertEqual(by_claims["results"][1]["claims"], 6)

        by_bytes = client.get("/api/admin/top-users/?metric=bytes").json()
        self.assertEqual(by_bytes["results"][0]["bytes_shared"], 3000)

    def test_invalid_metric_is_400_and_limit_is_respected(self):
        client = self.staff_client()
        self.assertEqual(client.get("/api/admin/top-users/?metric=nope").status_code, 400)
        for n in range(3):
            self.make_link(self.make_user(f"u{n}@example.com"))
        self.assertEqual(len(client.get("/api/admin/top-users/?limit=2").json()["results"]), 2)
        self.assertEqual(client.get("/api/admin/top-users/?limit=abc").status_code, 200)

    def test_staff_never_ranked(self):
        self.make_link(self.make_staff("boss2@example.com"))
        results = self.staff_client().get("/api/admin/top-users/").json()["results"]
        self.assertEqual(results, [])


class SecurityTests(AdminTestCase):
    def test_windows_and_series(self):
        link = self.make_link(self.make_user("alice@example.com"))
        for _ in range(3):
            self.event(link, Event.PASSWORD_FAILED)
        self.event(link, Event.LOCKED_OUT)
        self.event(link, Event.PASSWORD_FAILED, when=timezone.now() - timedelta(days=3))

        data = self.staff_client().get("/api/admin/security/").json()
        self.assertEqual(data["windows"]["24h"], {"password_failed": 3, "locked_out": 1})
        self.assertEqual(data["windows"]["7d"]["password_failed"], 4)
        self.assertEqual(data["links_with_failures_7d"], 1)
        self.assertEqual(len(data["series"]), 14)
        self.assertEqual(data["series"][-1]["password_failed"], 3)
