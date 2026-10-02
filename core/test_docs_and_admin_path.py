from importlib import reload

from django.test import TestCase, override_settings
from django.urls import clear_url_caches, set_urlconf
from rest_framework.test import APIClient

from accounts.models import User

PLAIN_STATIC = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(STORAGES=PLAIN_STATIC)  # no collectstatic manifest under test
class DocsAndAdminPathTests(TestCase):
    """urls.py is evaluated at import, so reload it under the settings being tested."""

    def reload_urls(self):
        import config.urls

        clear_url_caches()
        reload(config.urls)
        set_urlconf(None)

    def tearDown(self):
        self.reload_urls()

    @override_settings(ENABLE_API_DOCS=False)
    def test_docs_are_not_mounted_when_disabled(self):
        self.reload_urls()
        client = APIClient()
        self.assertEqual(client.get("/").status_code, 404)
        self.assertEqual(client.get("/redoc/").status_code, 404)
        self.assertEqual(client.get("/health/").status_code, 200)

    @override_settings(ENABLE_API_DOCS=True, DEBUG=False)
    def test_docs_need_a_staff_session_in_production(self):
        self.reload_urls()
        self.assertIn(APIClient().get("/").status_code, (401, 403))
        staff = User.objects.create_user("s@example.com", "x-Password-1", is_staff=True, is_email_verified=True)
        client = APIClient()
        client.force_login(staff)
        self.assertEqual(client.get("/").status_code, 200)

    @override_settings(ADMIN_URL="ops-9x2k/")
    def test_admin_moves_off_the_default_path(self):
        self.reload_urls()
        client = APIClient()
        self.assertEqual(client.get("/admin/login/").status_code, 404)
        self.assertEqual(client.get("/ops-9x2k/login/").status_code, 200)

    def test_no_personal_email_in_the_public_schema(self):
        import config.urls

        source = open(config.urls.__file__).read()
        self.assertNotIn("gmail.com", source)
        self.assertNotIn("google.com/policies", source)
