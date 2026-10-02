from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from core import views as core_views

urlpatterns = [
    # Configurable so production can move it off the guessable /admin/ (see ADMIN_URL).
    path(settings.ADMIN_URL, admin.site.urls),
    path("health/", core_views.health),
    path("internal/cleanup/", core_views.cleanup),
    path("internal/whoami/", core_views.whoami),
    path("api/auth/", include("accounts.urls")),
    path("api/admin/", include("insights.urls")),
    path("api/", include("vault.urls")),
]

if settings.ENABLE_API_DOCS:
    # Swagger/Redoc describe every endpoint, so they are off in production unless
    # ENABLE_API_DOCS=true. Even then, only a staff user logged in through the Django admin
    # (session cookie) can open them; in development they are open.
    from drf_yasg import openapi
    from drf_yasg.views import get_schema_view
    from rest_framework import permissions
    from rest_framework.authentication import SessionAuthentication

    open_docs = settings.DEBUG
    schema_view = get_schema_view(
        openapi.Info(title="LOCKBOX API", default_version="v1", description="API for LOCKBOX"),
        public=open_docs,
        permission_classes=[permissions.AllowAny if open_docs else permissions.IsAdminUser],
        authentication_classes=[] if open_docs else [SessionAuthentication],
    )
    urlpatterns += [
        path("", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
        path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
    ]
