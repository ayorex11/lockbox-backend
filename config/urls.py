from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from core import views as core_views
schema_view = get_schema_view(
    openapi.Info(
      title="LOCKBOX API",
      default_version='v1',
      description="API for LOCKBOX",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="adewalemaxwell11@gmail.com"),
      license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)
urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path("redoc/", schema_view.with_ui('redoc', cache_timeout=0), name="schema-redoc"),
    path("admin/", admin.site.urls),
    path("health/", core_views.health),
    path("internal/cleanup/", core_views.cleanup),
    path("api/auth/", include("accounts.urls")),
    path("api/admin/", include("insights.urls")),
    path("api/", include("vault.urls")),
]
