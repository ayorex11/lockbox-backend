from django.contrib import admin

from .models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("email", "is_email_verified", "is_active", "is_staff", "created_at")
    list_filter = ("is_email_verified", "is_active", "is_staff")
    search_fields = ("email",)
    readonly_fields = ("password", "last_login", "created_at")
