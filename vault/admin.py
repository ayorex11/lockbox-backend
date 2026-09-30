from django.contrib import admin

from .models import AuditEvent, File, ShareLink


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "status", "size_bytes", "created_at")
    list_filter = ("status",)
    search_fields = ("name", "owner__email")
    readonly_fields = ("storage_key",)


@admin.register(ShareLink)
class ShareLinkAdmin(admin.ModelAdmin):
    list_display = ("id", "mode", "expires_at", "download_count", "revoked_at")
    list_filter = ("mode",)
    # Hide the password hash and keep audit-relevant fields read-only.
    exclude = ("password_hash",)
    readonly_fields = ("id", "file", "download_count", "consumed_at", "last_claimed_at", "revoked_at")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "link", "ip_truncated", "created_at")
    list_filter = ("event_type",)

    def has_change_permission(self, request, obj=None):
        return False  # audit log is append-only
