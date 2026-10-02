import re
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import CommonPasswordValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import AuditEvent, File, ShareLink

TTL_CHOICES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class FileInitSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    size = serializers.IntegerField(min_value=1)

    def validate_name(self, value):
        value = _CONTROL_CHARS.sub("", value).strip()
        if not value or "/" in value or "\\" in value:
            raise serializers.ValidationError("invalid_file_name")
        return value

    def validate_size(self, value):
        if value > settings.MAX_UPLOAD_BYTES:
            raise serializers.ValidationError("file_too_large")
        return value


class LinkCreateSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()
    mode = serializers.ChoiceField(choices=ShareLink.Mode.choices)
    ttl = serializers.ChoiceField(choices=list(TTL_CHOICES))
    max_downloads = serializers.IntegerField(
        min_value=1, max_value=100, required=False, allow_null=True
    )
    password = serializers.CharField(
        max_length=128, required=False, trim_whitespace=False, write_only=True
    )
    show_sender_email = serializers.BooleanField(required=False, default=True)

    def validate_password(self, value):
        # Anyone holding the link can guess, so refuse the passwords guessers try first.
        if len(value) < settings.LINK_PASSWORD_MIN_LENGTH:
            raise serializers.ValidationError("password_too_short")
        try:
            CommonPasswordValidator().validate(value)
        except DjangoValidationError:
            raise serializers.ValidationError("password_too_common") from None
        return value

    def validate(self, attrs):
        if attrs["mode"] == ShareLink.Mode.ONE_TIME and attrs.get("max_downloads") is not None:
            raise serializers.ValidationError(
                {"max_downloads": "not_allowed_for_one_time_links"}
            )
        owner = self.context["request"].user
        file = File.objects.filter(pk=attrs["file_id"], owner=owner).first()
        if file is None or file.status != File.Status.READY:
            raise serializers.ValidationError({"file_id": "file_not_found_or_not_ready"})
        if ShareLink.objects.filter(file=file).exists():
            raise serializers.ValidationError({"file_id": "file_already_has_link"})
        attrs["file"] = file
        return attrs

    def to_link_kwargs(self, now):
        data = self.validated_data
        password = data.get("password")
        return {
            "file": data["file"],
            "mode": data["mode"],
            "expires_at": now + TTL_CHOICES[data["ttl"]],
            "max_downloads": data.get("max_downloads"),
            "password_hash": make_password(password) if password else "",
            "show_sender_email": data["show_sender_email"],
        }


class ShareLinkSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    file_name = serializers.CharField(source="file.name", read_only=True)
    file_size = serializers.IntegerField(source="file.size_bytes", read_only=True)
    requires_password = serializers.BooleanField(read_only=True)
    url = serializers.SerializerMethodField()

    class Meta:
        model = ShareLink
        fields = [
            "id", "url", "status", "mode", "file_name", "file_size", "created_at",
            "expires_at", "max_downloads", "download_count", "requires_password",
            "show_sender_email", "consumed_at", "last_claimed_at", "revoked_at",
        ]
        read_only_fields = fields

    def get_status(self, obj):
        return obj.compute_status().value

    def get_url(self, obj):
        # The client appends "#<key>" itself; the server never sees the key.
        return f"{settings.FRONTEND_URL}/s/{obj.pk}"


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = ["id", "event_type", "ip_truncated", "user_agent", "created_at"]
        read_only_fields = fields
