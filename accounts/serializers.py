from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import User


class EmailField(serializers.EmailField):
    def to_internal_value(self, data):
        return super().to_internal_value(data).strip().lower()


class RegisterSerializer(serializers.Serializer):
    """Email only. The password is chosen at the verification step, so whoever types an
    address into the sign-up form never gets to pick the password of that address's owner."""

    email = EmailField(max_length=254)


def check_new_password(password, user):
    try:
        validate_password(password, user)
    except DjangoValidationError as exc:
        raise serializers.ValidationError({"password": list(exc.messages)}) from None


class LoginSerializer(serializers.Serializer):
    email = EmailField(max_length=254)
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=1024)
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)


class ForgotPasswordSerializer(serializers.Serializer):
    email = EmailField(max_length=254)


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=1024)
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)


class ResendVerificationSerializer(serializers.Serializer):
    email = EmailField(max_length=254)
