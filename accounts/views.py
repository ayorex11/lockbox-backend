from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.hashers import check_password, make_password
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema

from core.throttles import (
    GlobalIPThrottle,
    LoginThrottle,
    RefreshThrottle,
    RegisterThrottle,
    ResendThrottle,
)

from . import lockout
from .cookies import clear_refresh_cookie, enforce_trusted_origin, set_refresh_cookie
from .emails import send_password_reset_email, send_verification_email
from .models import User
from .serializers import (
    ForgotPasswordSerializer,
    LoginSerializer,
    RegisterSerializer,
    ResendVerificationSerializer,
    ResetPasswordSerializer,
    VerifyEmailSerializer,
    check_new_password,
)
from .tokens import read_reset_token, read_verification_token, reset_token_matches

_dummy_hash = None


def _burn_password_check(password):
    """Spend roughly the same time as a real check so response timing doesn't
    reveal whether an email is registered."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = make_password("dummy-password-for-timing")
    check_password(password, _dummy_hash)


class PublicAPIView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]


def _may_email(kind, email, cooldown=60):
    """One email of each kind per address per minute, so the forms can't be used to flood
    someone's inbox. The caller still returns the normal response when this says no."""
    return cache.add(f"mail:{kind}:{email}", 1, timeout=cooldown)


class RegisterView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, RegisterThrottle]

    @swagger_auto_schema(request_body=RegisterSerializer)
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        user = User.objects.filter(email=email).first()
        if user is None:
            # No usable password yet: it is set when the owner opens the emailed link.
            user = User(email=email)
            user.set_unusable_password()
            user.save()
        if not user.is_email_verified and _may_email("verify", email):
            send_verification_email(user)
        # Identical response whether or not the address was already registered.
        return Response({"detail": "verification_email_sent"}, status=status.HTTP_202_ACCEPTED)


class VerifyEmailView(PublicAPIView):
    """Confirms the address AND sets the password. The link works once."""

    throttle_classes = [GlobalIPThrottle, RefreshThrottle]

    @swagger_auto_schema(request_body=VerifyEmailSerializer)
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = read_verification_token(serializer.validated_data["token"])
        user = None
        if payload:
            user = User.objects.filter(pk=payload.get("uid"), email=payload.get("email")).first()
        if user is None or user.is_email_verified or not user.is_active:
            return Response({"detail": "invalid_or_expired_token"}, status=status.HTTP_400_BAD_REQUEST)

        password = serializer.validated_data["password"]
        check_new_password(password, user)
        user.set_password(password)
        user.is_email_verified = True
        user.save(update_fields=["password", "is_email_verified"])
        return Response({"detail": "verified"})


class ResendVerificationView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, ResendThrottle]
    @swagger_auto_schema(request_body=ResendVerificationSerializer)

    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(
            email=serializer.validated_data["email"], is_email_verified=False, is_active=True
        ).first()
        if user and _may_email("verify", user.email):
            send_verification_email(user)
        return Response({"detail": "verification_email_sent"}, status=status.HTTP_202_ACCEPTED)


class ForgotPasswordView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, ResendThrottle]

    @swagger_auto_schema(request_body=ForgotPasswordSerializer)
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email, is_email_verified=True, is_active=True).first()
        if user and _may_email("reset", email):
            send_password_reset_email(user)
        return Response({"detail": "reset_email_sent"}, status=status.HTTP_202_ACCEPTED)


class ResetPasswordView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, RefreshThrottle]

    @swagger_auto_schema(request_body=ResetPasswordSerializer)
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = read_reset_token(serializer.validated_data["token"])
        user = None
        if payload:
            user = User.objects.filter(pk=payload.get("uid"), is_active=True).first()
        if user is None or not user.is_email_verified or not reset_token_matches(user, payload):
            return Response({"detail": "invalid_or_expired_token"}, status=status.HTTP_400_BAD_REQUEST)

        password = serializer.validated_data["password"]
        check_new_password(password, user)
        user.set_password(password)
        user.save(update_fields=["password"])
        # Whoever had the old password must not keep a session: end every refresh token.
        for outstanding in OutstandingToken.objects.filter(user=user):
            BlacklistedToken.objects.get_or_create(token=outstanding)
        lockout.clear(user.email)
        return Response({"detail": "password_reset"})


class LoginView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, LoginThrottle]
    @swagger_auto_schema(request_body=LoginSerializer)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        remaining = lockout.seconds_locked(email)
        if remaining:
            return Response(
                {"detail": "locked", "retry_after": remaining},
                status=status.HTTP_423_LOCKED,
            )

        user = User.objects.filter(email=email, is_active=True).first()
        if user is None:
            _burn_password_check(password)
            lockout.record_failure(email)
            return Response({"detail": "invalid_credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.check_password(password):
            lockout.record_failure(email)
            return Response({"detail": "invalid_credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        lockout.clear(email)
        if not user.is_email_verified:
            return Response({"detail": "email_not_verified"}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)
        response = Response(
            {
                "access": str(refresh.access_token),
                "user": {"email": user.email, "is_staff": user.is_staff},
            }
        )
        set_refresh_cookie(response, str(refresh))
        return response


class RefreshView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, RefreshThrottle]
    @swagger_auto_schema(request_body=TokenRefreshSerializer)
    def post(self, request):
        enforce_trusted_origin(request)
        raw = request.COOKIES.get(settings.REFRESH_COOKIE_NAME)
        if not raw:
            return Response({"detail": "no_refresh_token"}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = TokenRefreshSerializer(data={"refresh": raw})
        try:
            serializer.is_valid(raise_exception=True)
        except (TokenError, InvalidToken):
            response = Response({"detail": "invalid_refresh_token"}, status=status.HTTP_401_UNAUTHORIZED)
            clear_refresh_cookie(response)
            return response

        data = serializer.validated_data
        response = Response({"access": data["access"]})
        if data.get("refresh"):
            set_refresh_cookie(response, data["refresh"])
        return response


class LogoutView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, RefreshThrottle]

    def post(self, request):
        enforce_trusted_origin(request)
        raw = request.COOKIES.get(settings.REFRESH_COOKIE_NAME)
        if raw:
            try:
                RefreshToken(raw).blacklist()
            except TokenError:
                pass
        response = Response(status=status.HTTP_204_NO_CONTENT)
        clear_refresh_cookie(response)
        return response


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "email": request.user.email,
                "is_email_verified": request.user.is_email_verified,
                "is_staff": request.user.is_staff,
            }
        )
