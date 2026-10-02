from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
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
from .emails import send_verification_email
from .models import User
from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    ResendVerificationSerializer,
    VerifyEmailSerializer,
)
from .tokens import read_verification_token

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


class RegisterView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, RegisterThrottle]
    @swagger_auto_schema(request_body=RegisterSerializer)

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = User.objects.filter(email=email).first()
        if user is None:
            user = User.objects.create_user(email=email, password=password)
            send_verification_email(user)
        else:
            _burn_password_check(password)
            if not user.is_email_verified:
                # Never touch the existing password; just re-send the link.
                send_verification_email(user)
        # Identical response whether or not the address was already registered.
        return Response({"detail": "verification_email_sent"}, status=status.HTTP_202_ACCEPTED)


class VerifyEmailView(PublicAPIView):
    throttle_classes = [GlobalIPThrottle, RefreshThrottle]
    @swagger_auto_schema(request_body=VerifyEmailSerializer)

    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = read_verification_token(serializer.validated_data["token"])
        user = None
        if payload:
            user = User.objects.filter(pk=payload.get("uid"), email=payload.get("email")).first()
        if user is None:
            return Response({"detail": "invalid_or_expired_token"}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_email_verified:
            user.is_email_verified = True
            user.save(update_fields=["is_email_verified"])
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
        if user:
            send_verification_email(user)
        return Response({"detail": "verification_email_sent"}, status=status.HTTP_202_ACCEPTED)


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
