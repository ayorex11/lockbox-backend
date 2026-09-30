"""Public, unauthenticated endpoints used by whoever opens a shared link."""

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from core.throttles import ClaimIPThrottle, ClaimTokenThrottle, GlobalIPThrottle, MetaThrottle

from . import services
from .exceptions import LinkGone, LinkLocked, PasswordRequired, WrongPassword
from .models import File, ShareLink


def gone_response(reason):
    # Deliberately minimal: no filename, size or sender on any dead link.
    return Response({"available": False, "reason": reason}, status=status.HTTP_410_GONE)


class RecipientView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]


class LinkMetaView(RecipientView):
    """Never consumes anything, so previewers and bots can't burn a link."""

    throttle_classes = [GlobalIPThrottle, MetaThrottle]

    def get(self, request, token):
        link = ShareLink.objects.select_related("file", "file__owner").filter(pk=token).first()
        if link is None:
            return gone_response("unavailable")

        current = link.compute_status()
        if current != ShareLink.Status.ACTIVE or link.file.status != File.Status.READY:
            return gone_response(
                services.gone_reason(current)
                if current != ShareLink.Status.ACTIVE
                else "unavailable"
            )

        services.log_opened_once(link, request)
        return Response(
            {
                "available": True,
                "name": link.file.name,
                "size": link.file.size_bytes,
                "mode": link.mode,
                "expires_at": link.expires_at,
                "requires_password": link.requires_password,
                "sender_email": link.file.owner.email if link.show_sender_email else None,
            }
        )


class LinkClaimView(RecipientView):
    throttle_classes = [GlobalIPThrottle, ClaimIPThrottle, ClaimTokenThrottle]

    def post(self, request, token):
        password = request.data.get("password") if isinstance(request.data, dict) else None
        if password is not None and not isinstance(password, str):
            return Response({"detail": "invalid_password"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            url = services.claim(token, password, request)
        except LinkGone as exc:
            return gone_response(exc.reason)
        except LinkLocked as exc:
            return Response(
                {"detail": "locked", "retry_after": exc.retry_after},
                status=status.HTTP_423_LOCKED,
            )
        except PasswordRequired:
            return Response({"detail": "password_required"}, status=status.HTTP_401_UNAUTHORIZED)
        except WrongPassword as exc:
            return Response(
                {"detail": "wrong_password", "attempts_left": exc.attempts_left},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return Response({"download_url": url, "expires_in": settings.CLAIM_URL_TTL_SECONDS})
