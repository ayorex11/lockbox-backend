"""Sender-facing endpoints (authenticated + email-verified)."""

import uuid

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q, Sum
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from core.permissions import IsVerifiedUser
from core.throttles import GlobalIPThrottle, UploadThrottle

from . import services, storage
from .models import AuditEvent, File, ShareLink
from .serializers import (
    AuditEventSerializer,
    FileInitSerializer,
    LinkCreateSerializer,
    ShareLinkSerializer,
)

SenderPermissions = [IsAuthenticated, IsVerifiedUser]


class FileInitView(APIView):
    """Step 1 of upload: reserve a file id and hand back a presigned PUT URL."""

    permission_classes = SenderPermissions
    throttle_classes = [GlobalIPThrottle, UploadThrottle]
    @swagger_auto_schema(request_body=FileInitSerializer)

    def post(self, request):
        serializer = FileInitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        active = File.objects.filter(
            owner=request.user, status__in=[File.Status.PENDING, File.Status.READY]
        ).count()
        if active >= settings.MAX_ACTIVE_FILES_PER_USER:
            return Response({"detail": "file_limit_reached"}, status=status.HTTP_409_CONFLICT)

        file_id = uuid.uuid4()
        file = File.objects.create(
            id=file_id,
            owner=request.user,
            name=serializer.validated_data["name"],
            size_bytes=serializer.validated_data["size"],
            storage_key=f"files/{file_id}",
        )
        ttl = settings.UPLOAD_URL_TTL_SECONDS
        return Response(
            {
                "file_id": str(file.id),
                "upload_url": storage.presign_put(file.storage_key, ttl),
                "method": "PUT",
                "headers": {"Content-Type": storage.OCTET_STREAM},
                "expires_in": ttl,
            },
            status=status.HTTP_201_CREATED,
        )


class FileCompleteView(APIView):
    """Step 2 of upload: verify what actually landed in B2 before trusting it."""

    permission_classes = SenderPermissions
    throttle_classes = [GlobalIPThrottle, UploadThrottle]
    def post(self, request, pk):
        file = File.objects.filter(pk=pk, owner=request.user).first()
        if file is None or file.status == File.Status.DELETED:
            return Response({"detail": "not_found"}, status=status.HTTP_404_NOT_FOUND)
        if file.status == File.Status.READY:
            return Response({"file_id": str(file.pk), "status": file.status, "size": file.size_bytes})

        actual = storage.head_size(file.storage_key)
        if actual is None:
            return Response({"detail": "upload_missing"}, status=status.HTTP_400_BAD_REQUEST)
        if actual > settings.MAX_UPLOAD_BYTES:
            services.delete_file_object(file)
            return Response({"detail": "file_too_large"}, status=status.HTTP_400_BAD_REQUEST)

        file.size_bytes = actual
        file.status = File.Status.READY
        file.save(update_fields=["size_bytes", "status"])
        return Response({"file_id": str(file.pk), "status": file.status, "size": actual})


class LinkPagination(PageNumberPagination):
    """Adds dashboard card stats next to the page of results."""

    def get_paginated_response(self, data):
        response = super().get_paginated_response(data)
        response.data["stats"] = getattr(self, "stats", {})
        return response


class LinkListCreateView(generics.ListCreateAPIView):
    permission_classes = SenderPermissions
    pagination_class = LinkPagination

    def get_serializer_class(self):
        return LinkCreateSerializer if self.request.method == "POST" else ShareLinkSerializer

    def get_queryset(self):
        return ShareLink.objects.filter(file__owner=self.request.user).select_related("file")

    def list(self, request, *args, **kwargs):
        now = timezone.now()
        queryset = self.get_queryset()

        stats = queryset.aggregate(
            total=Count("pk"),
            active=Count("pk", filter=services.status_q(ShareLink.Status.ACTIVE, now)),
            used=Count("pk", filter=services.status_q(ShareLink.Status.USED, now)),
            expired=Count("pk", filter=services.status_q(ShareLink.Status.EXPIRED, now)),
            revoked=Count("pk", filter=services.status_q(ShareLink.Status.REVOKED, now)),
            total_claims=Sum("download_count"),
        )
        stats["total_claims"] = stats["total_claims"] or 0

        wanted = request.query_params.get("status")
        if wanted:
            if wanted not in ShareLink.Status.values:
                return Response({"status": "invalid_status"}, status=status.HTTP_400_BAD_REQUEST)
            queryset = queryset.filter(services.status_q(wanted, now))

        paginator = self.paginator
        paginator.stats = stats
        page = paginator.paginate_queryset(queryset.order_by("-created_at"), request, view=self)
        data = ShareLinkSerializer(page, many=True).data
        return paginator.get_paginated_response(data)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = LinkCreateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        # Lock the file row so two simultaneous requests can't both create a link.
        File.objects.select_for_update().get(pk=serializer.validated_data["file"].pk)
        if ShareLink.objects.filter(file=serializer.validated_data["file"]).exists():
            return Response({"file_id": ["file_already_has_link"]}, status=status.HTTP_400_BAD_REQUEST)
        link = ShareLink.objects.create(**serializer.to_link_kwargs(timezone.now()))
        services.log_event(link, AuditEvent.Type.LINK_CREATED, request)
        return Response(ShareLinkSerializer(link).data, status=status.HTTP_201_CREATED)


class _OwnedLinkMixin:
    permission_classes = SenderPermissions

    def get_link(self, request, pk):
        return (
            ShareLink.objects.select_related("file")
            .filter(pk=pk, file__owner=request.user)
            .first()
        )


class LinkDetailView(_OwnedLinkMixin, APIView):
    def get(self, request, pk):
        link = self.get_link(request, pk)
        if link is None:
            return Response({"detail": "not_found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(ShareLinkSerializer(link).data)


class LinkEventsView(_OwnedLinkMixin, generics.ListAPIView):
    serializer_class = AuditEventSerializer

    def get_queryset(self):
        return AuditEvent.objects.filter(
            link_id=self.kwargs["pk"], link__file__owner=self.request.user
        )


class LinkRevokeView(_OwnedLinkMixin, APIView):
    def post(self, request, pk):
        link = self.get_link(request, pk)
        if link is None:
            return Response({"detail": "not_found"}, status=status.HTTP_404_NOT_FOUND)
        services.revoke_link(link, request)
        return Response(ShareLinkSerializer(link).data)
