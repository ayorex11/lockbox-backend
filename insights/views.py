"""Staff-only, read-only endpoints behind the admin dashboard."""

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.permissions import IsStaffUser
from core.throttles import AdminThrottle, GlobalIPThrottle

from . import queries


class AdminAPIView(APIView):
    permission_classes = [IsAuthenticated, IsStaffUser]
    throttle_classes = [GlobalIPThrottle, AdminThrottle]


class OverviewView(AdminAPIView):
    def get(self, request):
        return Response(queries.overview())


class TimeseriesView(AdminAPIView):
    def get(self, request):
        return Response(queries.timeseries(request.query_params.get("days")))


class TopUsersView(AdminAPIView):
    def get(self, request):
        metric = request.query_params.get("metric", "links")
        if metric not in queries.TOP_METRICS:
            return Response({"detail": "invalid_metric"}, status=400)
        try:
            limit = int(request.query_params.get("limit", 10))
        except ValueError:
            limit = 10
        return Response(queries.top_users(metric, limit))


class SecurityView(AdminAPIView):
    def get(self, request):
        return Response(queries.security())
