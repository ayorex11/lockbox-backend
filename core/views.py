import hmac

from django.conf import settings
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from vault.services import run_cleanup

from .utils import get_client_ip, truncate_ip


@require_GET
def health(request):
    """Keep-alive target. Touches the DB so a free Supabase project also stays awake."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    return JsonResponse({"status": "ok"})


@csrf_exempt
@require_POST
def cleanup(request):
    secret = settings.CLEANUP_SECRET
    provided = request.headers.get("X-Cleanup-Secret", "")
    if not secret or not hmac.compare_digest(provided.encode(), secret.encode()):
        # 404 (not 403) so the endpoint's existence isn't advertised.
        return JsonResponse({"detail": "not_found"}, status=404)
    return JsonResponse(run_cleanup())


@require_GET
def whoami(request):
    """Diagnostic for the proxy setup: shows what the app sees and which address it picks.

    Protected by the cleanup secret (404 otherwise). Call it from your own machine, compare
    `resolved_ip` with your real public IP, and adjust CLIENT_IP_HEADER / TRUSTED_PROXY_COUNT
    until they match. It reveals only the caller's own connection details.
    """
    secret = settings.CLEANUP_SECRET
    provided = request.headers.get("X-Cleanup-Secret", "")
    if not secret or not hmac.compare_digest(provided.encode(), secret.encode()):
        return JsonResponse({"detail": "not_found"}, status=404)
    meta = request.META
    return JsonResponse(
        {
            "resolved_ip": get_client_ip(request),
            "stored_in_audit_log_as": truncate_ip(get_client_ip(request)),
            "remote_addr": meta.get("REMOTE_ADDR", ""),
            "x_forwarded_for": meta.get("HTTP_X_FORWARDED_FOR", ""),
            "cf_connecting_ip": meta.get("HTTP_CF_CONNECTING_IP", ""),
            "true_client_ip": meta.get("HTTP_TRUE_CLIENT_IP", ""),
            "client_ip_header_setting": settings.CLIENT_IP_HEADER,
            "trusted_proxy_count_setting": settings.TRUSTED_PROXY_COUNT,
        }
    )
