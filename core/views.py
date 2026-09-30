import hmac

from django.conf import settings
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from vault.services import run_cleanup


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
