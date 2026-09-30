import ipaddress

from django.conf import settings


def get_client_ip(request):
    """Return the client IP, trusting exactly TRUSTED_PROXY_COUNT proxies.

    With N trusted proxies, the client is the Nth entry from the right of
    X-Forwarded-For (anything to its left is client-controlled and spoofable).
    """
    remote = request.META.get("REMOTE_ADDR", "")
    proxies = settings.TRUSTED_PROXY_COUNT
    if proxies > 0:
        header = request.META.get("HTTP_X_FORWARDED_FOR", "")
        parts = [p.strip() for p in header.split(",") if p.strip()]
        if len(parts) >= proxies:
            candidate = parts[-proxies]
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
    return remote


def truncate_ip(ip):
    """Anonymise before storing: IPv4 -> /24, IPv6 -> /48. Returns '' if unparseable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def truncate_user_agent(request, limit=200):
    return request.META.get("HTTP_USER_AGENT", "")[:limit]
