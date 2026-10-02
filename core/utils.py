import ipaddress

from django.conf import settings


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip(request):
    """Best available client IP for audit logs and rate limiting.

    1. If CLIENT_IP_HEADER is set (e.g. "CF-Connecting-IP"), trust that header. It is
       written by the edge proxy and holds a single address. Use it only when the app is
       reachable solely through that proxy, as on Render.
    2. Otherwise trust exactly TRUSTED_PROXY_COUNT proxies: the client is the Nth entry
       from the right of X-Forwarded-For (anything to its left is client-controlled).
    3. Otherwise fall back to the socket address.
    """
    header = settings.CLIENT_IP_HEADER
    if header:
        meta_key = "HTTP_" + header.upper().replace("-", "_")
        value = request.META.get(meta_key, "").strip()
        if value and _valid_ip(value):
            return value

    remote = request.META.get("REMOTE_ADDR", "")
    proxies = settings.TRUSTED_PROXY_COUNT
    if proxies > 0:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= proxies and _valid_ip(parts[-proxies]):
            return parts[-proxies]
    return remote


def rate_limit_ident(ip):
    """Bucket key for throttling. IPv6 users hold whole /64s, so a single address would let
    one person rotate through billions of identities; bucket them by /64 instead."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip or "unknown"
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


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
