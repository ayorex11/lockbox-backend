from rest_framework.throttling import SimpleRateThrottle

from .utils import get_client_ip, rate_limit_ident


class IPThrottle(SimpleRateThrottle):
    """Rate limit per client IP (using the proxy-aware IP), one bucket per scope."""

    scope = None

    def get_ident(self, request):
        return rate_limit_ident(get_client_ip(request))

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}


class GlobalIPThrottle(IPThrottle):
    scope = "global"


class RegisterThrottle(IPThrottle):
    scope = "register"


class LoginThrottle(IPThrottle):
    scope = "login"


class ResendThrottle(IPThrottle):
    scope = "resend"


class RefreshThrottle(IPThrottle):
    scope = "refresh"


class MetaThrottle(IPThrottle):
    scope = "meta"


class ClaimIPThrottle(IPThrottle):
    scope = "claim"


class UploadThrottle(IPThrottle):
    scope = "upload"


class AdminThrottle(IPThrottle):
    scope = "admin"


class ClaimTokenThrottle(SimpleRateThrottle):
    """Caps claim attempts per link regardless of how many IPs the attacker uses."""

    scope = "claim_token"

    def get_cache_key(self, request, view):
        token = view.kwargs.get("token", "")
        return self.cache_format % {"scope": self.scope, "ident": token}
