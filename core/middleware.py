class NoStoreAPIMiddleware:
    """Never let browsers or proxies cache API responses (links, claims, tokens)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith(("/api/", "/internal/")):
            response["Cache-Control"] = "no-store"
        return response
