from rest_framework.permissions import BasePermission


class IsVerifiedUser(BasePermission):
    """Authenticated, active, and email-verified (required for all sender endpoints)."""

    message = "email_not_verified"

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user and user.is_authenticated and user.is_active and user.is_email_verified
        )
