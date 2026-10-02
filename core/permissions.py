from rest_framework.permissions import BasePermission


class IsVerifiedUser(BasePermission):
    """Authenticated, active, and email-verified (required for all sender endpoints)."""

    message = "email_not_verified"

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user and user.is_authenticated and user.is_active and user.is_email_verified
        )


class IsStaffUser(BasePermission):
    """Admin-dashboard access: active, email-verified staff only.

    Checked against the database user on every request (DRF loads the user from
    the token's id), so removing is_staff takes effect immediately.
    """

    message = "staff_only"

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and user.is_staff
            and user.is_email_verified
        )
