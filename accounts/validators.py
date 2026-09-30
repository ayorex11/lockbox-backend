import re

from django.core.exceptions import ValidationError


class LetterAndNumberValidator:
    """Require at least one letter and one digit (matches the signup screen's hint)."""

    def validate(self, password, user=None):
        if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
            raise ValidationError(
                "Password must contain both letters and numbers.",
                code="password_no_mix",
            )

    def get_help_text(self):
        return "Your password must contain both letters and numbers."
