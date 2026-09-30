class LinkGone(Exception):
    """Link can't be used. reason is 'expired' or 'unavailable' (revoked/used/unknown)."""

    def __init__(self, reason="unavailable"):
        self.reason = reason


class PasswordRequired(Exception):
    pass


class WrongPassword(Exception):
    def __init__(self, attempts_left):
        self.attempts_left = attempts_left


class LinkLocked(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after
