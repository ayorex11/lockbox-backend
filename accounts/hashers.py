from django.contrib.auth.hashers import Argon2PasswordHasher


class LockboxArgon2PasswordHasher(Argon2PasswordHasher):
    """Argon2id with OWASP's minimum recommended parameters (19 MiB, t=2, p=1).

    Django's default (100 MiB per hash) would let a handful of concurrent logins or
    password-protected claims exhaust a 512 MB free-tier instance. Existing hashes
    with other parameters are upgraded automatically on next successful check.
    """

    time_cost = 2
    memory_cost = 19456  # KiB
    parallelism = 1
