import json
import logging
import urllib.request
from email.utils import parseaddr

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend

logger = logging.getLogger(__name__)


class BrevoAPIEmailBackend(BaseEmailBackend):
    """Send mail through Brevo's transactional HTTPS API (port 443).

    Render's free web services block outbound SMTP (25/465/587), so SMTP relays time
    out there. Enabled automatically when BREVO_API_KEY is set. The sender address in
    DEFAULT_FROM_EMAIL must be a verified sender in Brevo.
    """

    endpoint = "https://api.brevo.com/v3/smtp/email"

    def send_messages(self, email_messages):
        sent = 0
        for message in email_messages:
            name, address = parseaddr(message.from_email)
            sender = {"email": address}
            if name:
                sender["name"] = name
            payload = {
                "sender": sender,
                "to": [{"email": recipient} for recipient in message.to],
                "subject": message.subject,
                "textContent": message.body,
            }
            request = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "api-key": settings.BREVO_API_KEY,
                    "content-type": "application/json",
                    "accept": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    if 200 <= response.status < 300:
                        sent += 1
            except Exception:  # noqa: BLE001
                logger.exception("Brevo API send failed")
                if not self.fail_silently:
                    raise
        return sent