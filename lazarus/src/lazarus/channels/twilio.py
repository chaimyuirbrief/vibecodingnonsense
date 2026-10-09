"""Twilio Programmable Messaging adapter (SMS out) and webhook signature check (SMS in).

NOT live-tested in this repository (no Twilio credentials were available).
Request shape and error-code mapping follow Twilio's public REST docs; the
signature algorithm is verified against Twilio's published example in tests.
Verify against your account before production use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.parse
from collections.abc import Mapping

from . import Outbound, SendResult
from .http import Transport, TransportConnectError, TransportTimeout, urllib_transport

# Twilio REST error codes that mean "this destination will never work" -> suppress.
SUPPRESS_CODES = {
    21211,  # invalid 'To' phone number
    21610,  # recipient has replied STOP at the carrier/Twilio level
    21614,  # 'To' is not a valid mobile number
}


class TwilioSMS:
    name = "sms"

    def __init__(self, account_sid: str, auth_token: str, from_number: str | None = None,
                 messaging_service_sid: str | None = None, status_callback: str | None = None,
                 transport: Transport = urllib_transport, timeout: float = 15.0) -> None:
        if not (from_number or messaging_service_sid):
            raise ValueError("need from_number or messaging_service_sid")
        self.sid = account_sid
        self._auth = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()
        self.from_number = from_number
        self.mss = messaging_service_sid
        self.status_callback = status_callback
        self.transport = transport
        self.timeout = timeout

    def send(self, msg: Outbound) -> SendResult:
        form = {"To": msg.to, "Body": msg.body}
        if self.mss:
            form["MessagingServiceSid"] = self.mss
        else:
            assert self.from_number
            form["From"] = self.from_number
        if self.status_callback:
            form["StatusCallback"] = self.status_callback
        url = f"https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(self.sid)}/Messages.json"
        headers = {"Authorization": f"Basic {self._auth}", "Content-Type": "application/x-www-form-urlencoded"}
        try:
            status, hdrs, body = self.transport("POST", url, headers, urllib.parse.urlencode(form).encode(), self.timeout)
        except TransportTimeout as e:
            return SendResult("ambiguous", error=f"timeout: {e}")
        except TransportConnectError as e:
            return SendResult("transient", error=f"connect: {e}")
        try:
            data = json.loads(body or b"{}")
        except json.JSONDecodeError:
            data = {}
        if status in (200, 201) and data.get("sid"):
            return SendResult("sent", provider_id=str(data["sid"]))
        if status in (200, 201):
            return SendResult("ambiguous", error="2xx without sid")
        if status == 429 or status >= 500:
            ra = hdrs.get("Retry-After") or hdrs.get("retry-after")
            return SendResult("transient", error=f"http {status}", retry_after_s=float(ra) if ra and ra.isdigit() else None)
        code = data.get("code")
        return SendResult("permanent", error=f"http {status} code {code}: {str(data.get('message', ''))[:200]}",
                          suppress=isinstance(code, int) and code in SUPPRESS_CODES)

    def lookup(self, idempotency_key: str) -> SendResult | None:
        # Twilio's Messages API has no client idempotency key to query by, so an
        # ambiguous send cannot be resolved automatically. A human checks the console.
        return None


def twilio_signature(auth_token: str, url: str, params: Mapping[str, str]) -> str:
    """X-Twilio-Signature: base64(HMAC-SHA1(token, url + concat(sorted k+v)))."""
    data = url + "".join(k + params[k] for k in sorted(params))
    digest = hmac.new(auth_token.encode(), data.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def verify_twilio_signature(auth_token: str, url: str, params: Mapping[str, str], signature: str | None) -> bool:
    if not signature or not auth_token:
        return False
    return hmac.compare_digest(twilio_signature(auth_token, url, params), signature)
