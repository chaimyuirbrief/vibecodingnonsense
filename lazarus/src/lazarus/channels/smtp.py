"""SMTP email adapter. NOT live-tested here (no mail server credentials);
covered by tests with an injected fake SMTP client."""

from __future__ import annotations

import hashlib
import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any

from . import Outbound, SendResult


class SMTPEmail:
    name = "email"

    def __init__(self, host: str, port: int, username: str | None, password: str | None, from_addr: str,
                 unsubscribe_mailto: str, unsubscribe_url: str | None = None, starttls: bool = True,
                 timeout: float = 20.0, smtp_factory: Callable[..., Any] = smtplib.SMTP) -> None:
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.from_addr = from_addr
        self.unsub_mailto = unsubscribe_mailto
        self.unsub_url = unsubscribe_url
        self.starttls = starttls
        self.timeout = timeout
        self.factory = smtp_factory
        self.domain = from_addr.rsplit("@", 1)[-1]

    def build(self, msg: Outbound) -> EmailMessage:
        em = EmailMessage()
        em["From"] = self.from_addr
        em["To"] = msg.to
        em["Subject"] = msg.subject or ""
        em["Date"] = formatdate(localtime=False)
        # Deterministic Message-ID: a retried send carries the same id, so receiving
        # systems that dedupe on Message-ID will collapse duplicates.
        # (hashed: idempotency keys contain ':' which is not legal in an RFC 5322 msg-id)
        em["Message-ID"] = f"<{hashlib.sha256(msg.idempotency_key.encode()).hexdigest()[:40]}@{self.domain}>"
        unsub = [f"<mailto:{self.unsub_mailto}?subject=unsubscribe>"]
        if self.unsub_url:
            unsub.insert(0, f"<{self.unsub_url}>")
            em["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        em["List-Unsubscribe"] = ", ".join(unsub)
        em.set_content(msg.body)
        return em

    def send(self, msg: Outbound) -> SendResult:
        em = self.build(msg)
        try:
            client = self.factory(self.host, self.port, timeout=self.timeout)
        except (OSError, smtplib.SMTPException) as e:
            return SendResult("transient", error=f"connect: {e}")
        stage = "handshake"
        try:
            if self.starttls:
                client.starttls(context=ssl.create_default_context())  # verify cert + hostname
            if self.username and self.password:
                client.login(self.username, self.password)
            stage = "data"
            refused = client.send_message(em)
            if refused:
                return SendResult("permanent", error=f"refused: {refused}", suppress=True)
            return SendResult("sent", provider_id=em["Message-ID"])
        except smtplib.SMTPRecipientsRefused as e:
            return SendResult("permanent", error=f"recipients refused: {e.recipients}", suppress=True)
        except smtplib.SMTPAuthenticationError as e:
            return SendResult("transient", error=f"auth: {e.smtp_code}")  # config problem; don't burn the address
        except smtplib.SMTPResponseException as e:
            if 400 <= e.smtp_code < 500:
                return SendResult("transient", error=f"smtp {e.smtp_code}")
            return SendResult("permanent", error=f"smtp {e.smtp_code}")
        except (smtplib.SMTPServerDisconnected, TimeoutError, OSError) as e:
            if stage == "handshake":
                return SendResult("transient", error=f"disconnected before DATA: {e}")
            return SendResult("ambiguous", error=f"disconnected mid-send: {e}")
        finally:
            try:
                client.quit()
            except Exception:  # noqa: BLE001, S110 - best effort close
                pass

    def lookup(self, idempotency_key: str) -> SendResult | None:
        return None
