"""Signed JSON webhooks: outbound CRM handoff sink + inbound verification.

Signature header: ``X-Lazarus-Signature: t=<unix>,v1=<hex hmac_sha256(secret, f"{t}.{body}")>``.
Receivers must check the timestamp is recent (replay protection) and compare
in constant time — ``verify`` does both.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from .channels.http import Transport, urllib_transport


def sign(secret: str, body: bytes, t: int | None = None) -> str:
    t = int(time.time()) if t is None else t
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def verify(secret: str, body: bytes, header: str | None, tolerance_s: int = 300, now: int | None = None) -> bool:
    if not header or not secret:
        return False
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    try:
        t = int(parts["t"])
    except (KeyError, ValueError):
        return False
    now = int(time.time()) if now is None else now
    if abs(now - t) > tolerance_s:
        return False
    expected = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


class WebhookSink:
    """Engine sink that POSTs handoffs to a CRM/automation URL (Zapier, n8n, HubSpot workflow, ...)."""

    def __init__(self, url: str, secret: str, transport: Transport = urllib_transport, timeout: float = 10.0) -> None:
        if not secret or len(secret) < 16:
            raise ValueError("webhook secret must be at least 16 characters")
        self.url = url
        self.secret = secret
        self.transport = transport
        self.timeout = timeout

    def __call__(self, kind: str, payload: dict[str, Any]) -> None:
        body = json.dumps({"kind": kind, **payload}, sort_keys=True).encode()
        headers = {"Content-Type": "application/json", "X-Lazarus-Signature": sign(self.secret, body),
                   "Idempotency-Key": f"{kind}:{payload.get('inbound_id', '')}"}
        status, _, resp = self.transport("POST", self.url, headers, body, self.timeout)
        if not 200 <= status < 300:
            raise RuntimeError(f"sink returned HTTP {status}: {resp[:200]!r}")
