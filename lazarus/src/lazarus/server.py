"""Inbound webhook server (stdlib only).

Routes:
  POST /webhooks/twilio/sms   Twilio inbound SMS; X-Twilio-Signature verified against LAZARUS_PUBLIC_URL
  POST /webhooks/inbound      generic JSON {"channel","from","body","id"} with X-Lazarus-Signature
  GET  /healthz

Binds 127.0.0.1 by default. Put it behind a TLS-terminating reverse proxy (or a
tunnel) and set the public URL so signatures validate; never expose it with
signature checks disabled.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .channels.twilio import verify_twilio_signature
from .engine import Engine
from .webhooks import verify

MAX_BODY = 64 * 1024
TWIML_EMPTY = b'<?xml version="1.0" encoding="UTF-8"?><Response></Response>'


class RateLimiter:
    def __init__(self, rate: float = 10.0, burst: int = 40) -> None:
        self.rate, self.burst = rate, burst
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._b.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._b[key] = (tokens, now)
                return False
            self._b[key] = (tokens - 1, now)
            if len(self._b) > 10_000:
                self._b.clear()
            return True


def make_server(engine_factory: Callable[[], Engine], host: str = "127.0.0.1", port: int = 8787,
                public_url: str | None = None, twilio_auth_token: str | None = None,
                inbound_secret: str | None = None, limiter: RateLimiter | None = None) -> ThreadingHTTPServer:
    local = threading.local()
    lim = limiter or RateLimiter()

    def engine() -> Engine:
        if not hasattr(local, "engine"):
            local.engine = engine_factory()  # one SQLite connection per handler thread
        e: Engine = local.engine
        return e

    class Handler(BaseHTTPRequestHandler):
        server_version = "lazarus"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            pass  # no request logging by default: bodies and numbers are PII

        def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: dict[str, Any]) -> None:
            self._send(code, json.dumps(obj).encode())

        def do_GET(self) -> None:
            if self.path == "/healthz":
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if not lim.allow(self.client_address[0]):
                return self._json(429, {"error": "rate_limited"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._json(400, {"error": "bad_length"})
            if length < 0 or length > MAX_BODY:
                return self._json(413, {"error": "too_large"})
            raw = self.rfile.read(length)
            path = self.path.split("?", 1)[0]
            try:
                if path == "/webhooks/twilio/sms":
                    return self._twilio(raw)
                if path == "/webhooks/inbound":
                    return self._generic(raw)
            except Exception:  # noqa: BLE001 - never leak internals; provider will retry on 5xx
                return self._json(500, {"error": "internal"})
            return self._json(404, {"error": "not_found"})

        def _twilio(self, raw: bytes) -> None:
            if not twilio_auth_token or not public_url:
                return self._json(503, {"error": "twilio_not_configured"})
            try:
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                                                                 strict_parsing=False).items()}
            except UnicodeDecodeError:
                return self._json(400, {"error": "bad_encoding"})
            url = public_url.rstrip("/") + self.path
            if not verify_twilio_signature(twilio_auth_token, url, form, self.headers.get("X-Twilio-Signature")):
                return self._json(403, {"error": "bad_signature"})
            frm, body, sid = form.get("From"), form.get("Body", ""), form.get("MessageSid")
            if not frm or not sid:
                return self._json(400, {"error": "missing_fields"})
            engine().handle_inbound("sms", frm, body, provider_id=sid)
            return self._send(200, TWIML_EMPTY, "text/xml")

        def _generic(self, raw: bytes) -> None:
            if not inbound_secret:
                return self._json(503, {"error": "inbound_not_configured"})
            if not verify(inbound_secret, raw, self.headers.get("X-Lazarus-Signature")):
                return self._json(403, {"error": "bad_signature"})
            try:
                data = json.loads(raw)
                channel, frm, body, pid = data["channel"], data["from"], data["body"], data["id"]
            except (json.JSONDecodeError, KeyError, TypeError):
                return self._json(400, {"error": "bad_payload"})
            if channel not in ("sms", "email") or not all(isinstance(x, str) for x in (frm, body, pid)):
                return self._json(400, {"error": "bad_payload"})
            res = engine().handle_inbound(channel, frm, body, provider_id=f"generic:{pid}")
            return self._json(200, {"label": res["label"], "duplicate": res["duplicate"]})

    return ThreadingHTTPServer((host, port), Handler)
