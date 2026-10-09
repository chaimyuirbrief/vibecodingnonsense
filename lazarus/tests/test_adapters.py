import json
import smtplib
import threading
import urllib.parse
import urllib.request
from collections.abc import Iterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any, ClassVar

import pytest

from lazarus.channels import Outbound
from lazarus.channels.fake import RecordingTransport
from lazarus.channels.smtp import SMTPEmail
from lazarus.channels.twilio import TwilioSMS, twilio_signature, verify_twilio_signature
from lazarus.engine import Engine
from lazarus.llm import AnthropicProvider, BudgetedProvider, CachingProvider, FakeLLM
from lazarus.server import RateLimiter, make_server
from lazarus.store import Store
from lazarus.webhooks import WebhookSink, sign, verify

from .conftest import add_lead, make_campaign

MSG = Outbound("m1", "enr:0:0", "sms", "+14045552368", "hello")


# ------------------------------------------------------------------ Twilio

def test_twilio_signature_matches_official_vector() -> None:
    # Vector from twilio-python tests/unit/test_request_validator.py
    params = {"CallSid": "CA1234567890ABCDE", "Digits": "1234", "From": "+14158675309", "To": "+18005551212",
              "Caller": "+14158675309"}
    url = "https://mycompany.com/myapp.php?foo=1&bar=2"
    assert twilio_signature("12345", url, params) == "RSOYDt4T1cUTdK1PDd93/VVr8B8="
    assert verify_twilio_signature("12345", url, params, "RSOYDt4T1cUTdK1PDd93/VVr8B8=")
    assert not verify_twilio_signature("12345", url, {**params, "Digits": "9"}, "RSOYDt4T1cUTdK1PDd93/VVr8B8=")
    assert not verify_twilio_signature("12345", url, params, None)
    assert not verify_twilio_signature("", url, params, "x")


@pytest.mark.parametrize("status,body,headers_outcome", [
    (201, '{"sid": "SM123"}', ("sent", False)),
    (429, '{"code": 20429}', ("transient", False)),
    (503, "", ("transient", False)),
    (400, '{"code": 21610, "message": "unsubscribed"}', ("permanent", True)),
    (400, '{"code": 21211, "message": "invalid To"}', ("permanent", True)),
    (400, '{"code": 21408, "message": "region"}', ("permanent", False)),
    (201, "{}", ("ambiguous", False)),
    (-1, "", ("ambiguous", False)),   # timeout after request was sent
    (-2, "", ("transient", False)),   # connection refused before sending
])
def test_twilio_send_outcomes(status: int, body: str, headers_outcome: tuple[str, bool]) -> None:
    tr = RecordingTransport([(status, body)])
    res = TwilioSMS("AC1", "tok", from_number="+15550001111", transport=tr).send(MSG)
    assert (res.outcome, res.suppress) == headers_outcome
    if tr.requests:
        method, url, headers, payload = tr.requests[0]
        assert method == "POST" and url.endswith("/Accounts/AC1/Messages.json")
        assert headers["Authorization"].startswith("Basic ")
        assert urllib.parse.parse_qs(payload.decode()) == {"To": ["+14045552368"], "Body": ["hello"], "From": ["+15550001111"]}


def test_twilio_lookup_is_honest() -> None:
    assert TwilioSMS("AC1", "t", from_number="+1").lookup("k") is None


# ------------------------------------------------------------------ SMTP

class FakeSMTP:
    instances: ClassVar[list["FakeSMTP"]] = []
    mode = "ok"

    def __init__(self, host: str, port: int, timeout: float) -> None:
        if FakeSMTP.mode == "connect_fail":
            raise ConnectionRefusedError("nope")
        self.sent: list[EmailMessage] = []
        FakeSMTP.instances.append(self)

    def starttls(self) -> None:
        if FakeSMTP.mode == "drop_handshake":
            raise smtplib.SMTPServerDisconnected("bye")

    def login(self, u: str, p: str) -> None: ...

    def send_message(self, m: EmailMessage) -> dict[str, Any]:
        if FakeSMTP.mode == "refused":
            raise smtplib.SMTPRecipientsRefused({m["To"]: (550, b"no such user")})
        if FakeSMTP.mode == "drop_data":
            raise TimeoutError("timed out")
        if FakeSMTP.mode == "busy":
            raise smtplib.SMTPResponseException(451, b"try later")
        self.sent.append(m)
        return {}

    def quit(self) -> None: ...


@pytest.mark.parametrize("mode,outcome,suppress", [
    ("ok", "sent", False), ("refused", "permanent", True), ("drop_data", "ambiguous", False),
    ("drop_handshake", "transient", False), ("busy", "transient", False), ("connect_fail", "transient", False),
])
def test_smtp_outcomes(mode: str, outcome: str, suppress: bool) -> None:
    FakeSMTP.mode = mode
    ch = SMTPEmail("smtp.example", 587, "u", "p", "mike@brightside.example", "unsub@brightside.example",
                   unsubscribe_url="https://brightside.example/u", smtp_factory=FakeSMTP)
    res = ch.send(Outbound("m1", "enr:0:0", "email", "dana@example.com", "Hi", "Subject"))
    assert (res.outcome, res.suppress) == (outcome, suppress)
    if mode == "ok":
        m = FakeSMTP.instances[-1].sent[0]
        import hashlib
        assert m["Message-ID"] == f"<{hashlib.sha256(b'enr:0:0').hexdigest()[:40]}@brightside.example>"
        assert "mailto:unsub@brightside.example" in m["List-Unsubscribe"]
        assert m["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"


# ------------------------------------------------------------------ signed webhooks

def test_hmac_sign_verify_and_replay_window() -> None:
    body = b'{"x":1}'
    h = sign("s" * 32, body, t=1_000_000)
    assert verify("s" * 32, body, h, now=1_000_100)
    assert not verify("s" * 32, body, h, now=1_000_400)       # stale -> replay rejected
    assert not verify("s" * 32, body + b" ", h, now=1_000_100)  # tampered
    assert not verify("t" * 32, body, h, now=1_000_100)        # wrong secret
    assert not verify("s" * 32, body, "garbage", now=1_000_100)


def test_webhook_sink_posts_signed_json() -> None:
    tr = RecordingTransport([(200, "ok"), (500, "down")])
    sink = WebhookSink("https://crm.example/hook", "x" * 20, transport=tr)
    sink("handoff", {"inbound_id": "in_1", "lead": {"id": "l"}})
    _, _, headers, body = tr.requests[0]
    assert verify("x" * 20, body, headers["X-Lazarus-Signature"])
    assert json.loads(body)["kind"] == "handoff"
    with pytest.raises(RuntimeError):
        sink("handoff", {"inbound_id": "in_2"})
    with pytest.raises(ValueError):
        WebhookSink("https://crm.example", "short")


# ------------------------------------------------------------------ Anthropic provider (real SDK, mocked HTTP)

def _sdk_client(handler: Any) -> Any:
    import anthropic
    import httpx2

    return anthropic.Anthropic(api_key="test-key", base_url="https://api.anthropic.test", max_retries=0,
                               http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)))


SCHEMA = {"type": "object", "properties": {"label": {"type": "string"}}, "required": ["label"], "additionalProperties": False}


def _msg(text: str, stop: str = "end_turn") -> dict[str, Any]:
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
            "content": [{"type": "text", "text": text}], "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 10}}


def test_anthropic_request_shape_and_parse() -> None:
    import httpx2

    seen: dict[str, Any] = {}

    def handler(req: httpx2.Request) -> httpx2.Response:
        seen["url"] = str(req.url)
        seen["headers"] = dict(req.headers)
        seen["body"] = json.loads(req.content)
        return httpx2.Response(200, json=_msg('{"label": "interested"}'))

    p = AnthropicProvider(client=_sdk_client(handler))
    res = p.complete_json(purpose="classify", system="sys", user="hi", schema=SCHEMA, max_tokens=256)
    assert res.data == {"label": "interested"} and res.error is None
    assert res.cost_usd == pytest.approx((100 * 4 + 10 * 20) / 1e6)
    b = seen["body"]
    assert seen["url"].endswith("/v1/messages?beta=true") or seen["url"].endswith("/v1/messages")
    assert b["model"] == "claude-opus-5-5"
    assert b["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert b["output_config"]["effort"] == "low"
    assert b["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in seen["headers"].get("anthropic-beta", "")
    assert "tool_choice" not in b and "thinking" not in b  # forced tool use / disabled thinking are 400s on this model
    assert b["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_anthropic_haiku_has_no_fallbacks() -> None:
    import httpx2

    seen: dict[str, Any] = {}

    def handler(req: httpx2.Request) -> httpx2.Response:
        seen["body"] = json.loads(req.content)
        return httpx2.Response(200, json=_msg('{"label": "x"}'))

    AnthropicProvider(model="claude-haiku-5-5", client=_sdk_client(handler)).complete_json(
        purpose="classify", system="s", user="u", schema=SCHEMA, max_tokens=64)
    assert "fallbacks" not in seen["body"]


@pytest.mark.parametrize("status,payload,err", [
    (200, _msg("", "refusal"), "refusal"),
    (200, _msg('{"label": "x"', "max_tokens"), "truncated"),
    (200, _msg("not json"), "invalid_json"),
    (200, _msg("[1,2]"), "not_an_object"),
    (429, {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}, "rate_limited"),
    (529, {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}, "api_error_529"),
    (400, {"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}}, "api_error_400"),
])
def test_anthropic_failure_modes(status: int, payload: dict[str, Any], err: str) -> None:
    import httpx2

    p = AnthropicProvider(client=_sdk_client(lambda req: httpx2.Response(status, json=payload)))
    res = p.complete_json(purpose="classify", system="s", user="u", schema=SCHEMA, max_tokens=64)
    assert res.data is None and res.error == err


def test_anthropic_connection_error() -> None:
    import httpx2

    def handler(req: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("down")

    res = AnthropicProvider(client=_sdk_client(handler)).complete_json(
        purpose="c", system="s", user="u", schema=SCHEMA, max_tokens=8)
    assert res.error == "connection_error"


def test_budget_and_cache(tmp_path: Path) -> None:
    st = Store(tmp_path / "b.db")
    calls = {"n": 0}

    def h(p: str, s: str, u: str) -> dict[str, Any]:
        calls["n"] += 1
        return {"label": "unclear", "possible_opt_out": False, "confidence": "high"}

    inner = FakeLLM(h, model="claude-opus-5-5")
    budget = BudgetedProvider(inner, max_usd=1.0, max_calls=2, store=st)
    cached = CachingProvider(budget, st)
    for _ in range(3):
        cached.complete_json(purpose="classify", system="s", user="same", schema=SCHEMA, max_tokens=8)
    assert calls["n"] == 1  # cache hit after first call
    cached.complete_json(purpose="classify", system="s", user="other", schema=SCHEMA, max_tokens=8)
    res = cached.complete_json(purpose="classify", system="s", user="third", schema=SCHEMA, max_tokens=8)
    assert res.error == "budget_exceeded" and calls["n"] == 2
    assert st.conn.execute("SELECT COUNT(*) FROM llm_usage").fetchone()[0] == 2


# ------------------------------------------------------------------ HTTP server

@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    db = tmp_path / "srv.db"
    st = Store(db)
    st.save_campaign(make_campaign())
    add_lead(st)
    Engine(st, {}).enroll("test")
    st.close()
    srv = make_server(lambda: Engine(Store(db), {}), host="127.0.0.1", port=0, public_url="https://lazarus.example",
                      twilio_auth_token="tok", inbound_secret="s" * 32, limiter=RateLimiter(rate=1000, burst=1000))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", db
    srv.shutdown()
    srv.server_close()


def _post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_server_twilio_inbound(server: tuple[str, Path]) -> None:
    base, db = server
    form = {"From": "+14045552368", "Body": "STOP", "MessageSid": "SM1", "To": "+15550001111"}
    sig = twilio_signature("tok", "https://lazarus.example/webhooks/twilio/sms", form)
    body = urllib.parse.urlencode(form).encode()
    code, out = _post(base + "/webhooks/twilio/sms", body, {"X-Twilio-Signature": sig, "Content-Type": "application/x-www-form-urlencoded"})
    assert code == 200 and b"<Response>" in out
    code, _ = _post(base + "/webhooks/twilio/sms", body, {"X-Twilio-Signature": "bad"})
    assert code == 403
    st = Store(db)
    assert st.is_suppressed("+14045552368") == "opt_out"


def test_server_generic_inbound_and_limits(server: tuple[str, Path]) -> None:
    base, _ = server
    body = json.dumps({"channel": "sms", "from": "+14045552368", "body": "yes how much", "id": "g1"}).encode()
    code, out = _post(base + "/webhooks/inbound", body, {"X-Lazarus-Signature": sign("s" * 32, body)})
    assert code == 200 and json.loads(out)["label"] == "interested"
    code, out = _post(base + "/webhooks/inbound", body, {"X-Lazarus-Signature": sign("s" * 32, body)})
    assert json.loads(out)["duplicate"] is True
    assert _post(base + "/webhooks/inbound", body, {"X-Lazarus-Signature": sign("s" * 32, body, t=1)})[0] == 403
    bad = b'{"channel": "fax"}'
    assert _post(base + "/webhooks/inbound", bad, {"X-Lazarus-Signature": sign("s" * 32, bad)})[0] == 400
    assert _post(base + "/webhooks/inbound", b"x" * (70 * 1024), {})[0] == 413
    assert _post(base + "/nope", b"", {})[0] == 404
    with urllib.request.urlopen(base + "/healthz", timeout=5) as r:
        assert json.loads(r.read()) == {"ok": True}


def test_rate_limiter() -> None:
    rl = RateLimiter(rate=0.0001, burst=3)
    assert [rl.allow("ip") for _ in range(5)] == [True, True, True, False, False]
    assert rl.allow("other")
