"""Regression tests for defects found by the adversarial review (docs/RED_TEAM.md).
Each test reproduces the reported scenario and asserts the fixed behavior."""

import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lazarus.channels import Outbound, SendResult
from lazarus.channels.fake import FakeChannel
from lazarus.engine import Engine, EngineConfig
from lazarus.ingest import import_csv
from lazarus.llm import FakeLLM
from lazarus.models import Label
from lazarus.normalize import Consent, normalize_email, normalize_sender
from lazarus.policy import check_send, lead_zones
from lazarus.replay import replay
from lazarus.store import Store
from lazarus.timeutil import FakeClock, allowed_now, canonical_zone, zone

from .conftest import add_lead, make_campaign


def test_quiet_hours_judged_at_send_time_not_batch_start(store: Store, campaign: Any, clock: FakeClock) -> None:
    """RT: one 'now' per tick let a batch starting 19:57 keep texting past 20:00 with sent_at=19:57."""
    clock.set(datetime(2026, 10, 12, 23, 50, tzinfo=UTC))  # 19:50 New York
    for i in range(10):
        add_lead(store, phone=f"+1404558{i:04d}")

    class Slow(FakeChannel):
        def send(self, msg: Outbound) -> SendResult:
            clock.advance(timedelta(minutes=2))  # each provider call takes 2 minutes
            return super().send(msg)

    ch = Slow("sms", clock=clock.now)
    e = Engine(store, {"sms": ch})
    e.enroll("test")
    e.tick()
    ny = zone("America/New_York")
    assert ny
    for d in ch.deliveries:
        assert d.at is not None and d.at.astimezone(ny).time() < datetime(2026, 1, 1, 20, 0).time()
    for r in store.conn.execute("SELECT sent_at FROM messages WHERE status='sent'"):
        assert r["sent_at"] > "2026-10-12T23:50"  # recorded at actual send time
    assert len(ch.deliveries) < 10  # the rest wait for tomorrow's window


def test_approval_gate_holds_until_n_approved(store: Store, channel: FakeChannel) -> None:
    """RT: counting drafts let message N+1 go out while the first N were still unreviewed."""
    store.save_campaign(make_campaign(id="ap", approve_first_n=3))
    for i in range(6):
        add_lead(store, phone=f"+1404559{i:04d}")
    e = Engine(store, {"sms": channel})
    e.enroll("ap")
    e.tick()
    assert channel.deliveries == []
    assert store.conn.execute("SELECT COUNT(*) FROM messages WHERE status='pending_approval'").fetchone()[0] == 6
    ids = [r["id"] for r in store.conn.execute("SELECT id FROM messages ORDER BY created_at LIMIT 3")]
    for i in ids:
        e.reject(i, "op") if i == ids[0] else e.approve(i, "op")
    assert e._needs_approval(e.campaign("ap"), "template")  # 2 approved < 3: still gated


def test_unmatched_sender_formats_still_match_or_reach_a_human(store: Store, engine: Engine) -> None:
    """RT: 'Dana <dana@x>' and '447700900123' failed to normalize, so the opt-out never reached the lead."""
    assert normalize_email("Dana Smith <Dana@Example.com>") == "dana@example.com"
    assert normalize_sender("sms", "447700900123") == "+447700900123"
    lid = add_lead(store, phone=None, email="dana@example.com")  # type: ignore[arg-type]
    engine.enroll("test")
    res = engine.handle_inbound("email", "Dana Smith <dana@example.com>", "Unsubscribe", provider_id="e1")
    assert res["label"] == "opt_out" and store.is_suppressed("dana@example.com")
    assert store.conn.execute("SELECT state FROM enrollments WHERE lead_id=?", (lid,)).fetchone()["state"] == "opted_out"
    res2 = engine.handle_inbound("sms", "garbage-sender", "STOP", provider_id="e2")
    assert "review:unmatched_opt_out" in res2["actions"]


def test_second_review_keeps_lead_paused(store: Store, channel: FakeChannel) -> None:
    """RT: resolving one flagged reply resumed outreach while a possible opt-out was still pending."""
    store.save_campaign(make_campaign(id="rv"))
    add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("rv")
    e.tick()
    a = e.handle_inbound("sms", "+14045552368", "how did you get my number", provider_id="r1")
    b = e.handle_inbound("sms", "+14045552368", "who is this?", provider_id="r2")
    assert a["needs_review"] and b["needs_review"]
    assert e.resolve_review(b["inbound_id"], Label.UNCLEAR, actor="op") == ["still_under_review"]
    store.save_campaign(make_campaign(id="rv2"))  # a second campaign must not bypass the hold either
    e.enroll("rv2")
    for _ in range(10):
        e.tick(store.clock.advance(timedelta(hours=12)))  # type: ignore[attr-defined]
    assert len(channel.deliveries) == 1


def test_timezone_abbreviations_and_regions(store: Store, campaign: Any, clock: FakeClock) -> None:
    """RT: 'EST' was accepted as fixed UTC-5; Hawaii/international numbers fell back to US mainland zones."""
    assert canonical_zone("EST") == "America/New_York" and canonical_zone("pst") == "America/Los_Angeles"
    assert canonical_zone("Asia/Tokyo") == "Asia/Tokyo" and canonical_zone("XYZ") is None
    hi = store.get_lead(add_lead(store, phone="+18085552368", tz=None))
    assert hi
    zs = lead_zones(hi, campaign)
    clock.set(datetime(2026, 10, 12, 16, 0, tzinfo=UTC))  # 12:00 ET, 06:00 Honolulu
    assert not allowed_now(campaign.window, zs, clock.now())
    assert check_send(store, hi, campaign, "sms", clock.now()).reason == "quiet_hours"
    uk = store.get_lead(add_lead(store, phone="+447700900123", tz=None))
    assert uk and check_send(store, uk, campaign, "sms", clock.now()).reason == "timezone_required_for_international"
    rep = import_csv(store, "phone,timezone\n4045553333,EST\n", "x")
    assert rep.created == 1
    lead = store.find_lead_by_addr("+14045553333")
    assert lead and lead.timezone == "America/New_York"


def test_outbox_delivered_once_with_concurrent_workers(tmp_path: Path, clock: FakeClock) -> None:
    """RT: two workers both POSTed the same CRM handoff."""
    st = Store(tmp_path / "o.db", clock)
    st.save_campaign(make_campaign())
    add_lead(st)
    calls: list[str] = []
    lock = threading.Lock()

    def sink(kind: str, payload: dict[str, Any]) -> None:
        time.sleep(0.2)
        with lock:
            calls.append(payload["inbound_id"])

    engines = [Engine(st if i == 0 else st.clone(), {}, sink=sink) for i in range(3)]
    engines[0].enroll("test")
    engines[0].handle_inbound("sms", "+14045552368", "yes how much", provider_id="x")
    ts_ = [threading.Thread(target=e.deliver_outbox) for e in engines]
    for t in ts_:
        t.start()
    for t in ts_:
        t.join()
    assert len(calls) == 1


def test_later_reply_during_compose_is_not_overwritten(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    """RT: a 'later' reply arriving while plan() waited on the LLM was overwritten and the lead texted."""
    store.save_campaign(make_campaign(id="lr", approve_llm_messages=False))
    add_lead(store)
    holder: dict[str, Engine] = {}

    def llm(purpose: str, system: str, user: str) -> Any:
        if purpose == "compose":
            holder["e"].handle_inbound("sms", "+14045552368", "maybe next month", provider_id="later1")
            return {"body": "Dana, Mike again from Brightside Roofing. Free roof inspection if you'd like."}
        return {"label": "later", "possible_opt_out": False, "confidence": "high"}

    e = Engine(store, {"sms": channel}, llm=FakeLLM(llm))
    holder["e"] = e
    e.enroll("lr")
    e.tick()  # step 0 (template)
    clock.advance(timedelta(hours=49))
    e.plan()  # step 1 personalizes -> reply lands mid-compose
    assert store.conn.execute("SELECT COUNT(*) FROM messages WHERE step_index=1").fetchone()[0] == 0


def test_campaign_edits_seen_by_running_worker(tmp_path: Path, clock: FakeClock) -> None:
    """RT: a long-running worker cached campaign specs forever."""
    st = Store(tmp_path / "c.db", clock)
    st.save_campaign(make_campaign())
    add_lead(st)
    add_lead(st, phone="+14045550001")
    ch = FakeChannel("sms", clock=clock.now)
    worker = Engine(st, {"sms": ch}, config=EngineConfig(plan_batch=1, dispatch_batch=1))
    worker.enroll("test")
    worker.tick()
    other = Store(tmp_path / "c.db", clock)
    other.save_campaign(make_campaign(window_end="11:30"))  # operator tightens the window to end 11:30 ET
    worker.tick(clock.advance(timedelta(minutes=30)))  # 11:30 ET now
    assert len(ch.deliveries) == 1


def test_reimport_revocation_applies_to_every_matched_lead(store: Store) -> None:
    """RT: a revocation row matching two records only updated the older one."""
    import_csv(store, "phone,sms_consent\n4045551111,yes\n", "a")
    import_csv(store, "email,email_consent\ndana@example.com,yes\n", "b")
    import_csv(store, "phone,email,sms_consent,email_consent\n4045551111,dana@example.com,no,no\n", "c")
    by_email = store.find_lead_by_addr("dana@example.com")
    assert by_email and by_email.email_consent is Consent.NO


def test_lease_expiry_mid_batch_cannot_cause_duplicates(store: Store, campaign: Any, clock: FakeClock) -> None:
    """RT: one lease covered a whole claimed batch; when it lapsed mid-batch another worker's reconcile
    requeued (lookup: 'not found') and sent the rows the first worker had not reached yet, and the first
    worker then sent them again."""
    for i in range(3):
        add_lead(store, phone=f"+1404560{i:04d}")
    calls = {"n": 0}

    class Stall(FakeChannel):
        def send(self, msg: Outbound) -> SendResult:
            calls["n"] += 1
            if calls["n"] == 1:  # first provider call stalls past the lease; worker B acts meanwhile
                clock.advance(timedelta(minutes=10))
                b.reconcile()
                b.dispatch()
            return super().send(msg)

    ch = Stall("sms", clock=clock.now)  # lookup-capable: unsent rows look "not found" -> requeued
    a = Engine(store, {"sms": ch}, worker_id="A", config=EngineConfig(lease_seconds=60))
    b = Engine(store.clone(), {"sms": ch}, worker_id="B", config=EngineConfig(lease_seconds=60))
    a.enroll("test")
    a.plan()
    a.dispatch()
    assert ch.duplicate_deliveries == 0
    assert len({d.msg.idempotency_key for d in ch.deliveries}) == len(ch.deliveries) == 3
    assert replay(store).ok


def test_guard_closes_reported_bypasses() -> None:
    """RT: TLD allow-list, fragment/backslash hosts, spelled-out offers, dash-split phrases, UCS-2 typography."""
    from lazarus.compose import gsm_friendly, guard, sms_segments
    from lazarus.models import Lead
    c = make_campaign(facts=["Free roof inspection."])
    lead = Lead(id="x", first_name="Dana", sms_consent=Consent.YES)
    step = c.steps[1]
    ref = "Hi Dana, Mike again. Want a free inspection?"
    for body in ["Rebook at acme-booking.shop/r", "See is.gd/r00f1", "https://evil.example#.brightside.example",
                 "https://evil.example\\.brightside.example", "https://brightside.example@evil.example/x",
                 "fifty percent off this week only", "Half off a new roof", "one hundred percent risk–free",
                 "Twenty-five year warranty included"]:
        assert guard(f"Hi Dana, {body}", c, lead, step, reference=ref, is_first=False), body
    assert guard("Hi Dana, want one? Mike from brightside.example", c, lead, step, reference=ref, is_first=False) == []
    assert gsm_friendly("plain — a person’s text") == "plain - a person's text"
    assert sms_segments("a" * 160) == 1 and sms_segments("a" * 161) == 2 and sms_segments("—" * 71) == 2


def test_domain_like_names_never_reach_a_message(store: Store) -> None:
    """RT: a web-form 'name' like Pay.Acme-Billing.Com passed import and was texted via the template path."""
    from lazarus.compose import compose
    from lazarus.models import Lead
    from lazarus.normalize import normalize_name
    assert normalize_name("Pay.Acme-Billing.Com") is None and normalize_name("J.R.") == "J.R."
    c = make_campaign()
    sneaky = Lead(id="x", first_name="Visit Free-Prize.Shop", sms_consent=Consent.YES)  # bypassing import
    out = compose(c.steps[0], sneaky, c, is_first=True, llm=None)
    assert "Prize" not in out.body and out.body.startswith("Hi there")


def test_llm_label_goes_through_strict_gate() -> None:
    """RT: an LLM-decided label skipped the opt-out-cue gate."""
    from lazarus.classify import classify
    llm = FakeLLM(lambda p, s, u: {"label": "later", "possible_opt_out": False, "confidence": "high"})
    c = classify("idk, the texts are kind of a lot honestly, enough already", llm=llm)
    assert c.needs_review


def test_fallback_and_unknown_models_are_charged() -> None:
    """RT: spend on fallback models (not in the price table) was recorded as $0."""
    from lazarus.llm import LLMResult
    assert LLMResult({}, None, "claude-opus-4-8", 1_000_000, 0).cost_usd == 5.0
    assert LLMResult({}, None, "claude-something-new", 1_000_000, 0).cost_usd >= 10.0



def test_junk_flood_cannot_block_signed_webhooks(tmp_path: Path) -> None:
    import json as _json
    import urllib.request

    from lazarus.server import RateLimiter, make_server
    from lazarus.webhooks import sign
    db = tmp_path / "s.db"
    st = Store(db)
    st.save_campaign(make_campaign())
    add_lead(st)
    st.close()
    srv = make_server(lambda: Engine(Store(db), {}), port=0, inbound_secret="s" * 32, limiter=RateLimiter(rate=0.0001, burst=3))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/webhooks/inbound"

    def post(body: bytes, sig: str | None) -> int:
        req = urllib.request.Request(base, data=body, headers={"X-Lazarus-Signature": sig} if sig else {}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    codes = [post(b"junk", None) for _ in range(6)]
    assert codes[:3] == [403] * 3 and set(codes[3:]) == {429}
    body = _json.dumps({"channel": "sms", "from": "+14045552368", "body": "STOP", "id": "real"}).encode()
    assert post(body, sign("s" * 32, body)) == 200  # a real opt-out still gets through
    srv.shutdown()
    srv.server_close()


def test_transport_refuses_redirects_and_plain_http(tmp_path: Path) -> None:
    import http.server

    import pytest

    from lazarus.channels.http import urllib_transport

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()

        def log_message(self, *a: Any) -> None: ...

    srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    status, _, _ = urllib_transport("POST", f"http://127.0.0.1:{srv.server_address[1]}/hook", {}, b"{}", 5)
    assert status == 302  # surfaced, not followed
    srv.shutdown()
    with pytest.raises(ValueError):
        urllib_transport("POST", "http://crm.example/hook", {}, b"{}", 5)
    with pytest.raises(ValueError):
        urllib_transport("POST", "https@crm.example", {}, b"{}", 5)


def test_plan_respects_daily_capacity_and_claims(tmp_path: Path, clock: FakeClock) -> None:
    """RT (architecture): plan() queued the whole backlog regardless of the daily cap, and concurrent
    planners each composed (and paid an LLM for) the same enrollment."""
    st = Store(tmp_path / "p.db", clock)
    st.save_campaign(make_campaign(id="cp", daily_send_cap=10))
    for i in range(40):
        add_lead(st, phone=f"+1404562{i:04d}")
    calls = {"n": 0}

    def llm(p: str, s: str, u: str) -> Any:
        calls["n"] += 1
        time.sleep(0.01)
        return {"body": "Hi there, it's Mike from Brightside Roofing. Free roof inspection if you'd like."}

    a = Engine(st, {}, llm=FakeLLM(llm))
    a.enroll("cp")
    assert sum(a.plan().values()) - 0 >= 10
    assert st.conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 10  # capped at today's capacity
    st2 = Store(tmp_path / "q.db", clock)
    c = make_campaign(id="pp", steps=[make_campaign().steps[0].model_copy(update={"personalize": True})],
                      approve_llm_messages=False)
    st2.save_campaign(c)
    for i in range(30):
        add_lead(st2, phone=f"+1404563{i:04d}")
    engines = [Engine(st2 if i == 0 else st2.clone(), {}, llm=FakeLLM(llm)) for i in range(3)]
    engines[0].enroll("pp")
    calls["n"] = 0
    ts_ = [threading.Thread(target=e.plan) for e in engines]
    for t in ts_:
        t.start()
    for t in ts_:
        t.join()
    assert st2.conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 30
    assert calls["n"] == 30  # each enrollment composed exactly once across 3 planners


def test_server_reuses_engines_across_requests(tmp_path: Path) -> None:
    """RT: ThreadingHTTPServer starts a thread per request, so the thread-local engine (and its LLM budget)
    was rebuilt for every webhook."""
    import json as _json
    import urllib.request

    from lazarus.server import make_server
    from lazarus.webhooks import sign
    db = tmp_path / "pool.db"
    Store(db).save_campaign(make_campaign())
    built = {"n": 0}

    def factory() -> Engine:
        built["n"] += 1
        return Engine(Store(db), {})

    srv = make_server(factory, port=0, inbound_secret="s" * 32)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for i in range(5):
        body = _json.dumps({"channel": "sms", "from": "+14045550000", "body": "who is this", "id": f"p{i}"}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/webhooks/inbound", data=body,
                                     headers={"X-Lazarus-Signature": sign("s" * 32, body)}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            assert r.status == 200
    srv.shutdown()
    srv.server_close()
    assert built["n"] == 1


def test_classification_cache_only_keeps_confident_answers(tmp_path: Path) -> None:
    """RT: one sampled LLM answer was cached forever for every lead sending the same text."""
    from lazarus.llm import CachingProvider
    st = Store(tmp_path / "cc.db")
    answers = iter([{"label": "later", "possible_opt_out": False, "confidence": "medium"},
                    {"label": "interested", "possible_opt_out": False, "confidence": "high"},
                    {"label": "unclear", "possible_opt_out": False, "confidence": "high"}])
    inner = FakeLLM(lambda p, s, u: next(answers))
    c = CachingProvider(inner, st)
    kw: dict[str, Any] = dict(purpose="classify", system="s", user="maybe", schema={}, max_tokens=8)
    assert c.complete_json(**kw).data["label"] == "later"      # medium confidence: not cached
    assert c.complete_json(**kw).data["label"] == "interested"  # asked again; high: cached
    assert c.complete_json(**kw).data["label"] == "interested" and len(inner.calls) == 2
    st.clock = FakeClock(datetime(2030, 1, 1, tzinfo=UTC))      # past the TTL
    assert c.complete_json(**kw).data["label"] == "unclear"
