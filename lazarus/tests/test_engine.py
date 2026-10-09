import threading
from datetime import timedelta
from typing import Any

import pytest

from lazarus.channels import Outbound, SendResult
from lazarus.channels.fake import CrashAfterSend, FakeChannel, FaultPlan
from lazarus.engine import Engine, EngineConfig
from lazarus.llm import FakeLLM
from lazarus.models import Campaign, EnrollmentState, Label, MessageStatus
from lazarus.normalize import Consent
from lazarus.replay import replay
from lazarus.store import Store
from lazarus.timeutil import FakeClock

from .conftest import add_lead, make_campaign


def statuses(store: Store) -> list[str]:
    return [r["status"] for r in store.conn.execute("SELECT status FROM messages ORDER BY created_at")]


def enr_state(store: Store, lead_id: str) -> str:
    return str(store.conn.execute("SELECT state FROM enrollments WHERE lead_id=?", (lead_id,)).fetchone()["state"])


def test_happy_path_sequence_runs_to_exhaustion(store: Store, engine: Engine, channel: FakeChannel, clock: FakeClock) -> None:
    lid = add_lead(store)
    assert engine.enroll("test") == 1
    assert engine.enroll("test") == 0  # idempotent
    for _ in range(60):
        engine.tick(clock.advance(timedelta(hours=6)))
    assert len(channel.deliveries) == 3
    assert channel.deliveries[0].msg.body.endswith("Reply STOP to opt out.")
    assert not channel.deliveries[1].msg.body.endswith("Reply STOP to opt out.")
    assert enr_state(store, lid) == "exhausted"
    assert replay(store).ok


def test_unknown_timezone_uses_conservative_window(store: Store, engine: Engine, channel: FakeChannel, clock: FakeClock) -> None:
    add_lead(store, tz=None)  # 11:00 ET but 08:00 PT -> must wait for 09:00 PT
    engine.enroll("test")
    engine.tick()
    assert channel.deliveries == []
    engine.tick(clock.advance(timedelta(hours=1)))
    assert len(channel.deliveries) == 1


def test_no_consent_blocks_at_plan(store: Store, engine: Engine, channel: FakeChannel) -> None:
    lid = add_lead(store, consent=Consent.NO)
    engine.enroll("test")
    engine.tick()
    assert channel.deliveries == [] and enr_state(store, lid) == "blocked"


def test_approval_gate(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="appr", approve_first_n=1))
    add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("appr")
    e.tick()
    assert statuses(store) == ["pending_approval"] and channel.deliveries == []
    mid = store.conn.execute("SELECT id FROM messages").fetchone()["id"]
    assert e.approve(mid, "op", body="Hi Dana, Mike from Brightside Roofing here. Edited.")
    assert not e.approve(mid, "op")  # compare-and-set: second approval is a no-op
    e.tick()
    assert channel.deliveries[0].msg.body.startswith("Hi Dana, Mike from Brightside Roofing here. Edited.")


def test_reject_pauses_enrollment(store: Store, channel: FakeChannel) -> None:
    store.save_campaign(make_campaign(id="appr", approve_first_n=5))
    lid = add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("appr")
    e.tick()
    mid = store.conn.execute("SELECT id FROM messages").fetchone()["id"]
    assert e.reject(mid, "op", "tone")
    assert enr_state(store, lid) == "paused"


def test_transient_errors_back_off_then_fail(store: Store, campaign: Campaign, clock: FakeClock) -> None:
    ch = FakeChannel("sms", plan=FaultPlan(transient=1.0), clock=clock.now)
    e = Engine(store, {"sms": ch}, config=EngineConfig(backoff_base_s=60))
    lid = add_lead(store)
    e.enroll("test")
    e.tick()
    row = store.conn.execute("SELECT * FROM messages").fetchone()
    assert row["status"] == "queued" and row["attempts"] == 1
    for _ in range(40):
        e.tick(clock.advance(timedelta(hours=3)))
    assert statuses(store) == ["failed"] and enr_state(store, lid) == "failed"
    assert sum(ch.attempts.values()) == campaign.max_send_attempts


def test_permanent_error_suppresses_destination(store: Store, engine: Engine, channel: FakeChannel) -> None:
    channel.invalid.add("+14045552368")
    lid = add_lead(store)
    engine.enroll("test")
    engine.tick()
    assert statuses(store) == ["failed"] and enr_state(store, lid) == "failed"
    assert store.is_suppressed("+14045552368") == "invalid_destination"


def test_crash_after_send_reconciles_without_duplicate(store: Store, campaign: Campaign, clock: FakeClock) -> None:
    ch = FakeChannel("sms", plan=FaultPlan(crash_after_send=1.0), clock=clock.now)
    e = Engine(store, {"sms": ch}, config=EngineConfig(lease_seconds=60))
    add_lead(store)
    e.enroll("test")
    with pytest.raises(CrashAfterSend):
        e.tick()
    assert statuses(store) == ["sending"] and len(ch.deliveries) == 1
    ch.plan = FaultPlan()
    e.tick(clock.advance(timedelta(minutes=5)))  # lease expired -> lookup finds it -> sent
    assert statuses(store)[0] == "sent"
    assert ch.duplicate_deliveries == 0 and len(ch.deliveries) == 1
    assert replay(store).ok


def test_ambiguous_without_lookup_needs_human(store: Store, campaign: Campaign, clock: FakeClock) -> None:
    ch = FakeChannel("sms", plan=FaultPlan(ambiguous=1.0), clock=clock.now, supports_lookup=False)
    e = Engine(store, {"sms": ch})
    lid = add_lead(store)
    e.enroll("test")
    e.tick()
    for _ in range(5):
        e.tick(clock.advance(timedelta(hours=1)))
    assert statuses(store) == ["unknown"] and len(ch.deliveries) == 1  # never blindly resent
    mid = store.conn.execute("SELECT id FROM messages").fetchone()["id"]
    assert e.resolve_unknown(mid, sent=True, actor="op")
    assert enr_state(store, lid) == "active"


def test_ambiguous_lost_is_requeued_after_lookup(store: Store, campaign: Campaign, clock: FakeClock) -> None:
    ch = FakeChannel("sms", plan=FaultPlan(ambiguous_lost=1.0), clock=clock.now)
    e = Engine(store, {"sms": ch})
    add_lead(store)
    e.enroll("test")
    e.tick()
    ch.plan = FaultPlan()
    e.tick(clock.advance(timedelta(minutes=1)))  # within the resend grace: not yet requeued
    assert statuses(store) == ["unknown"]
    e.tick(clock.advance(timedelta(minutes=16)))  # past grace: provider never got it -> requeue
    e.tick(clock.advance(timedelta(minutes=1)))
    assert len(ch.deliveries) == 1 and statuses(store) == ["sent"]


def test_adapter_exception_is_not_resent(store: Store, campaign: Campaign, clock: FakeClock) -> None:
    class Broken:
        name = "sms"

        def send(self, msg: Outbound) -> SendResult:
            raise KeyError("bug")

        def lookup(self, key: str) -> SendResult | None:
            return None

    e = Engine(store, {"sms": Broken()})
    add_lead(store)
    e.enroll("test")
    e.tick()
    assert statuses(store) == ["unknown"]


def test_opt_out_reply_cancels_and_suppresses(store: Store, engine: Engine, channel: FakeChannel, clock: FakeClock) -> None:
    lid = add_lead(store, email="dana@example.com")
    engine.enroll("test")
    engine.tick()
    res = engine.handle_inbound("sms", "(404) 555-2368", "STOP", provider_id="SM1")
    assert res["label"] == "opt_out"
    assert store.is_suppressed("+14045552368") and store.is_suppressed("dana@example.com")
    assert enr_state(store, lid) == "opted_out"
    for _ in range(20):
        engine.tick(clock.advance(timedelta(hours=12)))
    assert len(channel.deliveries) == 1


def test_opt_out_between_plan_and_dispatch(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="appr", approve_first_n=5))
    add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("appr")
    e.plan()
    e.handle_inbound("sms", "+14045552368", "unsubscribe", provider_id="SM9")
    mid = store.conn.execute("SELECT id FROM messages").fetchone()["id"]
    assert not e.approve(mid, "op")  # canceled; cannot be approved
    e.tick()
    assert channel.deliveries == []


def test_suppression_checked_at_send_time(store: Store, engine: Engine, channel: FakeChannel) -> None:
    add_lead(store)
    engine.enroll("test")
    engine.plan()
    store.suppress("+14045552368", "manual", "test")  # e.g. imported DNC list between plan and send
    engine.dispatch()
    assert channel.deliveries == [] and statuses(store) == ["canceled"]
    state = store.conn.execute("SELECT state FROM enrollments").fetchone()["state"]
    assert state == "blocked"  # not stranded in awaiting_send


def test_optout_confirmation_sent_once(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="conf", send_optout_confirmation=True))
    add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("conf")
    e.tick()
    e.handle_inbound("sms", "+14045552368", "STOP", provider_id="a")
    e.handle_inbound("sms", "+14045552368", "STOP!!", provider_id="b")
    e.tick()
    bodies = [d.msg.body for d in channel.deliveries]
    assert len(bodies) == 2 and "unsubscribed" in bodies[1]


def test_optout_confirmation_expires(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="conf", send_optout_confirmation=True))
    add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("conf")
    e.tick()
    e.handle_inbound("sms", "+14045552368", "STOP", provider_id="a")
    e.tick(clock.advance(timedelta(minutes=30)))
    assert len(channel.deliveries) == 1


def test_duplicate_webhook_is_idempotent(store: Store, engine: Engine) -> None:
    add_lead(store)
    engine.enroll("test")
    engine.tick()
    a = engine.handle_inbound("sms", "+14045552368", "yes how much", provider_id="SMx")
    b = engine.handle_inbound("sms", "+14045552368", "yes how much", provider_id="SMx")
    assert b["duplicate"] and a["inbound_id"] == b["inbound_id"]
    assert store.conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1


def test_interested_hands_off_and_outbox_retries(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    calls: list[dict[str, Any]] = []
    fail = {"n": 2}

    def sink(kind: str, payload: dict[str, Any]) -> None:
        if fail["n"]:
            fail["n"] -= 1
            raise ConnectionError("crm down")
        calls.append(payload)

    store.save_campaign(make_campaign(id="hh"))
    lid = add_lead(store)
    e = Engine(store, {"sms": channel}, sink=sink, config=EngineConfig(backoff_base_s=10))
    e.enroll("hh")
    e.tick()
    e.handle_inbound("sms", "+14045552368", "yes! how much for a metal roof?", provider_id="SM1")
    assert enr_state(store, lid) == "handed_off"
    for _ in range(5):
        e.deliver_outbox(clock.advance(timedelta(minutes=5)))
    assert len(calls) == 1 and calls[0]["lead"]["phone"] == "+14045552368"
    assert store.conn.execute("SELECT status, attempts FROM outbox").fetchone()["attempts"] == 3


def test_later_snoozes_and_replans_same_step(store: Store, engine: Engine, channel: FakeChannel, clock: FakeClock) -> None:
    """Regression: a canceled step message must not block re-planning that step after a snooze."""
    lid = add_lead(store)
    engine.enroll("test")
    engine.tick()  # step 0 sent
    engine.tick(clock.advance(timedelta(hours=49)))  # step 1 sent
    engine.handle_inbound("sms", "+14045552368", "not now, maybe next month", provider_id="L1")
    assert enr_state(store, lid) == "active"
    for _ in range(80):
        engine.tick(clock.advance(timedelta(hours=12)))
    keys = [d.msg.idempotency_key for d in channel.deliveries]
    assert len(keys) == 3 and len(set(keys)) == 3
    assert enr_state(store, lid) == "exhausted"
    assert replay(store).ok


def test_later_cancels_pending_message_then_new_generation(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="gg", approve_first_n=10))
    lid = add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("gg")
    e.plan()
    e.handle_inbound("sms", "+14045552368", "maybe next month", provider_id="L2")
    clock.advance(timedelta(days=31))
    e.plan()
    keys = [r["idempotency_key"] for r in store.conn.execute("SELECT idempotency_key FROM messages ORDER BY created_at")]
    assert keys[0].endswith(":0:0") and keys[1].endswith(":0:1")
    assert enr_state(store, lid) == "awaiting_send"


def test_unclear_pauses_and_resolution_resumes(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="rr", approve_first_n=10))
    lid = add_lead(store)
    e = Engine(store, {"sms": channel})
    e.enroll("rr")
    e.plan()
    res = e.handle_inbound("sms", "+14045552368", "who is this?", provider_id="U1")
    assert res["needs_review"] and enr_state(store, lid) == "paused"
    assert statuses(store) == ["held"]
    out = e.resolve_review(res["inbound_id"], Label.UNCLEAR, actor="op")
    assert out[0].startswith("resumed")
    assert statuses(store) == ["pending_approval"]  # regression: release must not bypass the approval gate
    assert enr_state(store, lid) == "awaiting_send"
    assert e.resolve_review(res["inbound_id"], Label.UNCLEAR, actor="op") == ["already_resolved"]


def test_review_resolved_as_opt_out(store: Store, engine: Engine) -> None:
    lid = add_lead(store)
    engine.enroll("test")
    engine.tick()
    res = engine.handle_inbound("sms", "+14045552368", "how did you get my number", provider_id="W1")
    assert res["possible_opt_out"]
    engine.resolve_review(res["inbound_id"], Label.OPT_OUT, actor="op")
    assert enr_state(store, lid) == "opted_out" and store.is_suppressed("+14045552368") == "opt_out"


def test_opted_out_lead_writing_back_goes_to_human(store: Store, engine: Engine) -> None:
    lid = add_lead(store)
    engine.enroll("test")
    engine.tick()
    engine.handle_inbound("sms", "+14045552368", "STOP", provider_id="1")
    res = engine.handle_inbound("sms", "+14045552368", "actually yes how much?", provider_id="2")
    assert "review" in res["actions"] and enr_state(store, lid) == "opted_out"
    assert store.conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0


def test_wrong_number_suppresses(store: Store, engine: Engine) -> None:
    lid = add_lead(store)
    engine.enroll("test")
    engine.tick()
    engine.handle_inbound("sms", "+14045552368", "wrong number", provider_id="1")
    assert enr_state(store, lid) == "wrong_number" and store.is_suppressed("+14045552368") == "wrong_number"


def test_unknown_sender_opt_out_still_suppressed(store: Store, engine: Engine) -> None:
    res = engine.handle_inbound("sms", "+13125550000", "STOP", provider_id="x")
    assert res["label"] == "opt_out" and store.is_suppressed("+13125550000")


def test_campaign_pause_blocks_planning(store: Store, engine: Engine, channel: FakeChannel) -> None:
    add_lead(store)
    engine.enroll("test")
    store.set_campaign_status("test", "paused")
    engine.tick()
    assert channel.deliveries == []
    store.set_campaign_status("test", "active")
    engine.tick()
    assert len(channel.deliveries) == 1


def test_llm_personalized_messages_need_approval(store: Store, channel: FakeChannel, clock: FakeClock) -> None:
    store.save_campaign(make_campaign(id="pp", approve_llm_messages=True))
    add_lead(store)
    llm = FakeLLM(lambda p, s, u: {"body": "Dana, Mike again from Brightside Roofing. Free roof inspection if you want one."}
                  if p == "compose" else {"label": "unclear", "possible_opt_out": False, "confidence": "low"})
    e = Engine(store, {"sms": channel}, llm=llm)
    e.enroll("pp")
    e.tick()
    e.tick(clock.advance(timedelta(hours=49)))
    rows = store.conn.execute("SELECT composed_by, status FROM messages ORDER BY created_at").fetchall()
    assert [(r["composed_by"], r["status"]) for r in rows] == [("template", "sent"), ("llm", "pending_approval")]


def test_concurrent_dispatchers_never_double_send(tmp_path: Any, clock: FakeClock) -> None:
    st = Store(tmp_path / "c.db", clock)
    st.save_campaign(make_campaign())
    for i in range(300):
        add_lead(st, phone=f"+1404555{i:04d}" if i >= 200 else f"+1404556{i:04d}")
    ch = FakeChannel("sms", clock=clock.now)
    engines = [Engine(st if i == 0 else st.clone(), {"sms": ch}, worker_id=f"w{i}") for i in range(6)]
    engines[0].enroll("test")
    engines[0].plan()
    errors: list[BaseException] = []

    def run(e: Engine) -> None:
        try:
            for _ in range(5):
                e.dispatch(limit=20)
        except BaseException as ex:
            errors.append(ex)

    threads = [threading.Thread(target=run, args=(e,)) for e in engines]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ch.duplicate_deliveries == 0
    assert len(ch.deliveries) == 300 == len({d.msg.to for d in ch.deliveries})
    assert replay(st).ok


def test_replay_detects_tampering(store: Store, engine: Engine) -> None:
    add_lead(store)
    engine.enroll("test")
    engine.tick()
    assert replay(store).ok
    store.conn.execute("UPDATE messages SET status='queued'")  # a write that bypasses the event log
    rep = replay(store)
    assert not rep.ok and rep.mismatches[0]["entity"] == "message"


def test_events_require_transaction(store: Store) -> None:
    with pytest.raises(RuntimeError):
        store.emit("x", "y", "z")


def test_schema_newer_than_code_is_refused(tmp_path: Any, clock: FakeClock) -> None:
    st = Store(tmp_path / "v.db", clock)
    st.conn.execute("PRAGMA user_version=99")
    st.close()
    with pytest.raises(RuntimeError):
        Store(tmp_path / "v.db", clock)


def test_message_status_enum_coverage() -> None:
    assert {s.value for s in MessageStatus} >= {"queued", "sending", "sent", "unknown", "held"}
    assert EnrollmentState.HANDED_OFF.value == "handed_off"


def test_daily_cap_enforced_at_claim_across_workers(tmp_path: Any, clock: FakeClock) -> None:
    st = Store(tmp_path / "cap.db", clock)
    st.save_campaign(make_campaign(id="cap", daily_send_cap=25))
    for i in range(100):
        add_lead(st, phone=f"+1404557{i:04d}")
    ch = FakeChannel("sms", clock=clock.now)
    engines = [Engine(st if i == 0 else st.clone(), {"sms": ch}, worker_id=f"w{i}") for i in range(4)]
    engines[0].enroll("cap")
    engines[0].plan()
    assert st.conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 25  # planning stops at capacity
    st.save_campaign(make_campaign(id="cap", daily_send_cap=10))  # operator lowers the cap after planning
    threads = [threading.Thread(target=e.dispatch, kwargs={"limit": 10}) for e in engines]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for e in engines:
        e.dispatch()
    assert len(ch.deliveries) == 10  # exact at the claim, despite 4 concurrent claimers
    clock.advance(timedelta(days=1))
    for _ in range(3):
        engines[0].tick()
    assert len(ch.deliveries) == 20
    assert replay(st).ok
