"""Campaign flight simulator: run the real engine against a fake world and check invariants.

Everything is real except the clock, the carrier, and the humans:

* FakeClock advances in fixed ticks over N days.
* FakeChannel injects transient/permanent/ambiguous failures and worker crashes
  *after* the provider accepted a message (the hardest case for exactly-once).
* Leads reply with texts drawn from a labeled corpus; some webhooks are delivered twice.
* A simulated operator approves pending messages; a simulated reviewer resolves
  flagged replies with the true label after a delay.
* Optionally N dispatcher threads, each with its own SQLite connection.

Then it checks invariants that must hold regardless of faults. Exit code is
non-zero on any violation, so this doubles as a CI regression gate.
"""

from __future__ import annotations

import json
import random
import tempfile
import threading
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .channels.fake import CrashAfterSend, FakeChannel, FaultPlan
from .engine import Engine, EngineConfig
from .evaluate import load_jsonl
from .ingest import upsert_lead
from .llm import LLMProvider
from .models import TERMINAL_ENROLLMENT, Campaign, Label, Step
from .normalize import Consent
from .policy import lead_zones
from .replay import replay
from .store import IdGen, Store, _lead
from .timeutil import FakeClock, allowed_now, parse_ts, ts

AREA_TZ = {
    "404": "America/New_York", "212": "America/New_York", "617": "America/New_York", "305": "America/New_York",
    "312": "America/Chicago", "214": "America/Chicago", "713": "America/Chicago", "612": "America/Chicago",
    "303": "America/Denver", "602": "America/Phoenix", "801": "America/Denver",
    "415": "America/Los_Angeles", "206": "America/Los_Angeles", "503": "America/Los_Angeles", "702": "America/Los_Angeles",
}
FIRST = ["Dana", "Kevin", "Maria", "Sam", "Priya", "Luis", "Grace", "Omar", "Tara", "Ben", "Aisha", "Chen", "Rosa", "Jake"]
REPLY_MIX = {"opt_out": 0.18, "interested": 0.2, "not_interested": 0.2, "later": 0.12, "wrong_number": 0.05,
             "auto_reply": 0.1, "unclear": 0.15}


@dataclass
class SimConfig:
    leads: int = 300
    days: int = 21
    seed: int = 7
    tick_minutes: int = 15
    reply_rate: float = 0.3
    unknown_tz_rate: float = 0.3
    no_consent_rate: float = 0.05
    duplicate_webhook_rate: float = 0.05
    review_delay_hours: float = 4
    workers: int = 1
    corpus: str = "evals/replies_blind_dev.jsonl"
    fault: FaultPlan = field(default_factory=lambda: FaultPlan(transient=0.05, permanent=0.01, ambiguous=0.01,
                                                                ambiguous_lost=0.01, crash_after_send=0.005))
    start: str = "2026-10-12T12:00:00+00:00"


@dataclass
class SimResult:
    config: dict[str, Any]
    metrics: dict[str, Any]
    violations: dict[str, list[Any]]
    wall_seconds: float

    @property
    def ok(self) -> bool:
        return not any(self.violations.values())

    def to_json(self) -> str:
        return json.dumps({"ok": self.ok, "config": self.config, "metrics": self.metrics,
                           "violations": {k: v[:20] for k, v in self.violations.items()},
                           "violation_counts": {k: len(v) for k, v in self.violations.items()},
                           "wall_seconds": round(self.wall_seconds, 2)}, indent=2, default=str)


def sim_campaign() -> Campaign:
    return Campaign(
        id="sim", name="Simulated reactivation", business_name="Brightside Roofing", sender_name="Mike",
        facts=["Free roof inspection."],
        steps=[
            Step(delay_hours=0, template="Hi {first_name|there}, it's {sender_name} from {business_name}. Still thinking about a new roof?"),
            Step(delay_hours=48, template="Hi {first_name|there}, {sender_name} again from {business_name}. Want a free inspection this week?"),
            Step(delay_hours=96, template="Last note, {first_name|there}. Reply anytime if the roof comes back up."),
        ],
        approve_first_n=3, approve_llm_messages=True, send_optout_confirmation=True, exhaust_after_hours=72,
    )


def run(cfg: SimConfig, llm: LLMProvider | None = None, db_path: str | None = None) -> SimResult:
    t0 = time.perf_counter()
    rng = random.Random(cfg.seed)
    clock = FakeClock(datetime.fromisoformat(cfg.start).astimezone(UTC))
    tmp = None
    if db_path is None:
        tmp = tempfile.TemporaryDirectory()
        db_path = str(Path(tmp.name) / "sim.db")
    store = Store(db_path, clock, IdGen(cfg.seed))
    corpus = load_jsonl(cfg.corpus)
    by_label: dict[str, list[str]] = defaultdict(list)
    for it in corpus:
        by_label[it["label"]].append(it["text"])

    campaign = sim_campaign()
    store.save_campaign(campaign)
    truth_tz: dict[str, str] = {}
    used: set[str] = set()
    for i in range(cfg.leads):
        area = rng.choice(list(AREA_TZ))
        while True:
            phone = f"+1{area}{rng.randint(200, 999)}{rng.randint(0, 9999):04d}"
            if phone not in used and phone[5:7] != "11" and not (phone[5:8] == "555" and phone[8:10] == "01"):
                break
        used.add(phone)
        tz = None if rng.random() < cfg.unknown_tz_rate else AREA_TZ[area]
        consent = Consent.YES if rng.random() >= cfg.no_consent_rate else rng.choice([Consent.NO, Consent.UNKNOWN])
        upsert_lead(store, {"external_id": f"sim-{i}", "first_name": rng.choice(FIRST), "last_name": None,
                            "email": None, "phone": phone, "timezone": tz, "tags": ["sim"], "sms_consent": consent,
                            "email_consent": Consent.UNKNOWN, "notes": ""}, source="sim")
        truth_tz[phone] = AREA_TZ[area]

    channel = FakeChannel("sms", plan=cfg.fault, clock=clock.now)
    handoffs: list[dict[str, Any]] = []
    lock = threading.Lock()

    def sink(kind: str, payload: dict[str, Any]) -> None:
        if rng.random() < 0.1:
            raise ConnectionError("simulated CRM outage")
        with lock:
            handoffs.append(payload)

    ecfg = EngineConfig(lease_seconds=600, dispatch_batch=50)
    engine = Engine(store, {"sms": channel}, llm=llm, config=ecfg, worker_id="w0", sink=sink)
    workers = [engine] + [Engine(store.clone(), {"sms": channel}, llm=llm, config=ecfg, worker_id=f"w{i}")
                          for i in range(1, cfg.workers)]
    engine.enroll(campaign.id)

    m: Counter[str] = Counter()
    true_label: dict[str, str] = {}       # phone -> intent label of their reply
    opted_out_at: dict[str, datetime] = {}  # phone -> when they (truly) sent an opt-out
    scheduled: list[tuple[datetime, str, str, str]] = []  # (at, phone, text, label)
    seen_deliveries = 0
    pid = 0

    end = clock.now() + timedelta(days=cfg.days)
    while clock.now() < end:
        now = clock.advance(timedelta(minutes=cfg.tick_minutes))
        engine.reconcile(now)
        engine.plan(now)
        for r in store.conn.execute("SELECT id FROM messages WHERE status='pending_approval'").fetchall():
            engine.approve(r["id"], actor="sim-operator")
            m["approved"] += 1

        def dispatch(e: Engine, now: datetime = now) -> None:
            try:
                e.dispatch(now)
            except CrashAfterSend:
                with lock:
                    m["worker_crashes"] += 1

        if len(workers) == 1:
            dispatch(engine)
        else:
            ths = [threading.Thread(target=dispatch, args=(w,)) for w in workers]
            for th in ths:
                th.start()
            for th in ths:
                th.join()
        engine.deliver_outbox(now)

        # New deliveries -> maybe schedule a reply (one intent per lead, decided at first reply)
        new = channel.deliveries[seen_deliveries:]
        seen_deliveries = len(channel.deliveries)
        for d in new:
            phone = d.msg.to
            if d.msg.idempotency_key.startswith("optout-confirm:") or phone in true_label:
                continue
            if rng.random() < cfg.reply_rate:
                label = rng.choices(list(REPLY_MIX), weights=list(REPLY_MIX.values()))[0]
                if not by_label.get(label):
                    continue
                true_label[phone] = label
                at = now + timedelta(minutes=rng.randint(2, 48 * 60))
                scheduled.append((at, phone, rng.choice(by_label[label]), label))

        due = [s for s in scheduled if s[0] <= now]
        scheduled = [s for s in scheduled if s[0] > now]
        for _at, phone, text, label in due:
            pid += 1
            if label == "opt_out":
                opted_out_at.setdefault(phone, now)  # when the engine receives it
            res = engine.handle_inbound("sms", phone, text, provider_id=f"SMsim{pid}", received_at=now)
            m[f"reply_true:{label}"] += 1
            m[f"reply_pred:{res['label']}"] += 1
            m["reply_correct"] += res["label"] == label
            if rng.random() < cfg.duplicate_webhook_rate:
                dup = engine.handle_inbound("sms", phone, text, provider_id=f"SMsim{pid}", received_at=now)
                m["duplicate_webhooks"] += 1
                m["duplicate_webhooks_deduped"] += bool(dup.get("duplicate"))

        # Simulated reviewer resolves flagged replies with the true label after a delay.
        for r in store.conn.execute("SELECT * FROM inbound WHERE needs_review=1 AND resolved_at IS NULL").fetchall():
            if now - parse_ts(r["received_at"]) >= timedelta(hours=cfg.review_delay_hours):
                lbl = true_label.get(r["from_addr"], "unclear")
                engine.resolve_review(r["id"], Label(lbl), actor="sim-reviewer")
                m["reviews_resolved"] += 1

    # Settle: let leases expire and reconcile once more.
    clock.advance(timedelta(seconds=ecfg.lease_seconds + 1))
    engine.reconcile(clock.now())

    violations = check_invariants(store, channel, campaign, opted_out_at, handoffs)
    sent = store.conn.execute("SELECT status, COUNT(*) n FROM messages GROUP BY status").fetchall()
    enr = store.conn.execute("SELECT state, COUNT(*) n FROM enrollments GROUP BY state").fetchall()
    replies = sum(v for k, v in m.items() if k.startswith("reply_true:"))
    metrics = {
        "deliveries": len(channel.deliveries),
        "channel_attempts": sum(channel.attempts.values()),
        "duplicate_deliveries": channel.duplicate_deliveries,
        "messages_by_status": {r["status"]: r["n"] for r in sent},
        "enrollments_by_state": {r["state"]: r["n"] for r in enr},
        "replies": replies,
        "reply_label_accuracy": round(m["reply_correct"] / replies, 3) if replies else None,
        "handoffs_delivered": len(handoffs),
        "events": store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        **{k: v for k, v in m.items() if not k.startswith("reply_correct")},
    }
    store.close()
    for w in workers[1:]:
        w.store.close()
    if tmp:
        tmp.cleanup()
    return SimResult(asdict(cfg), metrics, violations, time.perf_counter() - t0)


def check_invariants(store: Store, channel: FakeChannel, campaign: Campaign,
                     opted_out_at: dict[str, datetime], handoffs: list[dict[str, Any]]) -> dict[str, list[Any]]:
    v: dict[str, list[Any]] = defaultdict(list)
    sup = {r["addr"]: (parse_ts(r["created_at"]), r["reason"]) for r in store.conn.execute("SELECT * FROM suppressions")}
    leads = {r["phone"]: r for r in store.conn.execute("SELECT * FROM leads")}
    window = campaign.window
    last: dict[str, datetime] = {}
    per_step: Counter[str] = Counter()
    for d in channel.deliveries:
        at, to, key = d.at, d.msg.to, d.msg.idempotency_key
        assert at is not None
        confirmation = key.startswith("optout-confirm:")
        if not confirmation:
            if to in sup and sup[to][0] < at:
                v["sent_after_suppression"].append({"to": to, "at": ts(at), "reason": sup[to][1]})
            if to in opted_out_at and opted_out_at[to] < at:
                # Ground truth: they said stop (even if the classifier missed it).
                v["sent_after_true_opt_out"].append({"to": to, "at": ts(at)})
            lead = leads[to]
            zones = lead_zones(_lead(lead), campaign)
            if not allowed_now(window, zones, at):
                v["sent_in_quiet_hours"].append({"to": to, "at": ts(at)})
            if lead["sms_consent"] != "yes":
                v["sent_without_consent"].append({"to": to})
            if to in last and (at - last[to]) < timedelta(hours=campaign.min_hours_between_touches):
                v["frequency_cap"].append({"to": to, "gap_h": round((at - last[to]).total_seconds() / 3600, 2)})
            last[to] = at
            per_step[key.rsplit(":", 1)[0]] += 1
    for k, n in per_step.items():
        if n > 1:
            v["step_delivered_twice"].append({"step": k, "count": n})
    if channel.duplicate_deliveries:
        v["duplicate_idempotency_key"].append(channel.duplicate_deliveries)

    terminal = tuple(s.value for s in TERMINAL_ENROLLMENT)
    rows = store.conn.execute(
        f"""SELECT e.id, e.state, m.id mid, m.status FROM enrollments e JOIN messages m ON m.enrollment_id=e.id
            WHERE e.state IN ({','.join('?' * len(terminal))}) AND m.status IN ('queued','pending_approval','held','sending')""",
        terminal).fetchall()
    for r in rows:
        v["open_message_on_terminal_enrollment"].append(dict(r))
    stuck = store.conn.execute("SELECT id FROM messages WHERE status='sending'").fetchall()
    for r in stuck:
        v["stuck_sending"].append(r["id"])

    rep = replay(store)
    if not rep.ok:
        v["replay_mismatch"].extend(rep.mismatches)

    interested = {r["id"] for r in store.conn.execute(
        "SELECT id FROM inbound WHERE label='interested' AND lead_id IS NOT NULL AND (needs_review=0 OR resolved_at IS NOT NULL)")}
    got = {h["inbound_id"] for h in handoffs}
    pending = {json.loads(r["payload"])["inbound_id"] for r in store.conn.execute("SELECT payload FROM outbox WHERE status!='delivered'")}
    opted = {r["id"] for r in store.conn.execute(
        "SELECT i.id FROM inbound i JOIN suppressions s ON s.addr=i.from_addr WHERE s.reason='opt_out'")}
    for iid in interested - got - pending - opted:
        v["interested_without_handoff"].append(iid)
    counts = Counter(h["inbound_id"] for h in handoffs)
    for iid, n in counts.items():
        if n > 1:
            v["handoff_delivered_twice"].append({"inbound": iid, "count": n})
    return {k: val for k, val in v.items()}
