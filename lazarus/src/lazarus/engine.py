"""The reactivation engine: a durable state machine over SQLite.

    enroll -> plan (compose + gate) -> [approve] -> dispatch (lease, gate, send) -> advance
    inbound reply -> classify -> route (suppress / handoff / snooze / close / pause for human)

Delivery is *at-most-once*: a message whose outcome is ambiguous (timeout after
the request left, worker crash mid-send) goes to ``unknown`` and is resolved by
provider lookup or a human — never by blind resend. For reactivation outreach a
missed touch is cheap; a duplicate text to someone who may already be annoyed
is not.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .channels import Channel, Outbound, SendResult
from .classify import Classification, classify
from .compose import compose, finalize
from .llm import LLMProvider
from .models import (
    OPEN_MESSAGE,
    TERMINAL_ENROLLMENT,
    Campaign,
    EnrollmentState,
    Label,
    Lead,
    MessageStatus,
)
from .normalize import normalize_email, normalize_phone
from .policy import address_for, check_send, static_checks
from .store import Store
from .timeutil import parse_ts, ts

S = EnrollmentState
M = MessageStatus


@dataclass
class EngineConfig:
    lease_seconds: int = 120
    plan_batch: int = 500
    dispatch_batch: int = 200
    backoff_base_s: int = 60
    backoff_max_s: int = 6 * 3600
    optout_confirmation_window_s: int = 300
    outbox_max_attempts: int = 12


Sink = Callable[[str, dict[str, Any]], None]  # (kind, payload) -> raises on failure


class Engine:
    def __init__(self, store: Store, channels: Mapping[str, Channel], llm: LLMProvider | None = None,
                 config: EngineConfig | None = None, worker_id: str = "worker-1", sink: Sink | None = None) -> None:
        self.store = store
        self.channels = dict(channels)
        self.llm = llm
        self.cfg = config or EngineConfig()
        self.worker_id = worker_id
        self.sink = sink
        self._campaigns: dict[str, Campaign] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers

    def now(self) -> datetime:
        return self.store.now()

    def campaign(self, cid: str) -> Campaign:
        with self._lock:
            c = self._campaigns.get(cid)
        if c is None:
            c = self.store.get_campaign(cid)
            if c is None:
                raise KeyError(f"campaign {cid}")
            with self._lock:
                self._campaigns[cid] = c
        return c

    def invalidate_campaign_cache(self) -> None:
        with self._lock:
            self._campaigns.clear()

    def _enrollment(self, eid: str) -> Any:
        return self.store.conn.execute("SELECT * FROM enrollments WHERE id=?", (eid,)).fetchone()

    def _backoff(self, attempts: int, retry_after: float | None) -> timedelta:
        secs = min(self.cfg.backoff_base_s * (2 ** max(attempts - 1, 0)), self.cfg.backoff_max_s)
        if retry_after:
            secs = max(secs, int(retry_after))
        return timedelta(seconds=secs)

    # ------------------------------------------------------------------ enrollment

    def enroll(self, campaign_id: str, lead_ids: list[str] | None = None, tag: str | None = None,
               actor: str = "operator") -> int:
        self.campaign(campaign_id)  # existence check
        q = "SELECT id FROM leads"
        args: list[Any] = []
        if lead_ids is not None:
            q += f" WHERE id IN ({','.join('?' * len(lead_ids))})" if lead_ids else " WHERE 0"
            args = list(lead_ids)
        rows = [r["id"] for r in self.store.conn.execute(q, args)]
        if tag:
            tagged = {r["id"] for r in self.store.conn.execute(
                "SELECT leads.id FROM leads, json_each(leads.tags) WHERE json_each.value=?", (tag.lower(),))}
            rows = [r for r in rows if r in tagged]
        created = 0
        now = ts(self.now())
        for i in range(0, len(rows), 500):
            with self.store.tx():
                for lid in rows[i:i + 500]:
                    eid = self.store.new_id("enr")
                    cur = self.store.conn.execute(
                        """INSERT OR IGNORE INTO enrollments (id, lead_id, campaign_id, state, step_index, next_due_at,
                           created_at, updated_at) VALUES (?,?,?,?,0,?,?,?)""",
                        (eid, lid, campaign_id, S.ACTIVE.value, now, now, now),
                    )
                    if cur.rowcount:
                        created += 1
                        self.store.emit("enrollment", eid, "enrollment.state",
                                        {"state": S.ACTIVE.value, "reason": "enrolled", "lead_id": lid,
                                         "campaign_id": campaign_id, "step_index": 0}, actor)
        return created

    # ------------------------------------------------------------------ plan

    def _needs_approval(self, campaign: Campaign, composed_by: str) -> bool:
        if composed_by == "llm" and campaign.approve_llm_messages:
            return True
        if campaign.approve_first_n:
            (n,) = self.store.conn.execute(
                "SELECT COUNT(*) FROM messages WHERE campaign_id=? AND kind='outreach' AND status NOT IN ('canceled')",
                (campaign.id,),
            ).fetchone()
            return bool(n < campaign.approve_first_n)
        return False

    def plan(self, now: datetime | None = None) -> Counter[str]:
        now = now or self.now()
        out: Counter[str] = Counter()
        rows = self.store.conn.execute(
            """SELECT e.* FROM enrollments e JOIN campaigns c ON c.id=e.campaign_id
               WHERE e.state=? AND e.next_due_at<=? AND c.status='active' ORDER BY e.next_due_at LIMIT ?""",
            (S.ACTIVE.value, ts(now), self.cfg.plan_batch),
        ).fetchall()
        for e in rows:
            campaign = self.campaign(e["campaign_id"])
            lead = self.store.get_lead(e["lead_id"])
            assert lead is not None
            step_index = e["step_index"]
            if step_index >= len(campaign.steps):
                self._cas_enrollment(e["id"], {S.ACTIVE}, step_index, S.EXHAUSTED, "sequence_complete")
                out["exhausted"] += 1
                continue
            step = campaign.steps[step_index]
            gate = static_checks(self.store, lead, campaign, step.channel)
            if not gate.allowed:
                self._cas_enrollment(e["id"], {S.ACTIVE}, step_index, S.BLOCKED, gate.reason, outcome=gate.reason)
                out[f"blocked:{gate.reason}"] += 1
                continue
            is_first = not self.store.conn.execute(
                "SELECT 1 FROM messages WHERE enrollment_id=? AND channel=? AND status IN ('sent','unknown') LIMIT 1",
                (e["id"], step.channel),
            ).fetchone()
            composed = compose(step, lead, campaign, is_first=is_first, llm=self.llm)  # may call LLM: outside tx
            body, subject = finalize(composed, step, campaign, is_first=is_first)
            status = M.PENDING_APPROVAL if self._needs_approval(campaign, composed.composed_by) else M.QUEUED
            addr = address_for(lead, step.channel)
            assert addr is not None
            with self.store.tx():
                cur = self._enrollment(e["id"])
                if cur["state"] != S.ACTIVE.value or cur["step_index"] != step_index:
                    out["skipped_changed"] += 1  # an inbound reply changed it while we composed
                    continue
                prior = [r["status"] for r in self.store.conn.execute(
                    "SELECT status FROM messages WHERE enrollment_id=? AND step_index=? AND kind='outreach'",
                    (e["id"], step_index))]
                if M.SENT.value in prior:
                    # Step already delivered (e.g. sent while the lead was paused): move on, don't resend.
                    self.store.set_enrollment_state(e["id"], S.AWAITING_SEND, reason="step_already_sent")
                    self._advance(e["id"], step_index, now)
                    out["already_sent"] += 1
                    continue
                if any(st in (M.SENDING.value, M.UNKNOWN.value, M.QUEUED.value, M.PENDING_APPROVAL.value, M.HELD.value)
                       for st in prior):
                    self.store.set_enrollment_state(e["id"], S.AWAITING_SEND, reason="message_in_flight")
                    out["in_flight"] += 1
                    continue
                mid = self.store.new_id("msg")
                # Generation suffix: a step whose earlier message was canceled/rejected gets a fresh key;
                # a step can never have two live messages.
                key = f"{e['id']}:{step_index}:{len(prior)}"
                ins = self.store.conn.execute(
                    """INSERT OR IGNORE INTO messages (id, kind, enrollment_id, lead_id, campaign_id, step_index, channel,
                       to_addr, subject, body, composed_by, status, idempotency_key, attempts, next_attempt_at,
                       created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
                    (mid, "outreach", e["id"], lead.id, campaign.id, step_index, step.channel, addr, subject, body,
                     composed.composed_by, status.value, key, ts(now), ts(now), ts(now)),
                )
                if not ins.rowcount:
                    out["duplicate_step"] += 1  # idempotency key already used: never create a second message
                    self.store.set_enrollment_state(e["id"], S.AWAITING_SEND, reason="message_exists")
                    continue
                self.store.emit("message", mid, "message.status",
                                {"status": status.value, "reason": "planned", "enrollment_id": e["id"],
                                 "step_index": step_index, "composed_by": composed.composed_by})
                if composed.guard_violations:
                    self.store.emit("message", mid, "compose.llm_rejected", {"violations": composed.guard_violations})
                if composed.llm_error:
                    self.store.emit("message", mid, "compose.llm_error", {"error": composed.llm_error})
                self.store.set_enrollment_state(e["id"], S.AWAITING_SEND, reason="planned")
            out[status.value] += 1
        return out

    def _cas_enrollment(self, eid: str, expect: set[EnrollmentState], step_index: int | None,
                        new: EnrollmentState, reason: str, actor: str = "system", **fields: Any) -> bool:
        with self.store.tx():
            cur = self._enrollment(eid)
            if cur is None or cur["state"] not in {s.value for s in expect}:
                return False
            if step_index is not None and cur["step_index"] != step_index:
                return False
            self.store.set_enrollment_state(eid, new, reason=reason, actor=actor, **fields)
            return True

    # ------------------------------------------------------------------ approvals

    def approve(self, message_id: str, actor: str, body: str | None = None) -> bool:
        fields: dict[str, Any] = {"next_attempt_at": ts(self.now())}
        if body is not None:
            fields["body"] = body
            fields["composed_by"] = "human"
        return self.store.set_message_status(message_id, M.QUEUED, reason="approved", actor=actor,
                                             expect=frozenset({M.PENDING_APPROVAL}), **fields)

    def reject(self, message_id: str, actor: str, reason: str = "rejected") -> bool:
        with self.store.tx():
            row = self.store.conn.execute("SELECT enrollment_id FROM messages WHERE id=?", (message_id,)).fetchone()
            ok = self.store.set_message_status(message_id, M.REJECTED, reason=reason, actor=actor,
                                               expect=frozenset({M.PENDING_APPROVAL}))
            if ok and row and row["enrollment_id"]:
                self._cas_enrollment(row["enrollment_id"], {S.AWAITING_SEND}, None, S.PAUSED, "message_rejected", actor)
            return ok

    # ------------------------------------------------------------------ dispatch

    def dispatch(self, now: datetime | None = None, limit: int | None = None) -> Counter[str]:
        now = now or self.now()
        out: Counter[str] = Counter()
        claimed: list[Any] = []
        with self.store.tx():
            rows = self.store.conn.execute(
                "SELECT * FROM messages WHERE status=? AND next_attempt_at<=? ORDER BY next_attempt_at LIMIT ?",
                (M.QUEUED.value, ts(now), limit or self.cfg.dispatch_batch),
            ).fetchall()
            for r in rows:
                if self.store.set_message_status(
                    r["id"], M.SENDING, reason="claimed", expect=frozenset({M.QUEUED}),
                    attempts=r["attempts"] + 1, lease_owner=self.worker_id,
                    lease_until=ts(now + timedelta(seconds=self.cfg.lease_seconds)),
                ):
                    claimed.append(r)
        for r in claimed:
            out[self._dispatch_one(r, now)] += 1
        return out

    def _dispatch_one(self, r: Any, now: datetime) -> str:
        mid = r["id"]
        if r["kind"] == "optout_confirmation":
            if now - parse_ts(r["created_at"]) > timedelta(seconds=self.cfg.optout_confirmation_window_s):
                self.store.set_message_status(mid, M.CANCELED, reason="confirmation_window_passed")
                return "canceled:confirmation_late"
        else:
            lead = self.store.get_lead(r["lead_id"])
            assert lead is not None
            campaign = self.campaign(r["campaign_id"])
            enr = self._enrollment(r["enrollment_id"])
            if enr["state"] != S.AWAITING_SEND.value:
                self.store.set_message_status(mid, M.CANCELED, reason=f"enrollment_{enr['state']}")
                return "canceled:enrollment_changed"
            d = check_send(self.store, lead, campaign, r["channel"], now, exclude_message_id=mid)
            if not d.allowed:
                if d.permanent:
                    with self.store.tx():
                        self.store.set_message_status(mid, M.CANCELED, reason=d.reason)
                        self._cas_enrollment(r["enrollment_id"], {S.AWAITING_SEND}, None, S.BLOCKED, d.reason, outcome=d.reason)
                    return f"blocked:{d.reason}"
                self.store.set_message_status(mid, M.QUEUED, reason=f"deferred:{d.reason}", attempts=r["attempts"],
                                              next_attempt_at=ts(d.retry_at or now), lease_owner=None, lease_until=None)
                return f"deferred:{d.reason}"
            # Last-moment suppression check: narrows the opt-out race to the provider call itself.
            if self.store.is_suppressed(lead.phone, lead.email):
                self.store.set_message_status(mid, M.CANCELED, reason="suppressed_at_send")
                return "canceled:suppressed_at_send"

        channel = self.channels.get(r["channel"])
        if channel is None:
            self.store.set_message_status(mid, M.QUEUED, reason="no_channel_configured", attempts=r["attempts"],
                                          next_attempt_at=ts(now + timedelta(hours=1)), lease_owner=None, lease_until=None)
            return "deferred:no_channel"
        msg = Outbound(mid, r["idempotency_key"], r["channel"], r["to_addr"], r["body"], r["subject"])
        try:
            res = channel.send(msg)
        except Exception as e:  # noqa: BLE001 - an adapter bug must not become a resend
            res = SendResult("ambiguous", error=f"adapter exception: {type(e).__name__}: {e}")
        return self._record_result(r, res, now)

    def _record_result(self, r: Any, res: SendResult, now: datetime) -> str:
        mid = r["id"]
        attempts = r["attempts"] + 1
        with self.store.tx():
            if res.outcome == "sent":
                self.store.set_message_status(mid, M.SENT, reason="sent", provider_id=res.provider_id,
                                              sent_at=ts(now), lease_owner=None, lease_until=None,
                                              expect=frozenset({M.SENDING, M.UNKNOWN}))
                if r["enrollment_id"]:
                    self._advance(r["enrollment_id"], r["step_index"], now)
                return "sent"
            if res.outcome == "transient":
                campaign_max = self.campaign(r["campaign_id"]).max_send_attempts if r["campaign_id"] else 3
                if attempts >= campaign_max:
                    self.store.set_message_status(mid, M.FAILED, reason="max_attempts", last_error=res.error,
                                                  lease_owner=None, lease_until=None)
                    if r["enrollment_id"]:
                        self._cas_enrollment(r["enrollment_id"], {S.AWAITING_SEND}, None, S.FAILED, "max_attempts")
                    return "failed:max_attempts"
                self.store.set_message_status(mid, M.QUEUED, reason="transient_error", last_error=res.error,
                                              next_attempt_at=ts(now + self._backoff(attempts, res.retry_after_s)),
                                              lease_owner=None, lease_until=None)
                return "retry"
            if res.outcome == "permanent":
                self.store.set_message_status(mid, M.FAILED, reason="permanent_error", last_error=res.error,
                                              lease_owner=None, lease_until=None)
                if res.suppress:
                    self.store.suppress(r["to_addr"], "invalid_destination", source=f"provider:{r['channel']}")
                if r["enrollment_id"]:
                    self._cas_enrollment(r["enrollment_id"], {S.AWAITING_SEND}, None, S.FAILED, "permanent_error")
                return "failed:permanent"
            self.store.set_message_status(mid, M.UNKNOWN, reason="ambiguous_outcome", last_error=res.error,
                                          lease_owner=None, lease_until=None)
            return "unknown"

    def _advance(self, eid: str, step_index: int, now: datetime) -> None:
        enr = self._enrollment(eid)
        if enr is None or enr["state"] != S.AWAITING_SEND.value or enr["step_index"] != step_index:
            return  # a reply (opt-out, handoff, snooze) already moved it; don't resurrect
        campaign = self.campaign(enr["campaign_id"])
        nxt = step_index + 1
        if nxt < len(campaign.steps):
            due = now + timedelta(hours=campaign.steps[nxt].delay_hours)
        else:
            due = now + timedelta(hours=campaign.exhaust_after_hours)
        self.store.set_enrollment_state(eid, S.ACTIVE, reason="step_sent", step_index=nxt, next_due_at=ts(due))

    # ------------------------------------------------------------------ reconcile

    def reconcile(self, now: datetime | None = None) -> Counter[str]:
        """Expired leases (crashed workers) and unknown outcomes: ask the provider, never resend blind."""
        now = now or self.now()
        out: Counter[str] = Counter()
        rows = self.store.conn.execute(
            "SELECT * FROM messages WHERE (status=? AND lease_until<?) OR status=? LIMIT 500",
            (M.SENDING.value, ts(now), M.UNKNOWN.value),
        ).fetchall()
        for r in rows:
            ch = self.channels.get(r["channel"])
            found = ch.lookup(r["idempotency_key"]) if ch else None
            if found is not None and found.outcome == "sent":
                with self.store.tx():
                    ok = self.store.set_message_status(r["id"], M.SENT, reason="reconciled_sent", provider_id=found.provider_id,
                                                       sent_at=r["lease_until"] or ts(now), lease_owner=None, lease_until=None,
                                                       expect=frozenset({M.SENDING, M.UNKNOWN}))
                    if ok and r["enrollment_id"]:
                        self._advance(r["enrollment_id"], r["step_index"], now)
                out["reconciled_sent"] += 1
            elif found is not None and found.outcome == "permanent":
                # Provider definitively never received it: safe to send again.
                self.store.set_message_status(r["id"], M.QUEUED, reason="reconciled_not_sent", next_attempt_at=ts(now),
                                              lease_owner=None, lease_until=None, expect=frozenset({M.SENDING, M.UNKNOWN}))
                out["reconciled_requeued"] += 1
            elif r["status"] == M.SENDING.value:
                self.store.set_message_status(r["id"], M.UNKNOWN, reason="lease_expired", lease_owner=None,
                                              lease_until=None, expect=frozenset({M.SENDING}))
                out["lease_expired_unknown"] += 1
            else:
                out["still_unknown"] += 1
        return out

    def resolve_unknown(self, message_id: str, sent: bool, actor: str) -> bool:
        """Human reconciliation of an ambiguous send (after checking the provider console)."""
        row = self.store.conn.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        if row is None or row["status"] != M.UNKNOWN.value:
            return False
        now = self.now()
        with self.store.tx():
            if sent:
                self.store.set_message_status(message_id, M.SENT, reason="human_confirmed_sent", actor=actor,
                                              sent_at=ts(now), expect=frozenset({M.UNKNOWN}))
                if row["enrollment_id"]:
                    self._advance(row["enrollment_id"], row["step_index"], now)
            else:
                self.store.set_message_status(message_id, M.QUEUED, reason="human_confirmed_not_sent", actor=actor,
                                              next_attempt_at=ts(now), expect=frozenset({M.UNKNOWN}))
        return True

    # ------------------------------------------------------------------ inbound

    def handle_inbound(self, channel: str, from_raw: str, body: str, provider_id: str | None = None,
                       received_at: datetime | None = None) -> dict[str, Any]:
        now = received_at or self.now()
        addr = normalize_phone(from_raw) if channel == "sms" else normalize_email(from_raw)
        addr = addr or from_raw.strip()[:320]
        if provider_id:
            prev = self.store.conn.execute("SELECT * FROM inbound WHERE provider_id=?", (provider_id,)).fetchone()
            if prev:
                return {"inbound_id": prev["id"], "label": prev["label"], "duplicate": True}
        lead = self.store.find_lead_by_addr(addr)
        c = classify(body, llm=self.llm, first_name=lead.first_name if lead else None)
        enr = None
        if lead:
            enr = self.store.conn.execute(
                "SELECT * FROM enrollments WHERE lead_id=? ORDER BY updated_at DESC LIMIT 1", (lead.id,)).fetchone()
        iid = self.store.new_id("in")
        with self.store.tx():
            try:
                self.store.conn.execute(
                    """INSERT INTO inbound (id, provider_id, channel, from_addr, body, received_at, lead_id, enrollment_id,
                       label, label_source, rule_id, needs_review, possible_opt_out) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (iid, provider_id, channel, addr, body[:5000], ts(now), lead.id if lead else None,
                     enr["id"] if enr else None, c.label.value, c.source, ",".join(c.rule_ids)[:500],
                     int(c.needs_review), int(c.possible_opt_out)),
                )
            except Exception as e:
                if "UNIQUE" in str(e) and provider_id:  # concurrent duplicate webhook delivery
                    prev = self.store.conn.execute("SELECT * FROM inbound WHERE provider_id=?", (provider_id,)).fetchone()
                    return {"inbound_id": prev["id"], "label": prev["label"], "duplicate": True}
                raise
            self.store.emit("inbound", iid, "inbound.received", {**c.as_dict(), "lead_id": lead.id if lead else None})
            actions = self._route(iid, addr, channel, lead, c, now)
        return {"inbound_id": iid, "label": c.label.value, "needs_review": c.needs_review,
                "possible_opt_out": c.possible_opt_out, "actions": actions, "duplicate": False}

    def _open_enrollments(self, lead_id: str) -> list[Any]:
        return self.store.conn.execute(
            f"SELECT * FROM enrollments WHERE lead_id=? AND state NOT IN ({','.join('?' * len(TERMINAL_ENROLLMENT))})",
            (lead_id, *[s.value for s in TERMINAL_ENROLLMENT]),
        ).fetchall()

    def _cancel_open(self, lead_id: str, reason: str, statuses: frozenset[MessageStatus] = OPEN_MESSAGE,
                     enrollment_id: str | None = None) -> int:
        q = f"SELECT id FROM messages WHERE lead_id=? AND kind='outreach' AND status IN ({','.join('?' * len(statuses))})"
        args: list[Any] = [lead_id, *[s.value for s in statuses]]
        if enrollment_id:
            q += " AND enrollment_id=?"
            args.append(enrollment_id)
        n = 0
        for row in self.store.conn.execute(q, args).fetchall():
            n += self.store.set_message_status(row["id"], M.CANCELED, reason=reason, expect=statuses)
        return n

    def _route(self, iid: str, addr: str, channel: str, lead: Lead | None, c: Classification,
               now: datetime) -> list[str]:
        """Apply the consequences of a classified reply. Runs inside the inbound transaction."""
        acts: list[str] = []
        label = c.label
        if label is Label.OPT_OUT:
            addrs = {addr} | ({lead.phone, lead.email} - {None} if lead else set())
            for a in sorted(a for a in addrs if a):
                if self.store.suppress(a, "opt_out", source=f"inbound:{iid}"):
                    acts.append(f"suppressed:{a}")
            if lead:
                for e in self._open_enrollments(lead.id):
                    self.store.set_enrollment_state(e["id"], S.OPTED_OUT, reason="opt_out_reply", outcome="opt_out")
                acts.append(f"canceled:{self._cancel_open(lead.id, 'opt_out')}")
                self._queue_optout_confirmation(lead, addr, channel, now)
            return acts
        if lead is None:
            if c.needs_review or label is not Label.AUTO_REPLY:
                self._flag_review(iid)
                acts.append("review:unknown_sender")
            return acts
        if label is Label.WRONG_NUMBER:
            if channel == "sms" and lead.phone == addr:
                self.store.suppress(addr, "wrong_number", source=f"inbound:{iid}")
                acts.append(f"suppressed:{addr}")
            for e in self._open_enrollments(lead.id):
                self.store.set_enrollment_state(e["id"], S.WRONG_NUMBER, reason="wrong_number_reply", outcome="wrong_number")
            acts.append(f"canceled:{self._cancel_open(lead.id, 'wrong_number')}")
            return acts
        if label is Label.AUTO_REPLY and not c.needs_review:
            return ["ignored:auto_reply"]

        opted_out = self.store.is_suppressed(lead.phone, lead.email) == "opt_out"
        if c.needs_review or opted_out:
            # Ambiguous, possible opt-out, or a previously opted-out person writing back: a human decides.
            self._flag_review(iid)
            for e in self._open_enrollments(lead.id):
                if e["state"] != S.PAUSED.value:
                    self.store.set_enrollment_state(e["id"], S.PAUSED, reason="needs_review")
            held = 0
            for row in self.store.conn.execute(
                "SELECT id, status FROM messages WHERE lead_id=? AND kind='outreach' AND status IN ('queued','pending_approval')",
                (lead.id,)).fetchall():
                held += self.store.set_message_status(row["id"], M.HELD, reason="lead_under_review",
                                                      expect=frozenset({M.QUEUED, M.PENDING_APPROVAL}),
                                                      held_from=row["status"])
            acts += ["review", f"held:{held}"]
            return acts

        latest = self.store.conn.execute(
            "SELECT * FROM enrollments WHERE lead_id=? ORDER BY updated_at DESC LIMIT 1", (lead.id,)).fetchone()
        if label is Label.INTERESTED:
            targets = self._open_enrollments(lead.id) or ([latest] if latest and latest["state"] in
                                                           (S.EXHAUSTED.value, S.NOT_INTERESTED.value) else [])
            for e in targets:
                self.store.set_enrollment_state(e["id"], S.HANDED_OFF, reason="interested_reply", outcome="interested")
            acts.append(f"canceled:{self._cancel_open(lead.id, 'handed_off')}")
            self._outbox("handoff", f"handoff:{iid}", self._handoff_payload(iid, lead, latest, c))
            acts.append("handoff")
            return acts
        if label is Label.LATER:
            campaign = self.campaign(latest["campaign_id"]) if latest else None
            days = campaign.snooze_days_on_later if campaign else 30
            for e in self._open_enrollments(lead.id):
                self._cancel_open(lead.id, "snoozed", enrollment_id=e["id"])
                self.store.set_enrollment_state(e["id"], S.ACTIVE, reason="later_reply",
                                                next_due_at=ts(now + timedelta(days=days)))
            acts.append(f"snoozed:{days}d")
            return acts
        if label is Label.NOT_INTERESTED:
            for e in self._open_enrollments(lead.id):
                self.store.set_enrollment_state(e["id"], S.NOT_INTERESTED, reason="declined", outcome="not_interested")
            acts.append(f"canceled:{self._cancel_open(lead.id, 'declined')}")
            return acts
        self._flag_review(iid)
        return ["review"]

    def _flag_review(self, iid: str) -> None:
        self.store.conn.execute("UPDATE inbound SET needs_review=1 WHERE id=?", (iid,))

    def _queue_optout_confirmation(self, lead: Lead, addr: str, channel: str, now: datetime) -> None:
        if channel != "sms":
            return
        enr = self.store.conn.execute("SELECT campaign_id FROM enrollments WHERE lead_id=? ORDER BY updated_at DESC LIMIT 1",
                                      (lead.id,)).fetchone()
        if not enr:
            return
        campaign = self.campaign(enr["campaign_id"])
        if not campaign.send_optout_confirmation:
            return
        mid = self.store.new_id("msg")
        body = f"{campaign.business_name}: you're unsubscribed and won't get more messages from us."
        cur = self.store.conn.execute(
            """INSERT OR IGNORE INTO messages (id, kind, lead_id, campaign_id, channel, to_addr, body, composed_by, status,
               idempotency_key, attempts, next_attempt_at, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
            (mid, "optout_confirmation", lead.id, campaign.id, "sms", addr, body, "system", M.QUEUED.value,
             f"optout-confirm:{addr}", ts(now), ts(now), ts(now)),
        )
        if cur.rowcount:  # at most one confirmation per address, ever
            self.store.emit("message", mid, "message.status", {"status": M.QUEUED.value, "reason": "optout_confirmation"})

    def _handoff_payload(self, iid: str, lead: Lead, enr: Any, c: Classification) -> dict[str, Any]:
        msg = self.store.conn.execute("SELECT body, received_at FROM inbound WHERE id=?", (iid,)).fetchone()
        return {
            "type": "lead.interested", "inbound_id": iid,
            "lead": {"id": lead.id, "external_id": lead.external_id, "first_name": lead.first_name,
                     "last_name": lead.last_name, "phone": lead.phone, "email": lead.email},
            "campaign_id": enr["campaign_id"] if enr else None,
            "reply": {"text": msg["body"], "received_at": msg["received_at"]},
            "classification": c.as_dict(),
        }

    def resolve_review(self, inbound_id: str, label: Label, actor: str) -> list[str]:
        """A human labels a flagged reply; routing then proceeds as if the label were automatic."""
        row = self.store.conn.execute("SELECT * FROM inbound WHERE id=?", (inbound_id,)).fetchone()
        if row is None:
            raise KeyError(inbound_id)
        if row["resolved_at"]:
            return ["already_resolved"]
        lead = self.store.get_lead(row["lead_id"]) if row["lead_id"] else None
        c = Classification(label, "rule", rule_ids=["human"], confidence="high")
        with self.store.tx():
            self.store.conn.execute("UPDATE inbound SET resolved_by=?, resolved_at=?, label=?, label_source='human' WHERE id=?",
                                    (actor, ts(self.now()), label.value, inbound_id))
            self.store.emit("inbound", inbound_id, "inbound.resolved", {"label": label.value}, actor)
            if lead and label in (Label.AUTO_REPLY, Label.UNCLEAR):
                return self._resume_lead(lead.id, actor)
            if lead:
                # Release paused enrollments so normal routing can act on them.
                for e in self._open_enrollments(lead.id):
                    if e["state"] == S.PAUSED.value:
                        self.store.set_enrollment_state(e["id"], S.AWAITING_SEND if self._has_held(e["id"]) else S.ACTIVE,
                                                        reason="review_resolved", actor=actor)
                if label is not Label.OPT_OUT:
                    self._release_held(lead.id, actor)
            return self._route(inbound_id, row["from_addr"], row["channel"], lead, c, self.now())

    def _has_held(self, eid: str) -> bool:
        return bool(self.store.conn.execute("SELECT 1 FROM messages WHERE enrollment_id=? AND status='held'", (eid,)).fetchone())

    def _release_held(self, lead_id: str, actor: str) -> int:
        """Return held messages to exactly the status they had (a held draft that still needed
        approval goes back to the approval queue, never straight to sending)."""
        n = 0
        for row in self.store.conn.execute("SELECT id, held_from FROM messages WHERE lead_id=? AND status='held'",
                                           (lead_id,)).fetchall():
            back = M.PENDING_APPROVAL if row["held_from"] == M.PENDING_APPROVAL.value else M.QUEUED
            n += self.store.set_message_status(row["id"], back, reason="released", actor=actor, held_from=None,
                                               next_attempt_at=ts(self.now()), expect=frozenset({M.HELD}))
        return n

    def _resume_lead(self, lead_id: str, actor: str) -> list[str]:
        if self.store.is_suppressed(*[r for r in self.store.conn.execute(
                "SELECT phone, email FROM leads WHERE id=?", (lead_id,)).fetchone()]):
            return ["still_suppressed"]
        n = 0
        for e in self._open_enrollments(lead_id):
            if e["state"] == S.PAUSED.value:
                self.store.set_enrollment_state(e["id"], S.AWAITING_SEND if self._has_held(e["id"]) else S.ACTIVE,
                                                reason="resumed", actor=actor)
                n += 1
        released = self._release_held(lead_id, actor)
        return [f"resumed:{n}", f"released:{released}"]

    # ------------------------------------------------------------------ outbox (CRM handoff)

    def _outbox(self, kind: str, dedupe_key: str, payload: dict[str, Any]) -> None:
        now = ts(self.now())
        cur = self.store.conn.execute(
            """INSERT OR IGNORE INTO outbox (id, kind, dedupe_key, payload, status, attempts, next_attempt_at, created_at, updated_at)
               VALUES (?,?,?,?,'pending',0,?,?,?)""",
            (self.store.new_id("ob"), kind, dedupe_key, json.dumps(payload, sort_keys=True), now, now, now),
        )
        if cur.rowcount:
            self.store.emit("outbox", dedupe_key, "outbox.enqueued", {"kind": kind})

    def deliver_outbox(self, now: datetime | None = None, limit: int = 100) -> Counter[str]:
        now = now or self.now()
        out: Counter[str] = Counter()
        if self.sink is None:
            return out
        rows = self.store.conn.execute(
            "SELECT * FROM outbox WHERE status='pending' AND next_attempt_at<=? ORDER BY created_at LIMIT ?",
            (ts(now), limit)).fetchall()
        for r in rows:
            try:
                self.sink(r["kind"], json.loads(r["payload"]))
            except Exception as e:  # noqa: BLE001 - sink failures are retried
                attempts = r["attempts"] + 1
                dead = attempts >= self.cfg.outbox_max_attempts
                with self.store.tx():
                    self.store.conn.execute(
                        "UPDATE outbox SET status=?, attempts=?, next_attempt_at=?, last_error=?, updated_at=? WHERE id=?",
                        ("dead" if dead else "pending", attempts, ts(now + self._backoff(attempts, None)),
                         f"{type(e).__name__}: {e}"[:300], ts(now), r["id"]))
                    self.store.emit("outbox", r["dedupe_key"], "outbox.dead" if dead else "outbox.retry", {"error": str(e)[:200]})
                out["dead" if dead else "retry"] += 1
                continue
            with self.store.tx():
                self.store.conn.execute("UPDATE outbox SET status='delivered', attempts=attempts+1, updated_at=? WHERE id=?",
                                        (ts(now), r["id"]))
                self.store.emit("outbox", r["dedupe_key"], "outbox.delivered", {})
            out["delivered"] += 1
        return out

    # ------------------------------------------------------------------ tick

    def tick(self, now: datetime | None = None) -> dict[str, dict[str, int]]:
        now = now or self.now()
        return {
            "reconcile": dict(self.reconcile(now)),
            "plan": dict(self.plan(now)),
            "dispatch": dict(self.dispatch(now)),
            "outbox": dict(self.deliver_outbox(now)),
        }
