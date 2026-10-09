"""SQLite persistence with an append-only event log.

Rules this module enforces structurally:

* Every state change goes through ``set_enrollment_state`` / ``set_message_status``,
  which write the new state and an event row in the same transaction. ``replay``
  rebuilds state from events alone and diffs it against the tables, so a code
  path that changes state without an event is detectable.
* Writers use ``BEGIN IMMEDIATE`` so concurrent dispatchers (threads or
  processes) serialize on claims instead of double-sending.
* One database file per client/workspace is the tenant boundary.
"""

from __future__ import annotations

import json
import random
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Campaign, EnrollmentState, Lead, MessageStatus
from .normalize import Consent
from .timeutil import Clock, ts

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS leads (
  id TEXT PRIMARY KEY,
  external_id TEXT,
  first_name TEXT, last_name TEXT,
  email TEXT, phone TEXT, timezone TEXT,
  tags TEXT NOT NULL DEFAULT '[]',
  sms_consent TEXT NOT NULL DEFAULT 'unknown',
  email_consent TEXT NOT NULL DEFAULT 'unknown',
  notes TEXT NOT NULL DEFAULT '',
  source TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS leads_phone ON leads(phone) WHERE phone IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS leads_email ON leads(email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS leads_external ON leads(external_id);

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  spec TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL REFERENCES leads(id),
  campaign_id TEXT NOT NULL REFERENCES campaigns(id),
  state TEXT NOT NULL,
  step_index INTEGER NOT NULL DEFAULT 0,
  next_due_at TEXT,
  plan_lease_until TEXT,
  outcome TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (lead_id, campaign_id)
);
CREATE INDEX IF NOT EXISTS enrollments_due ON enrollments(state, next_due_at);
CREATE INDEX IF NOT EXISTS enrollments_lead ON enrollments(lead_id);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'outreach',
  enrollment_id TEXT REFERENCES enrollments(id),
  lead_id TEXT REFERENCES leads(id),
  campaign_id TEXT,
  step_index INTEGER,
  channel TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT,
  body TEXT NOT NULL,
  composed_by TEXT NOT NULL,
  status TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  lease_owner TEXT, lease_until TEXT,
  provider_id TEXT, last_error TEXT,
  held_from TEXT,
  approved_by TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sent_at TEXT
);
CREATE INDEX IF NOT EXISTS messages_ready ON messages(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS messages_to ON messages(to_addr, status, sent_at);
CREATE INDEX IF NOT EXISTS messages_enrollment ON messages(enrollment_id);
CREATE INDEX IF NOT EXISTS messages_campaign_sent ON messages(campaign_id, status, sent_at, kind);
CREATE INDEX IF NOT EXISTS messages_lead ON messages(lead_id, status);

CREATE TABLE IF NOT EXISTS inbound (
  id TEXT PRIMARY KEY,
  provider_id TEXT UNIQUE,
  channel TEXT NOT NULL,
  from_addr TEXT NOT NULL,
  body TEXT NOT NULL,
  received_at TEXT NOT NULL,
  lead_id TEXT, enrollment_id TEXT,
  label TEXT, label_source TEXT, rule_id TEXT,
  needs_review INTEGER NOT NULL DEFAULT 0,
  possible_opt_out INTEGER NOT NULL DEFAULT 0,
  resolved_by TEXT, resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS inbound_review ON inbound(needs_review, resolved_at);
CREATE INDEX IF NOT EXISTS inbound_lead_review ON inbound(lead_id, needs_review, resolved_at);

CREATE TABLE IF NOT EXISTS send_counters (
  campaign_id TEXT NOT NULL,
  day TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (campaign_id, day)
);

CREATE TABLE IF NOT EXISTS suppressions (
  addr TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  source TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  type TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  actor TEXT NOT NULL DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS events_entity ON events(entity, entity_id);

CREATE TABLE IF NOT EXISTS outbox (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  dedupe_key TEXT NOT NULL UNIQUE,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  purpose TEXT NOT NULL,
  model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  cost_usd REAL NOT NULL,
  outcome TEXT NOT NULL
);
"""


class IdGen:
    """Time-sortable ids. Seedable so simulator runs are reproducible."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed) if seed is not None else None
        self._lock = threading.Lock()

    def new(self, prefix: str, now: datetime) -> str:
        with self._lock:
            tail = f"{self._rng.getrandbits(48):012x}" if self._rng else secrets.token_hex(6)
        return f"{prefix}_{int(now.timestamp() * 1000):012x}{tail}"


class Store:
    def __init__(self, path: str | Path, clock: Clock | None = None, ids: IdGen | None = None) -> None:
        self.path = str(path)
        self.clock = clock or Clock()
        self.ids = ids or IdGen()
        self.conn = sqlite3.connect(self.path, isolation_level=None, timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=30000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def clone(self) -> Store:
        """A new connection to the same database (one per thread/worker)."""
        if self.path == ":memory:":
            raise ValueError("in-memory stores cannot be shared across connections")
        return Store(self.path, self.clock, self.ids)

    def close(self) -> None:
        self.conn.close()

    def _migrate(self) -> None:
        (version,) = self.conn.execute("PRAGMA user_version").fetchone()
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"database schema v{version} is newer than this code (v{SCHEMA_VERSION})")
        if version < SCHEMA_VERSION:
            # executescript() would implicitly COMMIT an open transaction, so the
            # script carries its own; IF NOT EXISTS makes concurrent inits safe.
            self.conn.executescript(
                "BEGIN IMMEDIATE;" + SCHEMA + f"PRAGMA user_version={SCHEMA_VERSION};COMMIT;"
            )

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        if self.conn.in_transaction:
            # Nested use joins the outer transaction (single writer per connection).
            yield self.conn
            return
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def now(self) -> datetime:
        return self.clock.now()

    def new_id(self, prefix: str) -> str:
        return self.ids.new(prefix, self.now())

    # ------------------------------------------------------------ events

    def emit(self, entity: str, entity_id: str, type_: str, data: dict[str, Any] | None = None,
             actor: str = "system") -> None:
        if not self.conn.in_transaction:
            raise RuntimeError("events must be emitted inside a transaction with the change they record")
        self.conn.execute(
            "INSERT INTO events (ts, entity, entity_id, type, data, actor) VALUES (?,?,?,?,?,?)",
            (ts(self.now()), entity, entity_id, type_, json.dumps(data or {}, sort_keys=True, default=str), actor),
        )

    # ------------------------------------------------------------ state transitions

    def set_enrollment_state(self, enrollment_id: str, state: EnrollmentState, *, reason: str,
                             actor: str = "system", **fields: Any) -> None:
        allowed = {"step_index", "next_due_at", "outcome"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"unexpected enrollment fields {bad}")
        sets = ["state=?", "updated_at=?"] + [f"{k}=?" for k in fields]
        vals: list[Any] = [state.value, ts(self.now()), *fields.values(), enrollment_id]
        with self.tx():
            cur = self.conn.execute(f"UPDATE enrollments SET {', '.join(sets)} WHERE id=?", vals)
            if cur.rowcount != 1:
                raise KeyError(enrollment_id)
            self.emit("enrollment", enrollment_id, "enrollment.state", {"state": state.value, "reason": reason, **fields}, actor)

    def set_message_status(self, message_id: str, status: MessageStatus, *, reason: str,
                           actor: str = "system", expect: frozenset[MessageStatus] | None = None,
                           owner: str | None = None, **fields: Any) -> bool:
        """Transition a message. With ``expect``, only if the current status is in it; with ``owner``,
        only if this worker still holds the lease (compare-and-set). Returns False when a guard fails."""
        allowed = {"attempts", "next_attempt_at", "lease_owner", "lease_until", "provider_id", "last_error",
                   "sent_at", "body", "subject", "composed_by", "held_from", "approved_by"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"unexpected message fields {bad}")
        sets = ["status=?", "updated_at=?"] + [f"{k}=?" for k in fields]
        vals: list[Any] = [status.value, ts(self.now()), *fields.values(), message_id]
        where = "id=?"
        if expect is not None:
            where += f" AND status IN ({','.join('?' * len(expect))})"
            vals += [s.value for s in expect]
        if owner is not None:
            where += " AND lease_owner=?"
            vals.append(owner)
        with self.tx():
            cur = self.conn.execute(f"UPDATE messages SET {', '.join(sets)} WHERE {where}", vals)
            if cur.rowcount != 1:
                return False
            safe = {k: v for k, v in fields.items() if k not in ("body", "subject")}
            self.emit("message", message_id, "message.status", {"status": status.value, "reason": reason, **safe}, actor)
            return True

    # ------------------------------------------------------------ leads

    def get_lead(self, lead_id: str) -> Lead | None:
        row = self.conn.execute("SELECT * FROM leads WHERE id=?", (lead_id,)).fetchone()
        return _lead(row) if row else None

    def find_lead_by_addr(self, addr: str) -> Lead | None:
        row = self.conn.execute("SELECT * FROM leads WHERE phone=? OR email=? ORDER BY created_at LIMIT 1",
                                (addr, addr)).fetchone()
        return _lead(row) if row else None

    # ------------------------------------------------------------ campaigns

    def save_campaign(self, campaign: Campaign, actor: str = "operator") -> None:
        now = ts(self.now())
        spec = campaign.model_dump_json()
        with self.tx():
            existing = self.conn.execute("SELECT spec FROM campaigns WHERE id=?", (campaign.id,)).fetchone()
            if existing:
                self.conn.execute("UPDATE campaigns SET spec=?, updated_at=? WHERE id=?", (spec, now, campaign.id))
                self.emit("campaign", campaign.id, "campaign.updated", {}, actor)
            else:
                self.conn.execute("INSERT INTO campaigns (id, spec, status, created_at, updated_at) VALUES (?,?,?,?,?)",
                                  (campaign.id, spec, "active", now, now))
                self.emit("campaign", campaign.id, "campaign.created", {}, actor)

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        row = self.conn.execute("SELECT spec FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        return Campaign.model_validate_json(row["spec"]) if row else None

    def campaign_status(self, campaign_id: str) -> str | None:
        row = self.conn.execute("SELECT status FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        return row["status"] if row else None

    def set_campaign_status(self, campaign_id: str, status: str, actor: str = "operator") -> None:
        if status not in ("active", "paused"):
            raise ValueError(status)
        with self.tx():
            cur = self.conn.execute("UPDATE campaigns SET status=?, updated_at=? WHERE id=?",
                                    (status, ts(self.now()), campaign_id))
            if cur.rowcount != 1:
                raise KeyError(campaign_id)
            self.emit("campaign", campaign_id, f"campaign.{status}", {}, actor)

    def lead_under_review(self, lead_id: str) -> bool:
        """A lead with any unresolved flagged reply must not be contacted, whatever campaign asks."""
        return self.conn.execute(
            "SELECT 1 FROM inbound WHERE lead_id=? AND needs_review=1 AND resolved_at IS NULL LIMIT 1", (lead_id,)
        ).fetchone() is not None

    # ------------------------------------------------------------ suppression

    def is_suppressed(self, *addrs: str | None) -> str | None:
        vals = [a for a in addrs if a]
        if not vals:
            return None
        row = self.conn.execute(
            f"SELECT reason FROM suppressions WHERE addr IN ({','.join('?' * len(vals))}) LIMIT 1", vals
        ).fetchone()
        return row["reason"] if row else None

    def suppress(self, addr: str, reason: str, source: str, actor: str = "system") -> bool:
        with self.tx():
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO suppressions (addr, reason, source, created_at) VALUES (?,?,?,?)",
                (addr, reason, source, ts(self.now())),
            )
            if cur.rowcount:
                self.emit("suppression", addr, "suppression.added", {"reason": reason, "source": source}, actor)
            return bool(cur.rowcount)


def _lead(row: sqlite3.Row) -> Lead:
    return Lead(
        id=row["id"], external_id=row["external_id"], first_name=row["first_name"], last_name=row["last_name"],
        email=row["email"], phone=row["phone"], timezone=row["timezone"], tags=tuple(json.loads(row["tags"])),
        sms_consent=Consent(row["sms_consent"]), email_consent=Consent(row["email_consent"]),
        notes=row["notes"], source=row["source"],
    )
