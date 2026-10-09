"""Event-log replay: rebuild state from events alone and diff it against tables.

If any code path changes ``enrollments.state`` or ``messages.status`` without
writing the matching event (or a row is edited by hand), replay finds it.
Also renders a per-lead timeline for debugging "why did this person get that text?".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .store import Store


@dataclass
class ReplayReport:
    events: int = 0
    enrollments_checked: int = 0
    messages_checked: int = 0
    mismatches: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches


def replay(store: Store) -> ReplayReport:
    rep = ReplayReport()
    enr: dict[str, str] = {}
    msg: dict[str, str] = {}
    step: dict[str, int] = {}
    for row in store.conn.execute("SELECT entity, entity_id, type, data FROM events ORDER BY seq"):
        rep.events += 1
        data = json.loads(row["data"])
        if row["entity"] == "enrollment" and row["type"] == "enrollment.state":
            enr[row["entity_id"]] = data["state"]
            if "step_index" in data:
                step[row["entity_id"]] = int(data["step_index"])
        elif row["entity"] == "message" and row["type"] == "message.status":
            msg[row["entity_id"]] = data["status"]

    for row in store.conn.execute("SELECT id, state, step_index FROM enrollments"):
        rep.enrollments_checked += 1
        want = enr.get(row["id"])
        if want != row["state"]:
            rep.mismatches.append({"entity": "enrollment", "id": row["id"], "table": row["state"], "replayed": want})
        elif step.get(row["id"], 0) != row["step_index"]:
            rep.mismatches.append({"entity": "enrollment", "id": row["id"], "field": "step_index",
                                   "table": row["step_index"], "replayed": step.get(row["id"], 0)})
    for row in store.conn.execute("SELECT id, status FROM messages"):
        rep.messages_checked += 1
        want = msg.get(row["id"])
        if want != row["status"]:
            rep.mismatches.append({"entity": "message", "id": row["id"], "table": row["status"], "replayed": want})
    known_enr = {r["id"] for r in store.conn.execute("SELECT id FROM enrollments")}
    known_msg = {r["id"] for r in store.conn.execute("SELECT id FROM messages")}
    for eid in set(enr) - known_enr:
        rep.mismatches.append({"entity": "enrollment", "id": eid, "table": None, "replayed": enr[eid]})
    for mid in set(msg) - known_msg:
        rep.mismatches.append({"entity": "message", "id": mid, "table": None, "replayed": msg[mid]})
    return rep


def timeline(store: Store, lead_id: str) -> list[dict[str, Any]]:
    ids = {lead_id}
    ids |= {r["id"] for r in store.conn.execute("SELECT id FROM enrollments WHERE lead_id=?", (lead_id,))}
    ids |= {r["id"] for r in store.conn.execute("SELECT id FROM messages WHERE lead_id=?", (lead_id,))}
    ids |= {r["id"] for r in store.conn.execute("SELECT id FROM inbound WHERE lead_id=?", (lead_id,))}
    lead = store.conn.execute("SELECT phone, email FROM leads WHERE id=?", (lead_id,)).fetchone()
    if lead:
        ids |= {a for a in (lead["phone"], lead["email"]) if a}
    out = []
    marks = ",".join("?" * len(ids))
    for row in store.conn.execute(
        f"SELECT seq, ts, entity, entity_id, type, data, actor FROM events WHERE entity_id IN ({marks}) ORDER BY seq",
        tuple(ids),
    ):
        out.append({"seq": row["seq"], "ts": row["ts"], "entity": row["entity"], "id": row["entity_id"],
                    "type": row["type"], "data": json.loads(row["data"]), "actor": row["actor"]})
    return out
