"""The simulator is only worth trusting if it fails when the engine is wrong.
Each mutation test breaks one guarantee and asserts the matching invariant fires."""

from typing import Any

import pytest

from lazarus import engine as engine_mod
from lazarus import simulate
from lazarus.channels.fake import FaultPlan
from lazarus.policy import ALLOW
from lazarus.simulate import SimConfig, run
from lazarus.store import Store

from .conftest import ROOT

CORPUS = str(ROOT / "evals" / "replies_blind_dev.jsonl")


def cfg(**kw: Any) -> SimConfig:
    base: dict[str, Any] = dict(leads=80, days=10, seed=3, corpus=CORPUS)
    base.update(kw)
    return SimConfig(**base)


def test_simulation_passes_all_invariants() -> None:
    r = run(cfg())
    assert r.ok, r.to_json()
    assert r.metrics["deliveries"] > 100
    assert r.metrics["worker_crashes"] >= 0 and r.metrics["duplicate_deliveries"] == 0


def test_simulation_is_deterministic() -> None:
    a, b = run(cfg(leads=40, days=5)), run(cfg(leads=40, days=5))
    assert a.metrics == b.metrics


def test_concurrent_workers_hold_invariants() -> None:
    r = run(cfg(workers=4, leads=120))
    assert r.ok, r.to_json()


def test_mutation_policy_disabled_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "check_send", lambda *a, **k: ALLOW)
    r = run(cfg())
    assert r.violations.get("sent_in_quiet_hours") or r.violations.get("frequency_cap")


def test_mutation_opt_out_not_honored_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    orig = engine_mod.Engine._route

    def broken(self: Any, iid: str, addr: str, channel: str, lead: Any, c: Any, now: Any) -> list[str]:
        from lazarus.models import Label
        if c.label is Label.OPT_OUT:
            return []  # forget to suppress and cancel
        return orig(self, iid, addr, channel, lead, c, now)

    monkeypatch.setattr(engine_mod.Engine, "_route", broken)
    r = run(cfg(reply_rate=0.6))
    assert r.violations.get("sent_after_true_opt_out")


def test_mutation_blind_resend_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    def resend_unknown(self: Any, now: Any = None) -> Any:
        from collections import Counter

        from lazarus.models import MessageStatus as M
        from lazarus.timeutil import ts
        now = now or self.now()
        for r in self.store.conn.execute("SELECT id FROM messages WHERE status IN ('unknown','sending')").fetchall():
            self.store.set_message_status(r["id"], M.QUEUED, reason="blind_resend", next_attempt_at=ts(now),
                                          lease_owner=None, lease_until=None)
        return Counter()

    monkeypatch.setattr(engine_mod.Engine, "reconcile", resend_unknown)
    r = run(cfg(fault=FaultPlan(ambiguous=0.2, seed=1)))
    assert r.violations.get("duplicate_idempotency_key") or r.violations.get("step_delivered_twice")


def test_mutation_unlogged_state_change_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    orig = Store.set_message_status

    def sneaky(self: Store, message_id: str, status: Any, **kw: Any) -> bool:
        if status.value == "sent":
            self.conn.execute("UPDATE messages SET status='sent' WHERE id=?", (message_id,))  # no event
            return True
        return orig(self, message_id, status, **kw)

    monkeypatch.setattr(Store, "set_message_status", sneaky)
    r = run(cfg(leads=30, days=4))
    assert r.violations.get("replay_mismatch")


def test_mutation_consent_ignored_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "static_checks", lambda *a, **k: ALLOW)
    monkeypatch.setattr(engine_mod, "check_send", lambda *a, **k: ALLOW)
    r = run(cfg(no_consent_rate=0.3))
    assert r.violations.get("sent_without_consent")


def test_sim_campaign_is_valid() -> None:
    c = simulate.sim_campaign()
    assert len(c.steps) == 3 and c.send_optout_confirmation
