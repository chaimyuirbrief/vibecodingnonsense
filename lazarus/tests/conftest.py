from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from lazarus.channels.fake import FakeChannel
from lazarus.engine import Engine, EngineConfig
from lazarus.ingest import upsert_lead
from lazarus.models import Campaign, Step
from lazarus.normalize import Consent
from lazarus.store import IdGen, Store
from lazarus.timeutil import FakeClock

ROOT = Path(__file__).resolve().parent.parent
# Monday 2026-10-12 15:00 UTC = 11:00 New York, 08:00 Los Angeles
MONDAY_11_ET = datetime(2026, 10, 12, 15, 0, tzinfo=UTC)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(MONDAY_11_ET)


@pytest.fixture
def store(tmp_path: Path, clock: FakeClock) -> Iterator[Store]:
    st = Store(tmp_path / "t.db", clock, IdGen(1))
    yield st
    st.close()


def make_campaign(**over: Any) -> Campaign:
    base: dict[str, Any] = dict(
        id="test", name="Test", business_name="Brightside Roofing", sender_name="Mike",
        facts=["Free roof inspection."], allowed_link_domains=["brightside.example"],
        steps=[
            Step(delay_hours=0, template="Hi {first_name|there}, it's {sender_name} from {business_name}. Still need a roof?"),
            Step(delay_hours=48, template="Hi {first_name|there}, {sender_name} again. Want a free inspection?", personalize=True),
            Step(delay_hours=96, template="Last note, {first_name|there}. Reply anytime."),
        ],
        approve_first_n=0, approve_llm_messages=False, exhaust_after_hours=72,
    )
    base.update(over)
    return Campaign(**base)


@pytest.fixture
def campaign(store: Store) -> Campaign:
    c = make_campaign()
    store.save_campaign(c)
    return c


@pytest.fixture
def channel(clock: FakeClock) -> FakeChannel:
    return FakeChannel("sms", clock=clock.now)


@pytest.fixture
def engine(store: Store, channel: FakeChannel, campaign: Campaign) -> Engine:
    return Engine(store, {"sms": channel}, config=EngineConfig(lease_seconds=60))


def add_lead(store: Store, phone: str = "+14045552368", first: str | None = "Dana", tz: str | None = "America/New_York",
             consent: Consent = Consent.YES, email: str | None = None, notes: str = "") -> str:
    upsert_lead(store, {"external_id": None, "first_name": first, "last_name": None, "email": email, "phone": phone,
                        "timezone": tz, "tags": [], "sms_consent": consent, "email_consent": Consent.UNKNOWN,
                        "notes": notes}, source="test")
    row = store.conn.execute("SELECT id FROM leads WHERE phone=? OR email=?", (phone, email)).fetchone()
    return str(row["id"])
