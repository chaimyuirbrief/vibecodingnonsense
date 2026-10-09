from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lazarus.timeutil import SendWindow, allowed_now, next_allowed, parse_ts, ts

NY, LA, CHI, HON, TOKYO = (ZoneInfo(z) for z in
                           ("America/New_York", "America/Los_Angeles", "America/Chicago", "Pacific/Honolulu", "Asia/Tokyo"))
WIN = SendWindow(time(9), time(20), frozenset(range(6)))  # Mon-Sat 9-20


def test_ts_roundtrip_and_ordering() -> None:
    a = datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC)
    b = a + timedelta(microseconds=1)
    assert parse_ts(ts(a)) == a
    assert ts(a) < ts(b)


def test_naive_rejected() -> None:
    with pytest.raises(ValueError):
        ts(datetime(2026, 1, 1))


def test_window_validation() -> None:
    with pytest.raises(ValueError):
        SendWindow(time(20), time(9), frozenset({0}))
    with pytest.raises(ValueError):
        SendWindow(time(9), time(20), frozenset())


def test_inside_window_returns_now() -> None:
    now = datetime(2026, 10, 12, 15, 0, tzinfo=UTC)  # Mon 11:00 ET
    assert next_allowed(WIN, [NY], now) == now


def test_before_window_returns_open() -> None:
    now = datetime(2026, 10, 12, 11, 0, tzinfo=UTC)  # Mon 07:00 ET
    assert next_allowed(WIN, [NY], now) == datetime(2026, 10, 12, 13, 0, tzinfo=UTC)


def test_sunday_skipped() -> None:
    sat_night = datetime(2026, 10, 18, 1, 0, tzinfo=UTC)  # Sat 21:00 ET -> next is Mon 09:00 ET
    assert next_allowed(WIN, [NY], sat_night) == datetime(2026, 10, 19, 13, 0, tzinfo=UTC)


def test_intersection_of_zones_is_conservative() -> None:
    now = datetime(2026, 10, 12, 13, 0, tzinfo=UTC)  # 09:00 ET, 06:00 PT
    got = next_allowed(WIN, [NY, LA], now)
    assert got == datetime(2026, 10, 12, 16, 0, tzinfo=UTC)  # 12:00 ET = 09:00 PT


def test_empty_intersection_returns_none() -> None:
    narrow = SendWindow(time(9), time(10), frozenset(range(7)))
    assert next_allowed(narrow, [NY, TOKYO], datetime(2026, 10, 12, tzinfo=UTC)) is None


@pytest.mark.parametrize("day", [datetime(2026, 3, 8, 9, 0, tzinfo=UTC), datetime(2026, 11, 1, 9, 0, tzinfo=UTC)])
def test_dst_transition_days(day: datetime) -> None:
    # 09:00 UTC on the Sunday of each US DST switch is ~04:00-05:00 New York time, before the window.
    # With Sunday allowed, the next opening must be exactly 09:00 local on that same day.
    w = SendWindow(time(9), time(20), frozenset(range(7)))
    got = next_allowed(w, [NY], day)
    assert got is not None and got.astimezone(NY).time() == time(9) and got.astimezone(NY).date() == day.date()


@settings(max_examples=300, deadline=None)
@given(
    moment=st.datetimes(min_value=datetime(2026, 1, 1), max_value=datetime(2027, 12, 31), timezones=st.just(UTC)),
    zones=st.lists(st.sampled_from([NY, LA, CHI, HON]), min_size=1, max_size=4, unique=True),
)
def test_next_allowed_is_allowed_and_minimal(moment: datetime, zones: list[ZoneInfo]) -> None:
    got = next_allowed(WIN, zones, moment)
    assert got is not None
    assert got >= moment
    assert allowed_now(WIN, zones, got)
    if got > moment:
        # Minimality: one minute earlier is not allowed (and neither is the starting moment).
        assert not allowed_now(WIN, zones, got - timedelta(minutes=1)) or got - timedelta(minutes=1) < moment
        assert not allowed_now(WIN, zones, moment)
