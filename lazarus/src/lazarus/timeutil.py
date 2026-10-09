"""Time handling: one canonical timestamp format, injectable clocks, send windows.

Every timestamp stored in SQLite goes through ``ts()`` so that lexicographic
order equals chronological order (fixed width, always UTC). Comparisons in SQL
(``next_attempt_at <= ?``) depend on that.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("naive datetime; all times must be timezone-aware")
    return dt.astimezone(UTC).strftime(_FMT)


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, _FMT).replace(tzinfo=UTC)


def parse_iso(s: str) -> datetime:
    """Parse user-supplied ISO-8601 (CLI flags). Naive input is treated as UTC."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FakeClock(Clock):
    """Deterministic clock for tests and the simulator."""

    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None:
            raise ValueError("FakeClock needs an aware datetime")
        self._now = start.astimezone(UTC)
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, delta: timedelta) -> datetime:
        with self._lock:
            self._now += delta
            return self._now

    def set(self, dt: datetime) -> None:
        with self._lock:
            self._now = dt.astimezone(UTC)


def zone(name: str | None) -> ZoneInfo | None:
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None


@dataclass(frozen=True)
class SendWindow:
    """Local-time window in which outreach is allowed, on allowed weekdays.

    ``weekdays`` uses Python's convention: Monday=0 .. Sunday=6.
    """

    start: time
    end: time
    weekdays: frozenset[int]

    def __post_init__(self) -> None:
        if not self.start < self.end:
            raise ValueError("send window must not wrap midnight (start < end)")
        if not self.weekdays or not self.weekdays <= set(range(7)):
            raise ValueError("weekdays must be a non-empty subset of 0..6")

    def contains(self, moment: datetime, tz: ZoneInfo) -> bool:
        local = moment.astimezone(tz)
        return local.weekday() in self.weekdays and self.start <= local.time() < self.end


Interval = tuple[datetime, datetime]


def _day_intervals(window: SendWindow, tz: ZoneInfo, around: datetime, days: int) -> list[Interval]:
    base: date = around.astimezone(tz).date()
    out: list[Interval] = []
    for offset in range(-1, days + 1):
        d = base + timedelta(days=offset)
        if d.weekday() not in window.weekdays:
            continue
        lo = datetime.combine(d, window.start, tzinfo=tz).astimezone(UTC)
        hi = datetime.combine(d, window.end, tzinfo=tz).astimezone(UTC)
        if lo < hi:
            out.append((lo, hi))
    return out


def _intersect(a: Sequence[Interval], b: Sequence[Interval]) -> list[Interval]:
    i = j = 0
    out: list[Interval] = []
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo < hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def allowed_now(window: SendWindow, tzs: Iterable[ZoneInfo], moment: datetime) -> bool:
    return all(window.contains(moment, tz) for tz in tzs)


def next_allowed(window: SendWindow, tzs: Sequence[ZoneInfo], moment: datetime, horizon_days: int = 14) -> datetime | None:
    """Earliest instant >= ``moment`` that is inside the window in *every* zone.

    With one zone this is the lead's own local window. With several (lead zone
    unknown) it is the intersection — the conservative choice, because quiet-hour
    rules are judged by the recipient's location, which we do not know.
    Returns None if the intersection is empty within the horizon.
    """
    if not tzs:
        raise ValueError("need at least one timezone")
    merged: list[Interval] | None = None
    for tz in tzs:
        iv = sorted(_day_intervals(window, tz, moment, horizon_days))
        merged = iv if merged is None else _intersect(merged, iv)
        if not merged:
            return None
    assert merged is not None
    for lo, hi in merged:
        if hi > moment:
            return max(lo, moment)
    return None
