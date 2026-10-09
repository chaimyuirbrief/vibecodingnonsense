"""In-memory channel with deterministic fault injection (tests + simulator)."""

from __future__ import annotations

import random
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from . import Outbound, SendResult
from .http import TransportConnectError, TransportTimeout


class CrashAfterSend(BaseException):
    """Raised *after* the fake provider recorded the message: models the worker
    process dying between the provider call and the database write. Inherits
    BaseException so the engine's adapter-error handling cannot swallow it."""


@dataclass
class Delivery:
    msg: Outbound
    at: datetime | None


@dataclass
class FaultPlan:
    transient: float = 0.0
    permanent: float = 0.0
    ambiguous: float = 0.0       # provider got it, response lost (send happened)
    ambiguous_lost: float = 0.0  # provider never got it, response lost (send did not happen)
    crash_after_send: float = 0.0
    seed: int = 0


class FakeChannel:
    def __init__(self, name: str = "sms", plan: FaultPlan | None = None,
                 clock: Callable[[], datetime] | None = None,
                 invalid: set[str] | None = None, supports_lookup: bool = True) -> None:
        self.name = name
        self.plan = plan or FaultPlan()
        self.clock = clock
        self.invalid = invalid or set()
        self.supports_lookup = supports_lookup
        self.deliveries: list[Delivery] = []
        self.by_key: dict[str, Delivery] = {}
        self.attempts: Counter[str] = Counter()
        self.duplicate_deliveries = 0
        self._rng = random.Random(self.plan.seed)
        self._lock = threading.Lock()

    def _deliver(self, msg: Outbound) -> str:
        if msg.idempotency_key in self.by_key:
            self.duplicate_deliveries += 1
        d = Delivery(msg, self.clock() if self.clock else None)
        self.deliveries.append(d)
        self.by_key[msg.idempotency_key] = d
        return f"fake_{len(self.deliveries):06d}"

    def send(self, msg: Outbound) -> SendResult:
        with self._lock:
            self.attempts[msg.idempotency_key] += 1
            if msg.to in self.invalid:
                return SendResult("permanent", error="invalid_destination", suppress=True)
            r = self._rng.random()
            p = self.plan
            if r < p.transient:
                return SendResult("transient", error="503 simulated", retry_after_s=60)
            r -= p.transient
            if r < p.permanent:
                return SendResult("permanent", error="simulated permanent failure")
            r -= p.permanent
            if r < p.ambiguous:
                self._deliver(msg)
                return SendResult("ambiguous", error="timeout after request sent")
            r -= p.ambiguous
            if r < p.ambiguous_lost:
                return SendResult("ambiguous", error="timeout, request lost")
            r -= p.ambiguous_lost
            pid = self._deliver(msg)
            if r < p.crash_after_send:
                raise CrashAfterSend(msg.message_id)
            return SendResult("sent", provider_id=pid)

    def lookup(self, idempotency_key: str) -> SendResult | None:
        if not self.supports_lookup:
            return None
        with self._lock:
            d = self.by_key.get(idempotency_key)
        if d is None:
            return SendResult("permanent", error="not_found_at_provider")
        return SendResult("sent", provider_id=f"fake_lookup_{idempotency_key[:8]}")

    @property
    def sent_bodies(self) -> list[str]:
        return [d.msg.body for d in self.deliveries]


@dataclass
class RecordingTransport:
    """Fake HTTP transport for webhook/Twilio tests: returns scripted (status, body)."""

    responses: list[tuple[int, str]] = field(default_factory=list)
    requests: list[tuple[str, str, dict[str, str], bytes]] = field(default_factory=list)

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, dict[str, str], bytes]:
        self.requests.append((method, url, headers, body))
        status, text = self.responses.pop(0) if self.responses else (200, "{}")
        if status == -1:
            raise TransportTimeout("simulated timeout")
        if status == -2:
            raise TransportConnectError("simulated refused")
        return status, {}, text.encode()
