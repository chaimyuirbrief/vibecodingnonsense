"""Delivery channels. A channel turns one outbound message into a provider call.

Outcome semantics matter more than transport:

* ``sent`` — provider accepted it.
* ``transient`` — safe to retry later (429, 5xx, connection refused before send).
* ``permanent`` — will never succeed (invalid number, unsubscribed at carrier).
  ``suppress=True`` means the address itself must be suppressed.
* ``ambiguous`` — we cannot know whether it was sent (timeout after the request
  went out). The engine marks the message ``unknown`` and never auto-resends;
  ``lookup`` may later resolve it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

Outcome = Literal["sent", "transient", "permanent", "ambiguous"]


@dataclass(frozen=True)
class Outbound:
    message_id: str
    idempotency_key: str
    channel: str
    to: str
    body: str
    subject: str | None = None


@dataclass(frozen=True)
class SendResult:
    outcome: Outcome
    provider_id: str | None = None
    error: str | None = None
    suppress: bool = False
    retry_after_s: float | None = None


class Channel(Protocol):
    name: str

    def send(self, msg: Outbound) -> SendResult: ...

    def lookup(self, idempotency_key: str) -> SendResult | None:
        """Resolve an ambiguous send. None = channel cannot tell."""
        ...
