"""Domain models and campaign configuration (validated at load time)."""

from __future__ import annotations

import re
from datetime import time
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .normalize import Consent
from .timeutil import SendWindow, zone

PLACEHOLDER = re.compile(r"\{([a-z_]+)(?:\|([^{}]*))?\}")
TEMPLATE_FIELDS = frozenset({"first_name", "last_name", "business_name", "sender_name"})


class Label(StrEnum):
    OPT_OUT = "opt_out"
    WRONG_NUMBER = "wrong_number"
    AUTO_REPLY = "auto_reply"
    LATER = "later"
    INTERESTED = "interested"
    NOT_INTERESTED = "not_interested"
    UNCLEAR = "unclear"


class EnrollmentState(StrEnum):
    ACTIVE = "active"            # waiting for next step to come due
    AWAITING_SEND = "awaiting_send"  # a message for the current step exists
    PAUSED = "paused"            # needs a human (unclear reply / possible opt-out)
    HANDED_OFF = "handed_off"    # interested -> sales
    OPTED_OUT = "opted_out"
    WRONG_NUMBER = "wrong_number"
    NOT_INTERESTED = "not_interested"
    EXHAUSTED = "exhausted"      # sequence finished without a reply
    BLOCKED = "blocked"          # policy made this enrollment unsendable
    FAILED = "failed"            # permanent delivery failure


TERMINAL_ENROLLMENT = frozenset({
    EnrollmentState.HANDED_OFF, EnrollmentState.OPTED_OUT, EnrollmentState.WRONG_NUMBER,
    EnrollmentState.NOT_INTERESTED, EnrollmentState.EXHAUSTED, EnrollmentState.BLOCKED,
    EnrollmentState.FAILED,
})


class MessageStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    QUEUED = "queued"
    SENDING = "sending"      # leased by a dispatcher
    SENT = "sent"
    FAILED = "failed"
    UNKNOWN = "unknown"      # outcome ambiguous; never auto-resent
    CANCELED = "canceled"
    REJECTED = "rejected"
    HELD = "held"            # enrollment paused; may be released or canceled


OPEN_MESSAGE = frozenset({MessageStatus.PENDING_APPROVAL, MessageStatus.QUEUED, MessageStatus.HELD})


class Lead(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    external_id: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    phone: str | None = None
    timezone: str | None = None
    tags: tuple[str, ...] = ()
    sms_consent: Consent = Consent.UNKNOWN
    email_consent: Consent = Consent.UNKNOWN
    notes: str = ""
    source: str | None = None


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: Literal["sms", "email"] = "sms"
    delay_hours: float = Field(ge=0, le=24 * 365)
    template: str = Field(min_length=1, max_length=2000)
    subject: str | None = Field(default=None, max_length=200)
    personalize: bool = False
    goal: str = Field(default="", max_length=300)

    @field_validator("template", "subject")
    @classmethod
    def _placeholders(cls, v: str | None) -> str | None:
        if v is None:
            return v
        for m in PLACEHOLDER.finditer(v):
            if m.group(1) not in TEMPLATE_FIELDS:
                raise ValueError(f"unknown placeholder {{{m.group(1)}}}; allowed: {sorted(TEMPLATE_FIELDS)}")
        stripped = PLACEHOLDER.sub("", v)
        if "{" in stripped or "}" in stripped:
            raise ValueError("stray brace in template (use {field} or {field|fallback})")
        return v


class Campaign(BaseModel):
    """A reactivation sequence. Defaults are deliberately conservative.

    Defaults (9:00-20:00 local, Mon-Sat, >=24h between touches, explicit SMS
    consent required) sit inside common US rules — federal TCPA calling hours
    are 8am-9pm and several state laws use 8am-8pm. This is engineering, not
    legal advice; have counsel review your configuration.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    name: str
    business_name: str = Field(min_length=1, max_length=60)
    sender_name: str = Field(min_length=1, max_length=40)
    business_timezone: str = "America/New_York"
    facts: list[str] = Field(default_factory=list, max_length=30)
    allowed_link_domains: list[str] = Field(default_factory=list)
    steps: list[Step] = Field(min_length=1, max_length=10)

    window_start: time = time(9, 0)
    window_end: time = time(20, 0)
    weekdays: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5])
    fallback_timezones: list[str] = Field(
        default_factory=lambda: ["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"]
    )

    min_hours_between_touches: float = Field(default=24, ge=1)
    daily_send_cap: int = Field(default=500, ge=1)
    require_sms_consent: bool = True
    sms_optout_footer: Literal["first", "always"] = "first"
    max_sms_chars: int = Field(default=320, ge=70, le=1600)
    forbidden_phrases: list[str] = Field(default_factory=lambda: [
        "guarantee", "guaranteed", "risk-free", "risk free", "act now", "final notice", "winner",
        "you've been selected", "congratulations", "100%", "no obligation",
    ])
    email_footer: str | None = None  # must include a physical postal address for email steps

    approve_first_n: int = Field(default=10, ge=0)
    approve_llm_messages: bool = True
    snooze_days_on_later: int = Field(default=30, ge=1, le=365)
    exhaust_after_hours: float = Field(default=72, ge=0)
    # Off by default: carriers/providers (e.g. Twilio Advanced Opt-Out) usually confirm standard
    # keywords themselves, and a second confirmation is one text too many.
    send_optout_confirmation: bool = False
    max_send_attempts: int = Field(default=5, ge=1, le=20)

    @field_validator("business_timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        if zone(v) is None:
            raise ValueError(f"unknown timezone {v!r}")
        return v

    @field_validator("fallback_timezones")
    @classmethod
    def _tzs(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("need at least one fallback timezone")
        for name in v:
            if zone(name) is None:
                raise ValueError(f"unknown timezone {name!r}")
        return v

    @field_validator("allowed_link_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        return [d.lower().strip().lstrip(".") for d in v if d.strip()]

    @model_validator(mode="after")
    def _check(self) -> Campaign:
        SendWindow(self.window_start, self.window_end, frozenset(self.weekdays))  # raises if invalid
        if any(s.channel == "email" for s in self.steps):
            if not self.email_footer or not re.search(r"\d", self.email_footer):
                raise ValueError("email steps require email_footer containing a physical postal address (CAN-SPAM)")
            if any(s.channel == "email" and not s.subject for s in self.steps):
                raise ValueError("email steps need a subject")
        first_sms = next((s for s in self.steps if s.channel == "sms"), None)
        if first_sms and "{business_name}" not in first_sms.template and self.business_name not in first_sms.template:
            raise ValueError("first SMS must identify the business ({business_name})")
        return self

    @property
    def window(self) -> SendWindow:
        return SendWindow(self.window_start, self.window_end, frozenset(self.weekdays))
