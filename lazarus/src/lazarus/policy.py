"""The send gate. Pure policy over (lead, campaign, channel, now, store reads).

Checked twice: when a step is planned (to avoid composing doomed messages) and
again immediately before the provider call (state can change in between — an
opt-out can arrive while a message waits for approval or for the send window).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .models import Campaign, Lead
from .normalize import Consent
from .store import Store
from .timeutil import next_allowed, parse_ts, ts, zone


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = "ok"
    retry_at: datetime | None = None  # None with allowed=False means permanent

    @property
    def permanent(self) -> bool:
        return not self.allowed and self.retry_at is None


ALLOW = Decision(True)


def lead_zones(lead: Lead, campaign: Campaign) -> list[ZoneInfo]:
    tz = zone(lead.timezone)
    if tz is not None:
        return [tz]
    zs = [zone(n) for n in campaign.fallback_timezones]
    return [z for z in zs if z is not None]


def address_for(lead: Lead, channel: str) -> str | None:
    return lead.phone if channel == "sms" else lead.email


def static_checks(store: Store, lead: Lead, campaign: Campaign, channel: str) -> Decision:
    """Checks whose outcome does not depend on time — failures are permanent."""
    addr = address_for(lead, channel)
    if not addr:
        return Decision(False, f"no_{channel}_address")
    reason = store.is_suppressed(lead.phone, lead.email) if channel == "sms" else store.is_suppressed(lead.email, lead.phone)
    if reason:
        return Decision(False, f"suppressed:{reason}")
    if channel == "sms":
        if lead.sms_consent is Consent.NO:
            return Decision(False, "sms_consent_no")
        if campaign.require_sms_consent and lead.sms_consent is not Consent.YES:
            return Decision(False, "sms_consent_missing")
    if channel == "email" and lead.email_consent is Consent.NO:
        return Decision(False, "email_consent_no")
    return ALLOW


def check_send(store: Store, lead: Lead, campaign: Campaign, channel: str, now: datetime,
               exclude_message_id: str | None = None) -> Decision:
    status = store.campaign_status(campaign.id)
    if status != "active":
        return Decision(False, "campaign_paused", now + timedelta(hours=1))
    d = static_checks(store, lead, campaign, channel)
    if not d.allowed:
        return d

    zones = lead_zones(lead, campaign)
    if not zones:
        return Decision(False, "no_valid_timezone")
    window = campaign.window
    nxt = next_allowed(window, zones, now)
    if nxt is None:
        return Decision(False, "send_window_empty")
    if nxt > now:
        return Decision(False, "quiet_hours", nxt)

    # Frequency cap across ALL campaigns: count sent and in-flight messages to any of the lead's addresses.
    addrs = [a for a in (lead.phone, lead.email) if a]
    row = store.conn.execute(
        f"""SELECT MAX(COALESCE(sent_at, updated_at)) AS last FROM messages
            WHERE to_addr IN ({','.join('?' * len(addrs))}) AND status IN ('sent','sending','unknown')
            AND kind='outreach' AND id <> ?""",
        (*addrs, exclude_message_id or ""),
    ).fetchone()
    if row and row["last"]:
        gap_end = parse_ts(row["last"]) + timedelta(hours=campaign.min_hours_between_touches)
        if gap_end > now:
            retry = next_allowed(window, zones, gap_end) or gap_end
            return Decision(False, "frequency_cap", retry)

    # Daily campaign cap, counted per business-timezone calendar day.
    btz = zone(campaign.business_timezone)
    assert btz is not None
    local = now.astimezone(btz)
    day_start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    (count,) = store.conn.execute(
        """SELECT COUNT(*) FROM messages WHERE campaign_id=? AND kind='outreach'
           AND status IN ('sent','sending','unknown') AND COALESCE(sent_at, updated_at) >= ? AND id <> ?""",
        (campaign.id, ts(day_start), exclude_message_id or ""),
    ).fetchone()
    if count >= campaign.daily_send_cap:
        tomorrow = day_start + timedelta(days=1)
        return Decision(False, "daily_cap", next_allowed(window, zones, tomorrow) or tomorrow)
    return ALLOW
