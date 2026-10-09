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
from .timeutil import allowed_now, next_allowed, parse_ts, zone


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = "ok"
    retry_at: datetime | None = None  # None with allowed=False means permanent

    @property
    def permanent(self) -> bool:
        return not self.allowed and self.retry_at is None


ALLOW = Decision(True)
# The last minutes of a send window are treated as closed: a message checked at 19:59:59 must not
# be delivered at 20:00:01 because the provider call or the rest of the batch took time.
SEND_MARGIN = timedelta(minutes=5)


# NANP area codes outside the continental-US fallback zones. When a lead's timezone is unknown, the
# zone implied by the area code is added to the intersection, so e.g. Hawaii numbers are not texted at
# 06:00 local just because it is noon in New York.
AREA_CODE_ZONES = {
    "808": "Pacific/Honolulu", "907": "America/Anchorage", "787": "America/Puerto_Rico", "939": "America/Puerto_Rico",
    "340": "America/St_Thomas", "671": "Pacific/Guam", "670": "Pacific/Saipan", "684": "Pacific/Pago_Pago",
}


def lead_zones(lead: Lead, campaign: Campaign) -> list[ZoneInfo]:
    tz = zone(lead.timezone)
    if tz is not None:
        return [tz]
    names = list(campaign.fallback_timezones)
    if lead.phone and lead.phone.startswith("+1"):
        extra = AREA_CODE_ZONES.get(lead.phone[2:5])
        if extra:
            names.append(extra)
    zs = [zone(n) for n in names]
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
    if channel == "sms" and lead.phone and not lead.phone.startswith("+1") and zone(lead.timezone) is None:
        # Fallback zones are North American; guessing quiet hours for another country is not safe.
        return Decision(False, "timezone_required_for_international")
    if channel == "sms":
        if lead.sms_consent is Consent.NO:
            return Decision(False, "sms_consent_no")
        if campaign.require_sms_consent and lead.sms_consent is not Consent.YES:
            return Decision(False, "sms_consent_missing")
    if channel == "email" and lead.email_consent is Consent.NO:
        return Decision(False, "email_consent_no")
    return ALLOW


def check_send(store: Store, lead: Lead, campaign: Campaign, channel: str, now: datetime,
               exclude_message_id: str | None = None, daily_cap: bool = True) -> Decision:
    """``daily_cap=False`` when the caller already enforced the cap (dispatch does it at claim time)."""
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
    if not allowed_now(window, zones, now + SEND_MARGIN):
        return Decision(False, "quiet_hours", next_allowed(window, zones, now + SEND_MARGIN) or now + timedelta(hours=1))
    if store.lead_under_review(lead.id):
        return Decision(False, "lead_under_review", now + timedelta(hours=1))

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

    if daily_cap:
        used = daily_used(store, campaign, now, exclude_message_id)
        if used >= campaign.daily_send_cap:
            tomorrow = business_day_start(campaign, now) + timedelta(days=1)
            return Decision(False, "daily_cap", next_allowed(window, zones, tomorrow) or tomorrow)
    return ALLOW


def business_day_start(campaign: Campaign, now: datetime) -> datetime:
    btz = zone(campaign.business_timezone)
    assert btz is not None
    return now.astimezone(btz).replace(hour=0, minute=0, second=0, microsecond=0)


def day_key(campaign: Campaign, now: datetime) -> str:
    return business_day_start(campaign, now).date().isoformat()


def daily_used(store: Store, campaign: Campaign, now: datetime, exclude_message_id: str | None = None) -> int:
    """Send attempts claimed today (business-timezone day). Maintained by the dispatcher inside the
    claim transaction, so it is exact across concurrent workers. Retries count again (conservative)."""
    row = store.conn.execute("SELECT n FROM send_counters WHERE campaign_id=? AND day=?",
                             (campaign.id, day_key(campaign, now))).fetchone()
    return int(row["n"]) if row else 0
