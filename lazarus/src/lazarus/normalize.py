"""Deterministic normalization of untrusted CRM/CSV data.

Everything that ends up inside an outbound message (names) or decides where a
message goes (phones, emails) is normalized and validated here. CRM fields are
attacker-controllable in practice (web forms feed CRMs), so a "first name" of
``http://evil.example`` must never be rendered into an SMS.
"""

from __future__ import annotations

import re
import unicodedata
from email.utils import parseaddr
from enum import StrEnum

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)


class Consent(StrEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


_YES = {"y", "yes", "true", "1", "opted in", "opt-in", "optin", "granted", "express", "si", "sí", "x"}
_NO = {"n", "no", "false", "0", "opted out", "opt-out", "optout", "revoked", "denied", "dnc", "do not contact"}


def parse_consent(raw: object) -> Consent:
    if raw is None:
        return Consent.UNKNOWN
    v = str(raw).strip().lower()
    if v in _YES:
        return Consent.YES
    if v in _NO:
        return Consent.NO
    return Consent.UNKNOWN


def clean_text(raw: object, max_len: int = 2000) -> str:
    """NFKC-normalize, drop control and zero-width chars, collapse whitespace."""
    if raw is None:
        return ""
    s = unicodedata.normalize("NFKC", str(raw)).translate(_ZERO_WIDTH)
    s = "".join(ch if (ch in "\n\t" or unicodedata.category(ch)[0] != "C") else " " for ch in s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()[:max_len]


# ---------------------------------------------------------------- phones

_EXT = re.compile(r"\s*(?:ext\.?|extension|x|#)\s*\d{1,6}\s*$", re.IGNORECASE)


def normalize_phone(raw: object, default_country: str = "US") -> str | None:
    """Return E.164 or None.

    NANP (US/CA) numbers are validated structurally: area code and exchange
    must start with 2-9, N11 service codes and the 555-01XX fiction range are
    rejected. Non-NANP numbers are accepted only in explicit +CC form, with the
    E.164 length bound, because guessing other countries' formats is how texts
    end up at strangers.
    """
    if raw is None:
        return None
    s = unicodedata.normalize("NFKC", str(raw)).strip()
    # Any Unicode decimal digit (Arabic-Indic, Devanagari, ...) -> ASCII, so output is always ASCII E.164.
    s = "".join(str(unicodedata.decimal(ch)) if ch.isdecimal() and not ch.isascii() else ch for ch in s)
    if not s:
        return None
    s = _EXT.sub("", s)
    if re.search(r"[A-Za-z]", s):
        return None  # vanity numbers / garbage: refuse rather than guess
    plus = s.startswith("+") or s.startswith("00")
    digits = re.sub(r"[^0-9]", "", s)
    if s.startswith("00"):
        digits = digits[2:]
    if plus:
        if digits.startswith("1"):
            return _nanp(digits[1:])
        if 8 <= len(digits) <= 15 and digits[0] != "0":
            return "+" + digits
        return None
    if default_country.upper() not in ("US", "CA"):
        return None
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return _nanp(digits)


def _nanp(ten: str) -> str | None:
    if len(ten) != 10 or not (ten.isascii() and ten.isdigit()):
        return None
    area, exch, line = ten[:3], ten[3:6], ten[6:]
    if area[0] in "01" or exch[0] in "01":
        return None
    if area[1:] == "11" or exch[1:] == "11":
        return None  # N11 service codes (211, 911, ...)
    if exch == "555" and line.startswith("01"):
        return None  # 555-0100..0199 reserved for fiction
    return "+1" + ten


# ---------------------------------------------------------------- email

_EMAIL = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_email(raw: object) -> str | None:
    if raw is None:
        return None
    s = unicodedata.normalize("NFKC", str(raw)).translate(_ZERO_WIDTH).strip()
    if "<" in s and ">" in s:  # "Dana Smith <dana@example.com>"
        s = parseaddr(s)[1]
    s = s.strip().strip("<>").lower()
    if s.startswith("mailto:"):
        s = s[7:]
    if len(s) > 254 or not _EMAIL.match(s):
        return None
    return s


# ---------------------------------------------------------------- names

_NAME_OK = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ '\-.])*$", re.UNICODE)


def normalize_name(raw: object, max_len: int = 40) -> str | None:
    """A person's name or None. Rejects anything that is not letters plus
    space/apostrophe/hyphen/period — URLs, digits, braces, emoji, markup."""
    s = clean_text(raw, max_len=200)
    if not s or len(s) > max_len or "\n" in s:
        return None
    s = re.sub(r"\s+", " ", s)
    if not _NAME_OK.match(s):
        return None
    if re.search(r"[^\W\d_]\.[^\W\d_]{2,}", s):  # "Pay.Acme-Billing.Com": a host, not a name ("J.R." is fine)
        return None
    if s.isupper() or s.islower():
        # "MARY-JANE O'BRIEN" -> "Mary-Jane O'Brien", "j.r." -> "J.R."
        s = re.sub(r"(^|[\s\-'.])([^\W\d_])", lambda m: m.group(1) + m.group(2).upper(), s.lower())
    return s


def split_full_name(raw: object) -> tuple[str | None, str | None]:
    s = clean_text(raw, max_len=200)
    if not s:
        return None, None
    if "," in s:  # "Last, First"
        last, _, first = s.partition(",")
        return normalize_name(first.strip().split(" ")[0] if first.strip() else ""), normalize_name(last)
    parts = s.split()
    if len(parts) == 1:
        return normalize_name(parts[0]), None
    return normalize_name(parts[0]), normalize_name(parts[-1])


def csv_safe(value: object) -> str:
    """Neutralize spreadsheet formula injection in exported cells."""
    s = "" if value is None else str(value)
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s


def normalize_sender(channel: str, raw: str) -> str:
    """Best-effort canonical form of an inbound sender, so replies match the stored lead.
    Falls back to the cleaned raw string (which is still suppressed on opt-out)."""
    if channel == "sms":
        p = normalize_phone(raw)
        if p is None:
            digits = re.sub(r"[^0-9]", "", unicodedata.normalize("NFKC", raw))
            if 11 <= len(digits) <= 15 and not digits.startswith("1"):
                p = normalize_phone("+" + digits)  # international MSISDN delivered without '+'
        return p or raw.strip()[:320]
    return normalize_email(raw) or raw.strip().lower()[:320]
