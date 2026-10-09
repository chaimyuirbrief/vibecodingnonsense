"""CSV lead import: header mapping, normalization, dedupe, quarantine report."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .normalize import (
    Consent,
    clean_text,
    normalize_email,
    normalize_name,
    normalize_phone,
    parse_consent,
    split_full_name,
)
from .store import Store
from .timeutil import ts, zone

ALIASES: dict[str, tuple[str, ...]] = {
    "external_id": ("id", "external_id", "contact_id", "lead_id", "record_id", "crm_id"),
    "first_name": ("first_name", "firstname", "first", "fname", "given_name"),
    "last_name": ("last_name", "lastname", "last", "lname", "surname", "family_name"),
    "full_name": ("name", "full_name", "fullname", "contact_name", "contact"),
    "email": ("email", "email_address", "e_mail", "mail", "primary_email"),
    "phone": ("phone", "phone_number", "mobile", "cell", "mobile_phone", "cell_phone", "telephone", "primary_phone", "sms"),
    "timezone": ("timezone", "time_zone", "tz"),
    "tags": ("tags", "labels", "segment", "segments"),
    "sms_consent": ("sms_consent", "sms_opt_in", "text_opt_in", "sms_optin", "consent_sms", "tcpa_consent"),
    "email_consent": ("email_consent", "email_opt_in", "email_optin", "consent_email"),
    "notes": ("notes", "note", "comments", "description", "last_note"),
}

MAX_ROWS = 200_000
MAX_FIELD = 5000


def _key(h: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in h.strip().lower()).strip("_")


def map_headers(headers: Iterable[str]) -> dict[str, str]:
    """Return {canonical_field: original_header}."""
    lookup = {_key(h): h for h in headers if h}
    out: dict[str, str] = {}
    for canon, aliases in ALIASES.items():
        for a in aliases:
            if a in lookup:
                out[canon] = lookup[a]
                break
    return out


@dataclass
class RowIssue:
    row: int
    reasons: list[str]
    raw: dict[str, str]


@dataclass
class ImportReport:
    rows: int = 0
    created: int = 0
    merged: int = 0
    duplicate_in_file: int = 0
    rejected: list[RowIssue] = field(default_factory=list)
    warnings: list[RowIssue] = field(default_factory=list)
    unmapped_headers: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "rows": self.rows, "created": self.created, "merged": self.merged,
            "duplicate_in_file": self.duplicate_in_file, "rejected": len(self.rejected),
            "warnings": len(self.warnings), "unmapped_headers": self.unmapped_headers,
        }


def read_text(path: str | Path) -> str:
    raw = Path(path).read_bytes()
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    raise ValueError("unreachable: latin-1 decodes everything")


def import_csv(store: Store, text: str, source: str, default_country: str = "US") -> ImportReport:
    report = ImportReport()
    sample = text[:8192]
    try:
        dialect: type[csv.Dialect] | csv.Dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text, newline=""), dialect=dialect)
    headers = reader.fieldnames or []
    mapping = map_headers(headers)
    mapped = set(mapping.values())
    report.unmapped_headers = [h for h in headers if h and h not in mapped]
    if "phone" not in mapping and "email" not in mapping:
        raise ValueError(f"no phone or email column found in headers {headers!r}")

    seen: dict[str, int] = {}
    for i, raw in enumerate(reader, start=2):  # row 1 is the header
        if report.rows >= MAX_ROWS:
            raise ValueError(f"file exceeds {MAX_ROWS} rows; split it")
        report.rows += 1
        row = {k: (v if isinstance(v, str) else "") for k, v in raw.items() if k is not None}
        if raw.get(None):  # type: ignore[call-overload]
            report.warnings.append(RowIssue(i, ["extra columns ignored"], row))

        def get(canon: str, row: dict[str, str] = row) -> str:
            h = mapping.get(canon)
            return (row.get(h) or "")[:MAX_FIELD] if h else ""

        reasons: list[str] = []
        warns: list[str] = []
        phone_raw, email_raw = get("phone").strip(), get("email").strip()
        phone = normalize_phone(phone_raw.lstrip("'"), default_country) if phone_raw else None
        email = normalize_email(email_raw) if email_raw else None
        if phone_raw and not phone:
            warns.append(f"invalid phone {phone_raw!r}")
        if email_raw and not email:
            warns.append(f"invalid email {email_raw!r}")
        if not phone and not email:
            reasons.append("no valid phone or email")

        first = normalize_name(get("first_name")) if get("first_name") else None
        last = normalize_name(get("last_name")) if get("last_name") else None
        if not first and get("full_name"):
            first, last2 = split_full_name(get("full_name"))
            last = last or last2
        if get("first_name") and not first:
            warns.append("first name rejected (non-name characters)")

        tz_raw = get("timezone").strip()
        tz = tz_raw if tz_raw and zone(tz_raw) else None
        if tz_raw and not tz:
            warns.append(f"unknown timezone {tz_raw!r}; conservative fallback window will apply")

        if reasons:
            report.rejected.append(RowIssue(i, reasons + warns, row))
            continue
        if warns:
            report.warnings.append(RowIssue(i, warns, row))

        ident = phone or email
        assert ident is not None
        if ident in seen or (email and email in seen):
            report.duplicate_in_file += 1
        seen[ident] = i
        if email:
            seen[email] = i

        tags = sorted({t.strip().lower() for t in get("tags").replace(";", ",").split(",") if t.strip()})
        rec = {
            "external_id": clean_text(get("external_id"), 120) or None,
            "first_name": first, "last_name": last, "email": email, "phone": phone, "timezone": tz,
            "tags": tags, "sms_consent": parse_consent(get("sms_consent")),
            "email_consent": parse_consent(get("email_consent")),
            "notes": clean_text(get("notes"), 1000),
        }
        created = upsert_lead(store, rec, source)
        if created:
            report.created += 1
        else:
            report.merged += 1
    return report


def upsert_lead(store: Store, rec: dict[str, Any], source: str) -> bool:
    """Insert or merge one lead. Returns True if created.

    Merge rules: fill blanks, union tags, and consent is monotone toward
    "no" — an import can never flip an existing NO back to YES. Re-consent is
    a deliberate operator action, not a side effect of a spreadsheet.
    """
    now = ts(store.now())
    with store.tx():
        rows = store.conn.execute(
            "SELECT * FROM leads WHERE (phone IS NOT NULL AND phone=?) OR (email IS NOT NULL AND email=?)",
            (rec["phone"], rec["email"]),
        ).fetchall()
        if not rows:
            lead_id = store.new_id("lead")
            store.conn.execute(
                """INSERT INTO leads (id, external_id, first_name, last_name, email, phone, timezone, tags,
                   sms_consent, email_consent, notes, source, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (lead_id, rec["external_id"], rec["first_name"], rec["last_name"], rec["email"], rec["phone"],
                 rec["timezone"], json.dumps(rec["tags"]), rec["sms_consent"].value, rec["email_consent"].value,
                 rec["notes"], source, now, now),
            )
            store.emit("lead", lead_id, "lead.created", {"source": source})
            return True
        # If phone matches one lead and email another, merge into the oldest and leave the other
        # untouched; the report surfaces it rather than silently fusing two people.
        cur = sorted(rows, key=lambda r: r["created_at"])[0]
        merged_consent = {k: _merge_consent(Consent(cur[k]), rec[k]) for k in ("sms_consent", "email_consent")}
        phone = cur["phone"] or (rec["phone"] if not _taken(store, "phone", rec["phone"], cur["id"]) else None)
        email = cur["email"] or (rec["email"] if not _taken(store, "email", rec["email"], cur["id"]) else None)
        tags = sorted(set(json.loads(cur["tags"])) | set(rec["tags"]))
        notes = cur["notes"] if rec["notes"] in cur["notes"] else (cur["notes"] + "\n" + rec["notes"]).strip()[:4000]
        store.conn.execute(
            """UPDATE leads SET external_id=COALESCE(external_id, ?), first_name=COALESCE(first_name, ?),
               last_name=COALESCE(last_name, ?), email=?, phone=?, timezone=COALESCE(timezone, ?), tags=?,
               sms_consent=?, email_consent=?, notes=?, updated_at=? WHERE id=?""",
            (rec["external_id"], rec["first_name"], rec["last_name"], email, phone, rec["timezone"],
             json.dumps(tags), merged_consent["sms_consent"].value, merged_consent["email_consent"].value,
             notes, now, cur["id"]),
        )
        store.emit("lead", cur["id"], "lead.merged", {"source": source, "matched": len(rows)})
        return False


def _taken(store: Store, col: str, value: str | None, owner: str) -> bool:
    if not value:
        return True
    row = store.conn.execute(f"SELECT id FROM leads WHERE {col}=? AND id<>?", (value, owner)).fetchone()
    return row is not None


def _merge_consent(old: Consent, new: Consent) -> Consent:
    if Consent.NO in (old, new):
        return Consent.NO
    if Consent.YES in (old, new):
        return Consent.YES
    return Consent.UNKNOWN
