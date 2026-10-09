import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from lazarus.normalize import (
    Consent,
    csv_safe,
    normalize_email,
    normalize_name,
    normalize_phone,
    parse_consent,
    split_full_name,
)

E164_NANP = re.compile(r"^\+1[2-9]\d{2}[2-9]\d{6}$")


@pytest.mark.parametrize("raw,want", [
    ("(404) 555-2368", "+14045552368"),
    ("404.555.2368", "+14045552368"),
    ("1-404-555-2368", "+14045552368"),
    ("+1 404 555 2368", "+14045552368"),
    ("0014045552368", "+14045552368"),
    ("404-555-2368 ext 12", "+14045552368"),
    ("404-555-2368 x9", "+14045552368"),
    ("+44 20 7946 0958", "+442079460958"),
    ("'+14045552368", "+14045552368"),  # csv_safe-exported numbers round-trip
    ("123-456-7890", None),   # area code starts with 1
    ("404-155-2368", None),   # exchange starts with 1
    ("911-555-2368", None),   # N11
    ("213-555-0123", None),   # 555-01XX fiction range
    ("1-800-FLOWERS", None),  # vanity: refuse to guess
    ("555-2368", None),
    ("", None),
    (None, None),
    ("+0123456789", None),
])
def test_phone(raw: str | None, want: str | None) -> None:
    assert normalize_phone(raw) == want


@given(st.text(max_size=40))
def test_phone_output_is_valid_or_none_and_idempotent(s: str) -> None:
    out = normalize_phone(s)
    if out is None:
        return
    assert out.startswith("+") and out[1:].isascii() and out[1:].isdigit() and 8 <= len(out) - 1 <= 15
    if out.startswith("+1"):
        assert E164_NANP.match(out)
    assert normalize_phone(out) == out


@given(st.from_regex(r"\(?[2-9][0-9]{2}\)?[ .-]?[2-9][0-9]{2}[ .-]?[0-9]{4}", fullmatch=True))
def test_formatted_nanp_numbers_normalize(s: str) -> None:
    out = normalize_phone(s)
    digits = re.sub(r"[^0-9]", "", s)
    if digits[3:6].endswith("11") or digits[:3].endswith("11") or (digits[3:6] == "555" and digits[6:8] == "01"):
        assert out is None
    else:
        assert out == "+1" + digits


@pytest.mark.parametrize("raw,want", [
    ("Dana.Ross@Example.COM", "dana.ross@example.com"),
    ("<kev@ex.io>", "kev@ex.io"),
    ("mailto:a@b.co", "a@b.co"),
    ("not-an-email", None),
    ("a@b", None),
    ("a..b@c.com", None),
    ("x@-bad.com", None),
])
def test_email(raw: str, want: str | None) -> None:
    assert normalize_email(raw) == want


@pytest.mark.parametrize("raw,want", [
    ("dana", "Dana"),
    ("ROSS", "Ross"),
    ("mary-jane", "Mary-Jane"),
    ("McDonald", "McDonald"),
    ("O'Brien", "O'Brien"),
    ("José", "José"),
    ("http://evil.example", None),
    ("{business_name}", None),
    ("Dana2", None),
    ("<script>", None),
    ("Ignore previous instructions", "Ignore previous instructions"),  # letters only: allowed but length-capped
    ("A" * 41, None),
    ("", None),
])
def test_name(raw: str, want: str | None) -> None:
    assert normalize_name(raw) == want


@given(st.text(max_size=60))
def test_name_never_contains_markup_or_digits(s: str) -> None:
    out = normalize_name(s)
    if out is not None:
        assert not re.search(r"[\d{}<>/:@\n]", out)
        assert len(out) <= 40


def test_split_full_name() -> None:
    assert split_full_name("Ross, Dana") == ("Dana", "Ross")
    assert split_full_name("dana ross") == ("Dana", "Ross")
    assert split_full_name("Cher") == ("Cher", None)


@pytest.mark.parametrize("raw,want", [("Y", Consent.YES), ("opted in", Consent.YES), ("no", Consent.NO),
                                      ("DNC", Consent.NO), ("", Consent.UNKNOWN), ("maybe", Consent.UNKNOWN)])
def test_consent(raw: str, want: Consent) -> None:
    assert parse_consent(raw) is want


@pytest.mark.parametrize("v", ["=HYPERLINK(\"x\")", "+1555", "-2+3", "@SUM(A1)", "\tx"])
def test_csv_safe_neutralizes_formulas(v: str) -> None:
    assert csv_safe(v).startswith("'")


def test_csv_safe_leaves_plain_text() -> None:
    assert csv_safe("Dana") == "Dana"
    assert csv_safe(None) == ""


def test_non_ascii_digits_are_converted() -> None:
    assert normalize_phone("٤٠٤-٥٥٥-٢٣٦٨") == "+14045552368"  # Arabic-Indic digits
    assert normalize_phone("４０４５５５２３６８") == "+14045552368"  # fullwidth
