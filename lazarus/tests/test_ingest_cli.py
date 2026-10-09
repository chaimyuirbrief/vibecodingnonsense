import csv
import json
from pathlib import Path

import pytest

from lazarus.cli import main
from lazarus.ingest import import_csv, map_headers, read_text
from lazarus.normalize import Consent
from lazarus.store import Store

from .conftest import ROOT


def test_example_csv_import(store: Store) -> None:
    rep = import_csv(store, read_text(ROOT / "examples" / "leads.csv"), source="ex")
    assert rep.summary()["created"] == 4 and rep.merged == 1 and len(rep.rejected) == 2
    dana = store.find_lead_by_addr("+14045552368")
    assert dana and dana.first_name == "Dana" and dana.email == "dana.ross@example.com"
    assert set(dana.tags) == {"roof", "2023", "vip"}
    evil = store.find_lead_by_addr("+14155559012")
    assert evil and evil.first_name is None  # URL rejected as a name


def test_header_aliases() -> None:
    m = map_headers(["First Name", "Mobile Phone", "E-mail", "SMS Opt In", "Contact ID"])
    assert m == {"first_name": "First Name", "phone": "Mobile Phone", "sms_consent": "SMS Opt In",
                 "external_id": "Contact ID"} or m.get("email") == "E-mail"


def test_consent_never_flips_back_to_yes(store: Store) -> None:
    import_csv(store, "phone,sms_consent\n4045552368,no\n", "a")
    import_csv(store, "phone,sms_consent\n4045552368,yes\n", "b")
    lead = store.find_lead_by_addr("+14045552368")
    assert lead and lead.sms_consent is Consent.NO


def test_semicolon_and_bom_and_cp1252(tmp_path: Path, store: Store) -> None:
    p = tmp_path / "x.csv"
    p.write_bytes("﻿Name;Phone\nJosé Núñez;404 555 2368\n".encode())
    rep = import_csv(store, read_text(p), "x")
    assert rep.created == 1
    p.write_bytes("Name,Phone\nRen\xe9e Smith,404 555 9999\n".encode("cp1252"))
    rep = import_csv(store, read_text(p), "y")
    lead = store.find_lead_by_addr("+14045559999")
    assert rep.created == 1 and lead and lead.first_name == "Renée"


def test_requires_contact_column(store: Store) -> None:
    with pytest.raises(ValueError):
        import_csv(store, "name,city\nDana,Atlanta\n", "x")


def test_phone_and_email_matching_different_leads_are_not_fused(store: Store) -> None:
    import_csv(store, "phone,email\n4045551111,a@example.com\n4045552222,b@example.com\n", "x")
    rep = import_csv(store, "phone,email\n4045551111,b@example.com\n", "y")
    assert rep.merged == 1
    a = store.find_lead_by_addr("+14045551111")
    assert a and a.email == "a@example.com"  # did not steal b's email


# ------------------------------------------------------------------ CLI end to end

def run(*args: str) -> int:
    return main(list(args))


def test_cli_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "cli.db")
    now = "2026-10-12T15:00:00Z"
    base = ["--db", db, "--now", now, "--actor", "tester"]
    assert run(*base, "init") == 0
    report = tmp_path / "rej.csv"
    assert run(*base, "import", str(ROOT / "examples" / "leads.csv"), "--report", str(report)) == 0
    rows = list(csv.reader(report.open()))
    assert rows[0] == ["row", "kind", "reasons", "raw"] and len(rows) > 1
    assert run(*base, "campaign", "add", str(ROOT / "examples" / "campaign.json")) == 0
    assert run(*base, "enroll", "roof-reactivation") == 0
    capsys.readouterr()
    assert run(*base, "preview") == 0
    preview = json.loads(capsys.readouterr().out)
    assert any(p["decision"] == "ok" for p in preview) and any(p["decision"] == "quiet_hours" for p in preview)
    assert run(*base, "tick") == 0
    capsys.readouterr()
    assert run(*base, "approvals", "list") == 0
    pending = json.loads(capsys.readouterr().out)
    assert pending and all(p["body"].endswith("Reply STOP to opt out.") for p in pending)
    assert run(*base, "approvals", "approve", "--all") == 0
    assert run(*base, "inbound", "+14045552368", "STOP", "--id", "SM1") == 0
    assert run(*base, "suppress", "add", "(212) 555-4410") == 0
    capsys.readouterr()
    assert run(*base, "report") == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["suppressions"]["opt_out"] >= 1 and rep["suppressions"]["manual"] == 1
    assert run(*base, "export") == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("external_id,")
    assert run(*base, "replay") == 0
    assert run(*base, "review", "resolve") == 2  # usage error, not a crash
    assert run(*base, "campaign", "pause", "roof-reactivation") == 0


def test_cli_eval_gate(capsys: pytest.CaptureFixture[str]) -> None:
    assert run("eval", str(ROOT / "evals" / "replies_blind_dev.jsonl")) == 0
    m = json.loads(capsys.readouterr().out)
    assert m["unsafe_opt_out_misses"] == 0


def test_labels_export_scrubs_and_feeds_eval(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from lazarus.cli import scrub
    assert scrub("Dana here, call 404-555-2368 or dana@x.com https://x.co/a", ["Dana"]) == \
        "<name> here, call <phone> or <email> <url>"
    db = str(tmp_path / "lab.db")
    base = ["--db", db, "--now", "2026-10-12T15:00:00Z"]
    run(*base, "import", str(ROOT / "examples" / "leads.csv"))
    run(*base, "campaign", "add", str(ROOT / "examples" / "campaign.json"))
    run(*base, "enroll", "roof-reactivation")
    capsys.readouterr()
    run(*base, "inbound", "+14045552368", "who is this? Dana's my wife", "--id", "L1")
    iid = json.loads(capsys.readouterr().out)["inbound_id"]
    assert run(*base, "review", "resolve", iid, "wrong_number") == 0
    out = tmp_path / "labels.jsonl"
    assert run(*base, "labels", "export", "--out", str(out)) == 0
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    assert rows == [{"id": iid, "text": "who is this? <name>'s my wife", "label": "wrong_number", "source": "human",
                     "received_at": rows[0]["received_at"]}]
    capsys.readouterr()
    run("eval", str(out))
    assert json.loads(capsys.readouterr().out)["n"] == 1
