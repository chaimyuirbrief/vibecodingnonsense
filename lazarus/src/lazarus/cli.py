"""Command-line interface.

Configuration comes from flags and environment variables (never from files
committed to git). See ``.env.example``.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import signal
import sys
import time
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .channels import Channel
from .compose import compose, finalize
from .engine import Engine
from .evaluate import evaluate, load_jsonl
from .ingest import import_csv, read_text
from .llm import AnthropicProvider, BudgetedProvider, CachingProvider, LLMProvider
from .models import Campaign, Label
from .normalize import csv_safe, normalize_email, normalize_phone
from .policy import check_send
from .replay import replay, timeline
from .store import Store
from .timeutil import Clock, FakeClock, parse_iso, ts


def env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def open_store(args: argparse.Namespace) -> Store:
    clock: Clock = FakeClock(parse_iso(args.now)) if getattr(args, "now", None) else Clock()
    return Store(args.db, clock)


def build_llm(store: Store) -> LLMProvider | None:
    kind = env("LAZARUS_LLM", "none")
    if kind == "none":
        return None
    if kind != "anthropic":
        raise SystemExit(f"unknown LAZARUS_LLM={kind!r} (use none|anthropic)")
    inner = AnthropicProvider(model=env("LAZARUS_LLM_MODEL", "claude-opus-5-5") or "claude-opus-5-5",
                              effort=env("LAZARUS_LLM_EFFORT", "low") or "low")
    budget = float(env("LAZARUS_LLM_BUDGET_USD", "5") or "5")
    return CachingProvider(BudgetedProvider(inner, max_usd=budget, store=store), store)


def build_channels() -> dict[str, Channel]:
    chans: dict[str, Channel] = {}
    sid, tok = env("TWILIO_ACCOUNT_SID"), env("TWILIO_AUTH_TOKEN")
    if sid and tok:
        from .channels.twilio import TwilioSMS
        chans["sms"] = TwilioSMS(sid, tok, from_number=env("TWILIO_FROM"),
                                 messaging_service_sid=env("TWILIO_MESSAGING_SERVICE_SID"),
                                 status_callback=env("TWILIO_STATUS_CALLBACK"))
    host = env("SMTP_HOST")
    if host:
        from .channels.smtp import SMTPEmail
        frm = env("SMTP_FROM")
        unsub = env("SMTP_UNSUBSCRIBE_MAILTO")
        if not frm or not unsub:
            raise SystemExit("SMTP_FROM and SMTP_UNSUBSCRIBE_MAILTO are required with SMTP_HOST")
        chans["email"] = SMTPEmail(host, int(env("SMTP_PORT", "587") or "587"), env("SMTP_USER"), env("SMTP_PASSWORD"),
                                   frm, unsub, env("SMTP_UNSUBSCRIBE_URL"))
    return chans


def build_engine(store: Store, with_llm: bool = True, llm: LLMProvider | None = None) -> Engine:
    sink = None
    url, secret = env("LAZARUS_WEBHOOK_URL"), env("LAZARUS_WEBHOOK_SECRET")
    if url and secret:
        from .webhooks import WebhookSink
        sink = WebhookSink(url, secret)
    return Engine(store, build_channels(), llm=(llm or build_llm(store)) if with_llm else None,
                  worker_id=env("LAZARUS_WORKER_ID", f"pid-{os.getpid()}") or "w", sink=sink)


def out(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str, ensure_ascii=False))


# ------------------------------------------------------------------ commands

def cmd_init(a: argparse.Namespace) -> int:
    st = open_store(a)
    out({"db": a.db, "schema": st.conn.execute("PRAGMA user_version").fetchone()[0]})
    return 0


def cmd_import(a: argparse.Namespace) -> int:
    st = open_store(a)
    rep = import_csv(st, read_text(a.csv), source=a.source or Path(a.csv).name, default_country=a.country)
    out(rep.summary())
    if a.report:
        with open(a.report, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["row", "kind", "reasons", "raw"])
            for kind, items in (("rejected", rep.rejected), ("warning", rep.warnings)):
                for it in items:
                    w.writerow([it.row, kind, csv_safe("; ".join(it.reasons)), csv_safe(json.dumps(it.raw, ensure_ascii=False))])
    return 0


def cmd_campaign(a: argparse.Namespace) -> int:
    st = open_store(a)
    if a.action == "add":
        c = Campaign.model_validate_json(Path(a.file).read_text(encoding="utf-8"))
        st.save_campaign(c, actor=a.actor)
        out({"saved": c.id, "steps": len(c.steps)})
    elif a.action == "list":
        out([dict(r) for r in st.conn.execute("SELECT id, status, created_at, updated_at FROM campaigns")])
    elif a.action == "show":
        found = st.get_campaign(a.id)
        out(json.loads(found.model_dump_json()) if found else {"error": "not_found"})
    elif a.action in ("pause", "resume"):
        st.set_campaign_status(a.id, "paused" if a.action == "pause" else "active", actor=a.actor)
        out({a.id: a.action})
    return 0


def cmd_enroll(a: argparse.Namespace) -> int:
    st = open_store(a)
    n = build_engine(st, with_llm=False).enroll(a.campaign, tag=a.tag, actor=a.actor)
    out({"enrolled": n})
    return 0


def cmd_preview(a: argparse.Namespace) -> int:
    """Read-only: what would plan+dispatch do right now? Never writes, never calls an LLM."""
    st = open_store(a)
    now = st.now()
    rows = st.conn.execute(
        "SELECT * FROM enrollments WHERE state='active' AND next_due_at<=? ORDER BY next_due_at LIMIT ?",
        (ts(now), a.limit)).fetchall()
    res = []
    for e in rows:
        c = st.get_campaign(e["campaign_id"])
        lead = st.get_lead(e["lead_id"])
        if c is None or lead is None or e["step_index"] >= len(c.steps):
            continue
        step = c.steps[e["step_index"]]
        comp = compose(step, lead, c, is_first=e["step_index"] == 0, llm=None)
        body, _ = finalize(comp, step, c, is_first=e["step_index"] == 0)
        d = check_send(st, lead, c, step.channel, now)
        res.append({"lead": lead.id, "to": lead.phone if step.channel == "sms" else lead.email, "step": e["step_index"],
                    "decision": d.reason, "retry_at": d.retry_at.isoformat() if d.retry_at else None, "body": body})
    out(res)
    return 0


def cmd_tick(a: argparse.Namespace) -> int:
    st = open_store(a)
    out(build_engine(st).tick())
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    st = open_store(a)
    eng = build_engine(st)
    stop = {"flag": False}

    def handle(sig: int, frame: Any) -> None:
        stop["flag"] = True

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)
    while not stop["flag"]:
        res = eng.tick()
        if any(res.values()):
            print(json.dumps({"at": datetime.now().isoformat(timespec="seconds"), **res}), flush=True)
        for _ in range(int(a.interval * 10)):
            if stop["flag"]:
                break
            time.sleep(0.1)
    return 0


def cmd_approvals(a: argparse.Namespace) -> int:
    st = open_store(a)
    eng = build_engine(st, with_llm=False)
    if a.action == "list":
        out([dict(r) for r in st.conn.execute(
            "SELECT id, campaign_id, to_addr, composed_by, body, created_at FROM messages WHERE status='pending_approval' ORDER BY created_at LIMIT ?",
            (a.limit,))])
    elif a.action == "approve":
        ids = a.ids
        if a.all:
            ids = [r["id"] for r in st.conn.execute("SELECT id FROM messages WHERE status='pending_approval'")]
        out({i: eng.approve(i, actor=a.actor) for i in ids})
    elif a.action == "reject":
        out({i: eng.reject(i, actor=a.actor, reason=a.reason) for i in a.ids})
    return 0


def cmd_review(a: argparse.Namespace) -> int:
    st = open_store(a)
    eng = build_engine(st, with_llm=False)
    if a.action == "list":
        out([dict(r) for r in st.conn.execute(
            "SELECT id, from_addr, body, label, label_source, possible_opt_out, received_at FROM inbound WHERE needs_review=1 AND resolved_at IS NULL ORDER BY received_at")])
    else:
        out(eng.resolve_review(a.id, Label(a.label), actor=a.actor))
    return 0


def cmd_unknown(a: argparse.Namespace) -> int:
    st = open_store(a)
    eng = build_engine(st, with_llm=False)
    if a.action == "list":
        out([dict(r) for r in st.conn.execute(
            "SELECT id, channel, to_addr, last_error, updated_at FROM messages WHERE status='unknown'")])
    else:
        out({"resolved": eng.resolve_unknown(a.id, sent=a.action == "sent", actor=a.actor)})
    return 0


def cmd_inbound(a: argparse.Namespace) -> int:
    st = open_store(a)
    out(build_engine(st).handle_inbound(a.channel, a.sender, a.body, provider_id=a.id))
    return 0


def cmd_suppress(a: argparse.Namespace) -> int:
    st = open_store(a)
    if a.action == "list":
        out([dict(r) for r in st.conn.execute("SELECT * FROM suppressions ORDER BY created_at")])
        return 0
    addr = normalize_phone(a.addr) or normalize_email(a.addr)
    if not addr:
        print("not a valid phone or email", file=sys.stderr)
        return 2
    out({"suppressed": st.suppress(addr, a.reason, source="cli", actor=a.actor), "addr": addr})
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    st = open_store(a)

    def q(sql: str, *p: Any) -> dict[str, int]:
        return {r[0]: r[1] for r in st.conn.execute(sql, p)}

    out({
        "enrollments": q("SELECT state, COUNT(*) FROM enrollments GROUP BY state"),
        "messages": q("SELECT status, COUNT(*) FROM messages GROUP BY status"),
        "replies": q("SELECT label, COUNT(*) FROM inbound GROUP BY label"),
        "needs_review": st.conn.execute("SELECT COUNT(*) FROM inbound WHERE needs_review=1 AND resolved_at IS NULL").fetchone()[0],
        "suppressions": q("SELECT reason, COUNT(*) FROM suppressions GROUP BY reason"),
        "outbox": q("SELECT status, COUNT(*) FROM outbox GROUP BY status"),
        "llm_usd": round(st.conn.execute("SELECT COALESCE(SUM(cost_usd),0) FROM llm_usage").fetchone()[0], 4),
    })
    return 0


def cmd_export(a: argparse.Namespace) -> int:
    st = open_store(a)
    rows = st.conn.execute(
        """SELECT l.external_id, l.first_name, l.last_name, l.phone, l.email, e.campaign_id, e.state, e.outcome, e.updated_at
           FROM enrollments e JOIN leads l ON l.id=e.lead_id WHERE (? IS NULL OR e.state=?) ORDER BY e.updated_at""",
        (a.state, a.state)).fetchall()
    w = csv.writer(sys.stdout)
    w.writerow(["external_id", "first_name", "last_name", "phone", "email", "campaign", "state", "outcome", "updated_at"])
    for r in rows:
        w.writerow([csv_safe(v) for v in r])
    return 0


_PHONE_RX = re.compile(r"\+?\d[\d\s().-]{6,}\d")
_EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL_RX = re.compile(r"(?i)\bhttps?://\S+")


def scrub(text: str, names: list[str]) -> str:
    """Remove obvious PII before replies leave the database as training/eval data."""
    out = _URL_RX.sub("<url>", _EMAIL_RX.sub("<email>", _PHONE_RX.sub("<phone>", text)))
    for n in names:
        if n and len(n) > 1:
            out = re.sub(rf"(?i)\b{re.escape(n)}\b", "<name>", out)
    return out


def cmd_labels(a: argparse.Namespace) -> int:
    """Export human-resolved replies as an eval set (gold labels from your own traffic)."""
    st = open_store(a)
    q = """SELECT i.id, i.body, i.label, i.label_source, i.received_at, l.first_name, l.last_name
           FROM inbound i LEFT JOIN leads l ON l.id=i.lead_id WHERE i.label IS NOT NULL"""
    if not a.include_auto:
        q += " AND i.label_source='human'"
    n = 0
    with open(a.out, "w", encoding="utf-8") as f:
        for r in st.conn.execute(q + " ORDER BY i.received_at"):
            text = r["body"] if a.no_scrub else scrub(r["body"], [r["first_name"] or "", r["last_name"] or ""])
            f.write(json.dumps({"id": r["id"], "text": text, "label": r["label"], "source": r["label_source"],
                                "received_at": r["received_at"]}, ensure_ascii=False) + "\n")
            n += 1
    out({"exported": n, "file": a.out, "scrubbed": not a.no_scrub, "includes_auto_labels": a.include_auto})
    return 0


def cmd_timeline(a: argparse.Namespace) -> int:
    out(timeline(open_store(a), a.lead))
    return 0


def cmd_replay(a: argparse.Namespace) -> int:
    rep = replay(open_store(a))
    out({"ok": rep.ok, "events": rep.events, "enrollments": rep.enrollments_checked,
         "messages": rep.messages_checked, "mismatches": rep.mismatches[:50]})
    return 0 if rep.ok else 1


def cmd_simulate(a: argparse.Namespace) -> int:
    from .simulate import SimConfig, run
    r = run(SimConfig(leads=a.leads, days=a.days, seed=a.seed, workers=a.workers, corpus=a.corpus))
    print(r.to_json())
    return 0 if r.ok else 1


def cmd_eval(a: argparse.Namespace) -> int:
    llm = None
    if a.llm == "anthropic":
        st = Store(":memory:")
        llm = build_llm(st) if env("LAZARUS_LLM") == "anthropic" else CachingProvider(
            BudgetedProvider(AnthropicProvider(), max_usd=float(a.budget), store=st), st)
    rep = evaluate(load_jsonl(a.set), llm=llm)
    m = rep.metrics()
    if a.show_errors:
        m["errors"] = rep.errors
    m["unsafe"] = rep.unsafe
    out(m)
    return 0 if not rep.unsafe else 1


def cmd_serve(a: argparse.Namespace) -> int:
    from .server import make_server
    db = a.db
    shared_llm = build_llm(Store(db))  # one provider (and one budget) for every request handler
    srv = make_server(lambda: build_engine(Store(db), llm=shared_llm), host=a.host, port=a.port,
                      public_url=env("LAZARUS_PUBLIC_URL"), twilio_auth_token=env("TWILIO_AUTH_TOKEN"),
                      inbound_secret=env("LAZARUS_INBOUND_SECRET"))
    print(f"listening on http://{a.host}:{a.port}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lazarus", description="Compliance-first dead-lead reactivation engine")
    p.add_argument("--db", default=env("LAZARUS_DB", "lazarus.db"))
    p.add_argument("--now", help="pretend the current time is this ISO-8601 instant (testing/demos)")
    p.add_argument("--actor", default=env("USER", "operator"))
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)
    s = sub.add_parser("import")
    s.add_argument("csv")
    s.add_argument("--source")
    s.add_argument("--country", default="US")
    s.add_argument("--report", help="write rejected/warning rows to this CSV")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("campaign")
    s.add_argument("action", choices=["add", "list", "show", "pause", "resume"])
    s.add_argument("id_or_file", nargs="?")
    s.set_defaults(fn=cmd_campaign)

    s = sub.add_parser("enroll")
    s.add_argument("campaign")
    s.add_argument("--tag")
    s.set_defaults(fn=cmd_enroll)

    s = sub.add_parser("preview")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_preview)
    sub.add_parser("tick").set_defaults(fn=cmd_tick)
    s = sub.add_parser("run")
    s.add_argument("--interval", type=float, default=60)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("approvals")
    s.add_argument("action", choices=["list", "approve", "reject"])
    s.add_argument("ids", nargs="*")
    s.add_argument("--all", action="store_true")
    s.add_argument("--reason", default="rejected")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_approvals)

    s = sub.add_parser("review")
    s.add_argument("action", choices=["list", "resolve"])
    s.add_argument("id", nargs="?")
    s.add_argument("label", nargs="?", choices=[lbl.value for lbl in Label])
    s.set_defaults(fn=cmd_review)

    s = sub.add_parser("unknown")
    s.add_argument("action", choices=["list", "sent", "not-sent"])
    s.add_argument("id", nargs="?")
    s.set_defaults(fn=cmd_unknown)

    s = sub.add_parser("inbound", help="feed a reply by hand (testing, or providers without webhooks)")
    s.add_argument("sender")
    s.add_argument("body")
    s.add_argument("--channel", default="sms", choices=["sms", "email"])
    s.add_argument("--id", help="provider message id (dedupe key)")
    s.set_defaults(fn=cmd_inbound)

    s = sub.add_parser("suppress")
    s.add_argument("action", choices=["add", "list"])
    s.add_argument("addr", nargs="?")
    s.add_argument("--reason", default="manual")
    s.set_defaults(fn=cmd_suppress)

    sub.add_parser("report").set_defaults(fn=cmd_report)
    s = sub.add_parser("export")
    s.add_argument("--state")
    s.set_defaults(fn=cmd_export)
    s = sub.add_parser("labels", help="export human-resolved replies as a JSONL eval set")
    s.add_argument("action", choices=["export"])
    s.add_argument("--out", default="labels.jsonl")
    s.add_argument("--include-auto", action="store_true", help="also export rule/LLM labels (silver, not gold)")
    s.add_argument("--no-scrub", action="store_true", help="keep phone numbers, emails, URLs and lead names")
    s.set_defaults(fn=cmd_labels)
    s = sub.add_parser("timeline")
    s.add_argument("lead")
    s.set_defaults(fn=cmd_timeline)
    sub.add_parser("replay").set_defaults(fn=cmd_replay)

    s = sub.add_parser("simulate")
    s.add_argument("--leads", type=int, default=300)
    s.add_argument("--days", type=int, default=21)
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--workers", type=int, default=1)
    s.add_argument("--corpus", default="evals/replies_blind_dev.jsonl")
    s.set_defaults(fn=cmd_simulate)

    s = sub.add_parser("eval")
    s.add_argument("set")
    s.add_argument("--llm", choices=["none", "anthropic"], default="none")
    s.add_argument("--budget", default="2")
    s.add_argument("--show-errors", action="store_true")
    s.set_defaults(fn=cmd_eval)

    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = parser().parse_args(argv)
    if a.cmd == "campaign":
        if a.action == "add":
            a.file = a.id_or_file
        else:
            a.id = a.id_or_file
        if a.action != "list" and not a.id_or_file:
            print(f"campaign {a.action} needs an argument", file=sys.stderr)
            return 2
    if a.cmd == "review" and a.action == "resolve" and not (a.id and a.label):
        print("review resolve <inbound_id> <label>", file=sys.stderr)
        return 2
    if a.cmd == "unknown" and a.action != "list" and not a.id:
        print("unknown sent|not-sent <message_id>", file=sys.stderr)
        return 2
    if a.cmd == "suppress" and a.action == "add" and not a.addr:
        print("suppress add <phone|email>", file=sys.stderr)
        return 2
    fn = a.fn
    rc: int = fn(a)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
