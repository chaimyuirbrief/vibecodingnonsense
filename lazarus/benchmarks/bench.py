"""Throughput benchmarks on synthetic data. Usage: python benchmarks/bench.py [--sizes 1000,10000] [--json out.json]

Synthetic and single-machine: numbers show relative cost of each stage and catch
regressions; they are not a capacity guarantee for your hardware or provider limits.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import sqlite3
import statistics
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lazarus.channels.fake import FakeChannel
from lazarus.classify import classify
from lazarus.engine import Engine, EngineConfig
from lazarus.evaluate import load_jsonl
from lazarus.ingest import import_csv
from lazarus.models import Campaign, Step
from lazarus.store import IdGen, Store
from lazarus.timeutil import FakeClock

ROOT = Path(__file__).resolve().parent.parent
START = datetime(2026, 10, 12, 15, 0, tzinfo=UTC)  # Monday 11:00 ET


def synth_csv(n: int, seed: int = 1) -> str:
    rng = random.Random(seed)
    areas = ["404", "212", "312", "415", "617", "713", "206", "303"]
    tzs = ["America/New_York", "America/Chicago", "America/Los_Angeles", ""]
    lines = ["Contact ID,First Name,Last Name,Mobile Phone,Email,Time Zone,Tags,SMS Opt In,Notes"]
    for i in range(n):
        phone = f"({rng.choice(areas)}) {rng.randint(200, 999)}-{rng.randint(0, 9999):04d}"
        lines.append(f"c{i},Name{i % 97},Last{i % 89},{phone},user{i}@example.com,{rng.choice(tzs)},roof,yes,note {i}")
    return "\n".join(lines) + "\n"


def campaign() -> Campaign:
    return Campaign(id="bench", name="Bench", business_name="Brightside Roofing", sender_name="Mike",
                    steps=[Step(delay_hours=0, template="Hi {first_name|there}, it's {sender_name} from {business_name}. Still need a roof?")],
                    approve_first_n=0, daily_send_cap=10**9, fallback_timezones=["America/New_York"])


def timed(fn: Callable[[], Any]) -> tuple[float, Any]:
    t = time.perf_counter()
    out = fn()
    return time.perf_counter() - t, out


def bench_pipeline(n: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as d:
        clock = FakeClock(START)
        st = Store(Path(d) / "b.db", clock, IdGen(1))
        text = synth_csv(n)
        t_import, rep = timed(lambda: import_csv(st, text, "bench"))
        st.save_campaign(campaign())
        ch = FakeChannel("sms", clock=clock.now)
        eng = Engine(st, {"sms": ch}, config=EngineConfig(plan_batch=n, dispatch_batch=n))
        t_enroll, enrolled = timed(lambda: eng.enroll("bench"))
        t_plan, planned = timed(lambda: eng.plan())
        t_dispatch, dispatched = timed(lambda: eng.dispatch())
        corpus = [it["text"] for it in load_jsonl(ROOT / "evals" / "replies_blind_dev.jsonl")]
        phones = [r["phone"] for r in st.conn.execute("SELECT phone FROM leads WHERE phone IS NOT NULL LIMIT ?", (min(n, 2000),))]
        replies = [(p, corpus[i % len(corpus)]) for i, p in enumerate(phones)]
        t_inbound, _ = timed(lambda: [eng.handle_inbound("sms", p, b, provider_id=f"b{i}") for i, (p, b) in enumerate(replies)])
        size_mb = (Path(d) / "b.db").stat().st_size / 1e6
        st.close()
    return {
        "n": n,
        "import_rows_per_s": round(rep.rows / t_import),
        "enroll_per_s": round(enrolled / t_enroll),
        "plan_per_s": round(sum(planned.values()) / t_plan),
        "dispatch_per_s": round(sum(dispatched.values()) / t_dispatch),
        "inbound_per_s": round(len(replies) / t_inbound),
        "sent": len(ch.deliveries),
        "db_mb": round(size_mb, 1),
    }


def bench_classifier(reps: int = 20) -> dict[str, Any]:
    texts = []
    for name in ("blind_dev", "blind_dev2"):
        texts += [it["text"] for it in load_jsonl(ROOT / "evals" / f"replies_{name}.jsonl")]
    lat = []
    for _ in range(reps):
        for t in texts:
            s = time.perf_counter()
            classify(t)
            lat.append(time.perf_counter() - s)
    lat.sort()
    return {"messages": len(lat), "per_s": round(len(lat) / sum(lat)),
            "p50_us": round(statistics.median(lat) * 1e6), "p99_us": round(lat[int(len(lat) * 0.99)] * 1e6)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="1000,10000")
    ap.add_argument("--json")
    a = ap.parse_args()
    res = {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version, "machine": platform.machine(),
           "pipeline": [bench_pipeline(int(s)) for s in a.sizes.split(",")], "classifier": bench_classifier()}
    print(json.dumps(res, indent=2))
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    _ = timedelta  # keep import for users extending the script
    main()
