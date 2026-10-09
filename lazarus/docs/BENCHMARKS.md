# Benchmarks

`python benchmarks/bench.py --sizes 1000,10000,50000` — synthetic leads, FakeChannel (no network),
one SQLite file, single process, Python 3.13, SQLite 3.45, 4-vCPU cloud container. These numbers show
where time goes and catch regressions; they are **not** a capacity promise. Real throughput is bounded by
your SMS provider long before this (Twilio long codes: ~1 msg/s per number; 10DLC/toll-free limits vary).

## The improvement loop (Phase 5)

Baseline → profile → one hypothesis at a time → re-measure on the same harness → keep only what the
numbers support. Run-to-run noise on this machine was about ±5%.

| step | hypothesis | evidence | dispatch/s @10k | inbound/s @10k | import rows/s @10k | kept? |
|---|---|---|---|---|---|---|
| baseline | — | dispatch fell 1,574→324/s from 1k→10k leads (superlinear) | 324 | 381 | 3,990 | — |
| H1 | daily-cap `COUNT` scans every message the campaign ever sent (`COALESCE` defeats the index) | per-statement profile: count time grew 90→603 ms per 1.5k sends; `EXPLAIN QUERY PLAN` | 1,867 | 381 | 3,990 | yes |
| H2 | no index on `messages.lead_id`; reply handling scans the queue | `EXPLAIN QUERY PLAN` showed `messages_ready (status=?)` scan | 1,867 | 840 | 3,990 | yes |
| H3 | one transaction per imported row | per-row `COMMIT` dominated import profile | 1,867 | 840 | 11,283 | yes |
| red-team fixes | correctness (per-message claim + fresh clock + owner-guarded writes, template guard, review hold, plan lease) — not a speed change | — | 1,145 | 802 | 10,594 | yes (correctness first) |

H1's final form is not a faster `COUNT`: the daily cap became a per-campaign-per-day counter incremented
inside the serialized claim transaction, which is both O(1) per message and exact across concurrent
workers (`test_daily_cap_enforced_at_claim_across_workers`).

## Current numbers (after all fixes; `benchmarks/results.json`)

| leads | import rows/s | enroll/s | plan/s | dispatch/s | inbound/s | DB size |
|---|---|---|---|---|---|---|
| 1,000  | 10,309 | 40,241 | 1,655 | 1,335 | 859 | 4.8 MB |
| 10,000 | 10,594 | 33,903 | 1,492 | 1,145 | 802 | 35.2 MB |
| 50,000 | 7,555  | 19,561 | 1,321 | 1,028 | 734 | 163.6 MB |

Classifier (rules, 6,540 classifications): ~2,000 replies/s, p50 453 µs, p99 1.4 ms.
The pre-optimization baseline is kept in `benchmarks/baseline.json`.

**What this means:** one worker on one SQLite file plans and dispatches >1,000 messages/s and handles
~800 replies/s without an LLM, flat from 1k to 50k leads. The engine is not the bottleneck for any realistic
SMS campaign; the provider's rate limits and the human review queue are. The database grows ~3 KB per lead
per campaign touch, mostly the event log — plan retention (archive events older than N months) for large
deployments.

**Not measured:** LLM latency/cost (no API key), multi-process write contention beyond the 4–8 thread
simulator runs, network latency to real providers.
