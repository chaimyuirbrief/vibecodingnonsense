# Roadmap (prioritized)

Ordered by value per unit of effort, with the reason each item is where it is.

## Next three

1. **Measure the LLM layer on the held-out sets** (needs an API key; ~1 hour, a few dollars).
   `lazarus eval evals/replies_blind_test2.jsonl --llm anthropic --budget 2`. This is the single biggest
   unknown: if the second opinion removes the remaining unsafe misses and cuts the review rate, the product
   becomes usable unattended for English traffic. Then try a cheaper model at the same effort and keep it
   only if unsafe misses stay at zero.
2. **Collect real replies and grow the eval set.** Every human `review resolve` is a labeled example; add an
   `export-labels` command that writes resolved replies (PII-scrubbed) to JSONL, and gate releases on a
   real-data eval instead of synthetic sets.
3. **Twilio live smoke test + delivery-status callbacks.** Send to one consenting test number, verify the
   inbound webhook end to end behind a tunnel, then add `/webhooks/twilio/status` so carrier-level failures
   (30003 unreachable, 30005 unknown, 30006 landline, 30007 filtered) update message state and suppress dead
   numbers.

## Later

- **Twilio idempotent reconciliation**: look up ambiguous sends by `To` + time window + body hash via the
  Messages list API, reducing `unknown` items that need a human.
- **Global LLM budget** shared across worker processes (currently per process) via a ledger row with a
  compare-and-set increment.
- **Event hash chain** (each event stores the hash of the previous) so a DB-level tamper is detectable,
  not only a missing event.
- **Postgres backend** behind the `Store` interface when one SQLite file per client stops being enough
  (see BENCHMARKS.md for where the ceiling is).
- **CRM-native adapters** (HubSpot, GoHighLevel, Pipedrive) on top of the signed webhook, including pulling
  "do not contact" flags back in.
- **Review UI**: a minimal local web page for the approval/review/unknown queues (bound to 127.0.0.1, like
  the WhatsApp bot's panel).
- **WhatsApp Business Cloud API channel** — the sanctioned route for WhatsApp outreach.
