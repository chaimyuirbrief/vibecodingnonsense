# Architecture

## One-paragraph version

Lazarus is a single-process-or-many state machine over one SQLite file per client. Leads are imported
and normalized; a campaign is a short sequence of steps. `tick()` plans due steps into messages (template
first, optional LLM rewrite behind a deterministic guard), parks them for approval if required, then
dispatchers claim messages with leases, re-check the send policy at the last moment, call the provider,
and record the outcome. Replies come in by webhook, are classified (rules → strict gates → optional LLM),
and routed: suppress, hand off to a CRM, snooze, close, or pause for a human. Every state change writes an
event in the same transaction, so the event log can be replayed to verify the tables.

```
 CSV/CRM ──▶ ingest ──▶ leads ──enroll──▶ enrollments ──plan──▶ messages ──dispatch──▶ Channel (Twilio/SMTP)
                                              ▲                  │  ▲                       │
                         snooze/close/handoff │        approve ──┘  └── reconcile (lookup)   │
                                              │                                              ▼
 CRM webhook ◀── outbox ◀── route ◀── classify ◀── inbound ◀────────────── provider webhook (server.py)
                                              │
                                    events (append-only) ──▶ replay / timeline
```

## State machines

**Enrollment** (lead × campaign): `active` → `awaiting_send` → `active` (next step) … → `exhausted`.
Replies move it to `handed_off`, `opted_out`, `wrong_number`, `not_interested`, back to `active` with a
later `next_due_at` (snooze), or to `paused` (human review). `blocked`/`failed` are terminal policy/delivery
outcomes.

**Message**: `pending_approval` → `queued` → `sending` (leased, one message per claim) → `sent` |
`queued` (retry with backoff) | `failed` | `unknown`. `held` while the lead is under review (remembers whether it was awaiting approval),
`canceled` when the enrollment ends, `rejected` by an operator.

## Key decisions and why

| decision | why | cost |
|---|---|---|
| **At-most-once delivery.** Ambiguous outcomes → `unknown`, resolved by provider lookup or a human; never blind resend. A lookup that says "not found" allows a resend only after the lease plus a grace period longer than any adapter's request timeout (a request can still be in flight). | A duplicate text to someone who may already be irritated is worse than a missed touch. | Some sends need manual reconciliation when the provider has no lookup (Twilio). |
| **Per-message claim with a fresh clock.** Each message is policy-checked, claimed (lease + owner), sent and recorded on its own; every post-claim write is compare-and-set on status *and* lease owner; the last 5 minutes of a send window count as closed. | Batch claims let leases lapse mid-batch (duplicates) and judged quiet hours at batch-start time (texts after 20:00). | One extra transaction per message (~1,100 msg/s/worker still; see BENCHMARKS.md). |
| **Daily cap as a counter incremented in the claim transaction; planning stops at remaining capacity.** | Exact across concurrent workers and O(1) per message; a backlog stays as due enrollments instead of re-deferred messages. | The cap counts send *attempts* (a retried message counts twice) — conservative. |
| **Review hold is per lead.** Any unresolved flagged reply blocks planning and sending for that lead in every campaign. | A pause scoped to one enrollment was bypassed by resolving a different reply, a second campaign, or a "later" reply. | One indexed `EXISTS` per plan/send. |
| **Approval gate counts human approvals.** Until N messages of a campaign have been approved, every new one waits. | Counting drafts let message N+1 go out while the first N sat unreviewed. | — |
| **Idempotency key = `enrollment:step:generation`.** | A step can never have two live messages; a canceled step gets a fresh generation so it can be re-planned after a snooze. | Key semantics must be preserved by any new code path (tests cover it). |
| **Policy checked at plan *and* at send.** | Opt-outs, suppressions and windows change while messages wait for approval or quiet hours. | One extra query set per send. |
| **Unknown timezone → intersection of fallback zones (+ the zone implied by a non-continental area code).** Non-North-American numbers need an explicit timezone; `EST`/`PST`-style abbreviations map to DST-aware regions, other fixed offsets are rejected. | Quiet-hour rules follow the recipient's location, which we don't know; intersection is the conservative choice. | Fewer usable hours for those leads (e.g. 12:00–20:00 ET for continental US). |
| **Rules first, LLM optional, humans for the rest.** | Deterministic, free, auditable for the common cases; LLM only where language is open-ended; humans where the cost of error is legal. | Review queue workload (see EVALUATION.md). |
| **LLM may only move toward caution.** | Bounds the damage of model error and prompt injection to "a human looks at it". | Some LLM-correct answers still go to review. |
| **Deterministic output guard on LLM text; compliance text appended by code.** | A model must not be able to invent a price, add a link, or drop the opt-out line. | Over-strict guard falls back to the template (safe). |
| **Event in same transaction as state; replay verifier.** | Turns "the audit log is complete" from a hope into a check. | Every new transition must use `set_enrollment_state`/`set_message_status`. |
| **SQLite, one DB per client.** | Zero-ops, file-level tenant isolation, WAL handles a few concurrent workers. | Single-host write throughput ceiling; see BENCHMARKS.md. Postgres is the scale path. |
| **stdlib HTTP server, bound to 127.0.0.1.** | No framework dependency; meant to sit behind a TLS proxy/tunnel. | Not a hardened internet-facing server by itself. |

## Module map

| module | responsibility |
|---|---|
| `models.py` | Campaign config (validated at load), enums for states/labels |
| `normalize.py` | phones (E.164, NANP validation), emails, names (rejects URLs/markup), consent, CSV-safe export |
| `ingest.py` | CSV import: header aliases, encoding/delimiter sniffing, dedupe/merge, monotone consent |
| `store.py` | SQLite schema, transactions, state transitions + events, suppression list |
| `policy.py` | the send gate: suppression, consent, quiet hours, frequency cap, daily cap |
| `compose.py` | template rendering, LLM rewrite, output guard, compliance footers |
| `classify.py` | reply labeling: rule tables, strict gates, injection stripping, LLM second opinion |
| `engine.py` | enroll / plan / approve / dispatch / reconcile / inbound routing / outbox |
| `llm.py` | Anthropic provider (official SDK), cache, budget, fake |
| `channels/` | Twilio SMS, SMTP email, fake channel with fault injection, HTTP transport |
| `server.py`, `webhooks.py` | inbound webhooks (Twilio signature, HMAC with replay window), signed CRM sink |
| `replay.py` | event-log replay verifier and per-lead timeline |
| `simulate.py` | campaign flight simulator with fault injection and invariant checks |
| `evaluate.py` | classifier evaluation against labeled JSONL |
| `cli.py` | operator commands |
