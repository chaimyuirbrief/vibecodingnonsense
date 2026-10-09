# Lazarus — dead-lead reactivation that won't get you sued

Text your old leads ("Hi Dana, it's Mike from Brightside Roofing — still looking to get your roof
replaced?"), sort the replies, hand the warm ones to sales, and **never** text someone who said stop.

Lazarus is a small, durable engine for that job: a SQLite state machine with a deterministic send policy,
a reply classifier that knows when to ask a human, optional Claude assistance that can only make things
*safer*, Twilio/SMTP adapters, signed CRM webhooks, and a simulator that proves its invariants under faults.

> **Not legal advice.** Defaults are conservative relative to common US rules (TCPA calling hours, state
> "mini-TCPA" laws, CTIA opt-out keywords, CAN-SPAM footers), but you are responsible for consent and
> compliance in your jurisdiction. Have counsel review your campaign configuration.

## What it does

- **Import** messy CRM exports: header aliases, encoding/delimiter sniffing, E.164 phone normalization with
  NANP validation, email validation, names sanitized (a "first name" of `http://evil.example` is dropped),
  dedupe/merge where consent only ever moves toward "no". Rejected rows go to a report.
- **Send policy, checked at plan time and again per message at send time** (with that moment's clock):
  suppression list, explicit SMS consent, quiet hours in the lead's timezone with the last 5 minutes of the
  window treated as closed (unknown timezone → the intersection of all configured US zones plus the zone of
  non-continental area codes like 808; international numbers need an explicit timezone), ≥24h between touches
  across all campaigns, an exact daily cap, paused campaigns, and a hold on any lead with an unresolved
  flagged reply.
- **Compose**: templates with safe placeholders; optional LLM personalization whose output must pass a
  deterministic guard (no new links, numbers, prices, guarantees, wrong names; length limits). The
  opt-out line is appended by code, not by a template or model.
- **Approve**: until a human has approved N messages of a campaign, every new one waits; every LLM-written
  message waits by default.
- **Deliver at most once**: per-message leased claims with owner-checked writes, retries with backoff for
  transient errors, suppression on permanent ones, `unknown` (never blind resend) when the outcome is
  ambiguous, provider lookup to reconcile.
- **Handle replies**: opt-out (all CTIA keywords + natural phrasing + Spanish/Portuguese/German/Chinese/…),
  wrong number, auto-reply, later (snooze), interested (hand off), not interested; anything uncertain or
  in an unfamiliar language pauses the lead for a human. Prompt-injection text is stripped and flagged.
- **Hand off** interested leads to any CRM/automation URL with an HMAC-signed, retried webhook.
- **Audit**: every state change is an event; `lazarus replay` rebuilds state from events and diffs it;
  `lazarus timeline <lead>` answers "why did this person get that text?".
- **Simulate**: `lazarus simulate` runs the real engine against a fake clock, a carrier that fails in every
  way (including crashing after the provider accepted a message), duplicate webhooks, and concurrent
  workers — then checks invariants and exits non-zero on any violation.

## Honest status

| works and is tested | built but not live-tested | not built |
|---|---|---|
| engine, policy, import, approvals, reply routing, outbox, replay, simulator, CLI, webhook server | Twilio send (request/response mapping tested with a fake transport; signature check verified against Twilio's official vector), SMTP send (fake SMTP client), Claude calls (real SDK, mocked HTTP) | a web UI, Twilio delivery-status callbacks, CRM-native adapters (use the signed webhook), multi-host deployment |

An independent five-lens adversarial review of the first version produced 39 findings; separate verifiers
reproduced 38 (27 distinct defects after merging duplicates) and refuted 1. All are fixed, nearly all with a
regression test that fails on the old code: see [docs/RED_TEAM.md](docs/RED_TEAM.md).

**Reply classification is the weak point**, and the numbers are in [docs/EVALUATION.md](docs/EVALUATION.md):
rules alone stopped 33/33 and 48/50 opt-outs on two held-out synthetic sets, sending 25–39% of replies to
human review. Run with the review queue on.

## Install

```bash
cd lazarus
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # or '.[llm]' for runtime + Claude, or '.' for rules-only
pytest                           # 251 tests, ~14 s
```

Python ≥ 3.11. Runtime dependency: `pydantic`. Optional: `anthropic` (Claude).

## Quickstart (no credentials needed)

```bash
export LAZARUS_DB=demo.db
NOW=2026-10-12T15:00:00Z                       # pretend it's Monday 11:00 New York
lazarus --now $NOW init
lazarus --now $NOW import examples/leads.csv --report rejected.csv
lazarus --now $NOW campaign add examples/campaign.json
lazarus --now $NOW enroll roof-reactivation
lazarus --now $NOW preview                      # read-only: what would be sent, and why/why not
lazarus --now $NOW tick                         # plans messages (they wait for approval until 5 are approved)
lazarus --now $NOW approvals list
lazarus --now $NOW approvals approve --all
lazarus --now $NOW inbound "+14045552368" "yes how much for metal?" --id SM1   # -> handoff
lazarus --now $NOW inbound "+13125557781" "please stop texting me" --id SM2   # -> suppressed
lazarus report
lazarus replay                                  # event log matches tables?
lazarus simulate --leads 300 --days 21 --workers 4
```

Without `TWILIO_*` set, no channel is configured: messages stay queued (`deferred:no_channel`) — nothing
is sent anywhere.

## Going live

1. Copy `.env.example` to `.env`, fill in Twilio (and optionally SMTP, CRM webhook, Claude) values, load it
   into your environment. Never commit it.
2. `lazarus run --interval 60` (the worker loop; run it under systemd or similar).
3. `lazarus serve` (binds 127.0.0.1:8787). Expose it only through a TLS reverse proxy or a tunnel, set
   `LAZARUS_PUBLIC_URL` to the public base URL, and point the Twilio number's "A message comes in" webhook at
   `$LAZARUS_PUBLIC_URL/webhooks/twilio/sms`. Signatures are verified against that URL.
4. Work the queues daily: `lazarus approvals list`, `lazarus review list`, `lazarus unknown list`.

## CLI reference

| command | what it does |
|---|---|
| `init` | create/migrate the database |
| `import FILE [--report out.csv]` | import leads; write rejected/warning rows to a CSV |
| `campaign add FILE / list / show ID / pause ID / resume ID` | manage campaigns (JSON, validated) |
| `enroll CAMPAIGN [--tag T]` | enroll leads (idempotent) |
| `preview` | read-only: due messages with policy decisions |
| `tick` / `run --interval S` | one engine pass / worker loop |
| `approvals list / approve IDS / approve --all / reject IDS` | approval queue |
| `review list / resolve ID LABEL` | human labels for flagged replies (pauses lift on resolve) |
| `unknown list / sent ID / not-sent ID` | reconcile ambiguous sends after checking the provider |
| `inbound SENDER BODY [--id ID]` | feed a reply by hand |
| `suppress add ADDR / list` | manual do-not-contact |
| `report`, `export [--state S]`, `timeline LEAD`, `replay` | reporting and audit |
| `labels export [--out F]` | human-resolved replies as a PII-scrubbed JSONL eval set (feed it to `eval`) |
| `simulate`, `eval FILE [--llm anthropic]` | simulator; classifier evaluation |
| `serve` | inbound webhook server |

Global: `--db`, `--now ISO` (time travel for testing), `--actor NAME` (recorded in the event log).

## Using Claude (optional)

```bash
pip install -e '.[llm]'
export LAZARUS_LLM=anthropic ANTHROPIC_API_KEY=...   # or an `ant auth login` profile
export LAZARUS_LLM_BUDGET_USD=5                       # hard per-process ceiling
```

Defaults: model `claude-opus-5-5` at `effort: low` (override with `LAZARUS_LLM_MODEL`, e.g. a cheaper
model, if your own eval shows it holds quality), structured outputs, and server-side refusal fallbacks
(`fallbacks: "default"`) enabled. Claude is used for (a) a second opinion on replies and (b) rewriting
steps marked `"personalize": true`. Both can only make outcomes more cautious: see docs/ARCHITECTURE.md.

## Set it up with Claude Code

Paste into a Claude Code session opened in this folder:

````text
Set up Lazarus in this folder on this machine. Read README.md, docs/ARCHITECTURE.md and docs/THREAT_MODEL.md first.

Things you need to know that aren't obvious:
- Never send a real message while setting up. Use --now and `preview`; don't set TWILIO_* until I say so.
- .env holds credentials. Never commit it, never print secrets in full.
- `lazarus serve` must stay bound to 127.0.0.1. If I want Twilio webhooks, set up a TLS reverse proxy or
  tunnel and LAZARUS_PUBLIC_URL; never disable signature checks.
- The quiet hours, frequency cap and consent requirement are compliance controls. Don't loosen them
  unless I explicitly ask and confirm.

Please:
1. Create a venv, install with `pip install -e '.[dev]'`, run `pytest` and `lazarus simulate`.
2. Import my CSV (I'll give the path) with --report, and show me the rejected-row summary.
3. Help me write a campaign JSON for my business; validate it with `lazarus campaign add`.
4. Run `preview` and show me exactly what would be sent to the first 10 leads.
Stop there. I'll review before anything goes live.
````

## Layout

```
src/lazarus/      engine, policy, classifier, composer, store, channels, server, CLI
tests/            251 tests: unit, property-based (Hypothesis), failure injection, simulator mutation tests, red-team regressions
evals/            blind labeled reply sets + results
benchmarks/       throughput benchmark script and results
examples/         campaign.json, leads.csv
docs/             ARCHITECTURE, EVALUATION, THREAT_MODEL, BENCHMARKS, OPPORTUNITIES, ROADMAP, PROGRESS_LOG
```
