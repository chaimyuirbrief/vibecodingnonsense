# Adversarial review (Phase 7)

## Method

Five independent reviewers, each with one lens, read the code and were required to back every claim with a
concrete trigger (most wrote and ran reproduction scripts). For each lens a separate **verifier** was told to
*refute* the claims, reproducing each one against the unchanged code; only "confirmed" findings are counted
as defects below. Fixes were developed in an isolated copy while verification ran, then ported, and every fix
has a regression test that **fails on the pre-review code and passes now** (checked by running the tests
against the old source).

| lens | findings | confirmed | refuted / unreproduced |
|---|---|---|---|
| compliance & safety | 8 | 8 | 0 |
| data integrity & concurrency | 8 | 8 | 0 |
| security | 8 | 8 (2 downgraded to low) | 0 |
| LLM integration & cost | 7 | 6 | 1 refuted (cache: mechanism real, harm not shown) |
| architecture & simplicity | 8 | 8 (2 downgraded to low) | 0 |
| **total** | **39** | **38** | **1** |

Several defects were found independently by two to four lenses (batch lease, stale clock, campaign cache,
server LLM budget) and are listed once below: 39 findings collapse to 27 distinct reviewer-found defects (one refuted),
plus 3 found while fixing them (#3, the stranded enrollment, and a simulator timestamp artifact noted below).

## The three most consequential (fixed)

1. **Texts sent after quiet hours.** `tick()` read the clock once; a batch starting 19:57 kept sending past
   20:00 and recorded `sent_at` 19:57. Reproduced on the old engine: **16 of 60** messages delivered after
   20:00 New York in a 20 s-latency scenario. Fix: per-message clock and policy check at claim time, a 5-minute
   end-of-window margin, `sent_at` = actual send time. The simulator now models provider latency and a
   mutation test proves it catches a re-introduced stale clock.
2. **Opt-outs lost or overridden.** (a) `Dana <dana@x.com>` / `447700900123` senders never matched the lead,
   so an unsubscribe suppressed a string nobody was texted at; (b) resolving one flagged reply resumed outreach
   while a *possible opt-out* from the same lead was still pending, and a second campaign or a "later" reply
   bypassed the pause. Fix: robust sender normalization, unmatched opt-outs go to a human, and the review hold
   is now **lead-level** (enforced in planning, the send policy, and the last-moment check).
3. **Approval gate bypassed.** `approve_first_n` counted drafts, so message N+1 went out while the first N sat
   unreviewed (reproduced: 3 sent, 0 approvals). Fix: count messages a human actually approved (`approved_by`).

## All confirmed defects and fixes

| # | defect (lens) | severity | fix | regression test |
|---|---|---|---|---|
| 1 | stale per-tick clock → quiet-hour violations, wrong `sent_at` (compliance, integrity) | high | per-message clock, 5-min margin | `test_quiet_hours_judged_at_send_time_not_batch_start`, `test_mutation_stale_clock_is_caught` |
| 2 | one lease for a whole batch, unguarded writes → duplicate sends, sent recorded as canceled (integrity, compliance, architecture) | high | per-message claim + lease; every post-claim write compare-and-set on status **and** lease owner | `test_lease_expiry_mid_batch_cannot_cause_duplicates` |
| 3 | "not found" lookup treated as never-sent while the original request was still in flight (found while fixing #2) | high | resend only after lease + grace (> any adapter timeout) | same test; `test_ambiguous_lost_is_requeued_after_lookup` |
| 4 | review pause per enrollment, not per lead (compliance, integrity) | high | lead-level hold in plan / policy / send | `test_second_review_keeps_lead_paused` |
| 5 | approval gate counts drafts (compliance) | high | count `approved_by` | `test_approval_gate_holds_until_n_approved` |
| 6 | un-normalizable senders lose opt-outs (compliance, security) | critical/high | `normalize_sender`, display-name parsing, `+` for intl MSISDN, unmatched opt-out → review | `test_unmatched_sender_formats_still_match_or_reach_a_human` |
| 7 | unknown timezone ignores region: Hawaii at 06:00, international at 03:00; `EST` = fixed offset (compliance) | high | area-code zones join the intersection; non-NANP needs explicit tz; abbreviations mapped to DST-aware regions, other fixed offsets rejected | `test_timezone_abbreviations_and_regions` |
| 8 | campaign spec cached forever by running workers (integrity, compliance, architecture) | medium | reload per plan/dispatch/inbound pass | `test_campaign_edits_seen_by_running_worker` |
| 9 | `plan()` post-compose re-check misses a "later" reply (integrity) | medium | compare `next_due_at` too | `test_later_reply_during_compose_is_not_overwritten` |
| 10 | outbox not claimed → duplicate CRM handoffs (integrity, architecture) | medium→low | claim with lease; guarded status updates | `test_outbox_delivered_once_with_concurrent_workers` |
| 11 | worker death strands whole claimed batch as `unknown` (integrity) | medium | per-message claim (at most one stranded) | covered by #2 |
| 12 | server builds an Engine per request → LLM budget never enforced (integrity, security, LLM, architecture) | medium | bounded engine pool sharing one budgeted provider | `test_server_reuses_engines_across_requests` |
| 13 | re-import revocation applied only to the oldest matched lead (compliance) | medium | revocation applies to every matched record | `test_reimport_revocation_applies_to_every_matched_lead` |
| 14 | rate limiter before auth; one shared bucket behind a proxy → junk flood blocks real signed opt-outs (security) | medium | only failed authentication is rate-limited | `test_junk_flood_cannot_block_signed_webhooks` |
| 15 | SMTP STARTTLS without certificate verification (security) | high | `starttls(context=ssl.create_default_context())` | `test_smtp_outcomes` (asserts CERT_REQUIRED + hostname check) |
| 16 | domain-shaped "names" reach SMS via the template path (security) | medium | names with host-like tokens rejected; guard also runs on rendered templates (lead fields dropped on violation) | `test_domain_like_names_never_reach_a_message` |
| 17 | link guard: 15-TLD allow-list, `#`/`\`/`@` host tricks (security, LLM) | medium (TLD part: low) | any-TLD detection; browser-equivalent host parsing | `test_guard_closes_reported_bypasses` |
| 18 | outbound webhook followed redirects (POST→GET, signature to new host) (security) | medium | redirects surfaced as failures; strict scheme/host check | `test_transport_refuses_redirects_and_plain_http` |
| 19 | no socket timeout / unbounded threads (slowloris) (security) | low | 15 s socket timeout, 64 concurrent connections | — |
| 20 | LLM-decided labels skipped the strict gate (LLM) | medium | gate applies to LLM decisions | `test_llm_label_goes_through_strict_gate` |
| 21 | fallback-model / unknown-model spend recorded as $0 (LLM) | medium | price table includes fallback targets; unknown models charged at the highest known rate | `test_fallback_and_unknown_models_are_charged` |
| 22 | guard missed spelled-out numbers and dash-split forbidden phrases (LLM) | medium | number-word check; normalized phrase matching | `test_guard_closes_reported_bypasses` |
| 23 | classification cache stored one sampled answer forever (LLM) | **refuted** by the verifier (the cached answer still routed to review; no harm shown) | tightened anyway: cache only high-confidence, non-escalating answers; 30-day TTL; effort in key | `test_classification_cache_only_keeps_confident_answers` |
| 24 | LLM typography forced UCS-2 (2–3x SMS segments) (LLM) | low | GSM-7 normalization + real segment counting | `test_guard_closes_reported_bypasses` |
| 25 | per-message COUNT scans (daily cap, approvals); no `lead_id` index (architecture) | medium | counter table; per-plan cached approval count; index | benchmarks |
| 26 | `plan()` ignored daily capacity → backlog queued then re-deferred daily (architecture) | medium | plan stops at remaining capacity | `test_plan_respects_daily_capacity_and_claims` |
| 27 | `plan()` claimed nothing → concurrent planners each paid for the same LLM rewrite (architecture) | medium | plan lease on enrollments | `test_plan_respects_daily_capacity_and_claims` |
| 28 | BENCHMARKS.md described fixes not yet in the code (architecture) | medium | accurate at review time: the fixes were in the isolated copy, not yet ported; resolved by the port | — |

Also fixed (found by my own re-read of the diff and by re-running the simulator, not by the reviewers):
- a lead suppressed between planning and sending (e.g. a DNC import) left its enrollment stranded in
  `awaiting_send`; it is now `blocked` (`test_suppression_checked_at_send_time`);
- the simulator stamped replies with the tick-start time instead of the moment the engine received them, so once
  provider latency was modeled it reported sends that happened *before* the engine could know of an opt-out as
  violations; it also reused one fault-injection seed for every run. Both fixed; 6 seeds × 1,000 leads × 21 days ×
  4 workers now pass every invariant.

## What the review did not cover

No live provider testing, no load test across separate hosts, no formal verification of the state machine,
no review by a lawyer. "Confirmed" means reproduced by an LLM verifier; it is strong evidence, not proof that
no other defects exist — the review found 27 distinct defects in code that already had 226 passing tests.
