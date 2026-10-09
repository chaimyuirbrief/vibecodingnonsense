# Threat model

Scope: a small business (or an agency on its behalf) runs Lazarus on one host, sending SMS/email to
its own past leads through Twilio/SMTP, receiving replies by webhook, optionally calling Claude.
This is a design-level model plus the results of an adversarial review; it is not a certification.

## Assets

1. **Recipients' rights and the operator's legal exposure** — consent, opt-outs, quiet hours. The most
   expensive failure is texting someone who said stop (TCPA statutory damages are per message).
2. **Lead PII** — names, phones, emails, notes, reply texts (SQLite file, CRM webhook payloads, LLM prompts).
3. **Credentials** — Twilio auth token, SMTP password, webhook secrets, Anthropic key (environment only).
4. **The sender's reputation** — carrier filtering, 10DLC standing, domain reputation.
5. **Integrity of the record** — the event log is the evidence of what was sent and why.

## Trust boundaries and untrusted inputs

| input | who controls it | where it flows | mitigations |
|---|---|---|---|
| CSV / CRM fields (names, notes, tags) | anyone who filled a web form that fed the CRM | templates, LLM prompts, exports | names must be letters/space/'-. (URLs, digits, braces rejected); placeholders are a closed set; notes reach the LLM only as a JSON string field; CSV exports neutralize formulas |
| Inbound reply text | the recipient (or anyone who knows the number) | classifier, LLM, review queue, CRM payload | rules first; injection sentences stripped + flagged and never sent to the LLM; LLM output is a closed enum and can only increase caution |
| Webhook HTTP requests | the internet | `server.py` | Twilio HMAC-SHA1 signature against the configured public URL; generic endpoint HMAC-SHA256 with a 5-minute timestamp window; 64 KiB body limit; per-IP token bucket; errors don't leak internals; bound to 127.0.0.1 by default |
| LLM output | the model (influenced by the above) | message bodies, labels | output guard: no new links/numbers/forbidden phrases/wrong names, length cap; compliance text added by code; LLM-written messages need approval by default |
| Provider responses | Twilio/SMTP (or a MITM if TLS were off) | message status | HTTPS-only transport (localhost excepted); ambiguous → `unknown`, never resend |

## Threats and controls

| # | threat | control | residual risk |
|---|---|---|---|
| T1 | Text sent after an opt-out | suppression checked at plan and immediately before send; opt-out cancels all open messages in the same transaction; simulator invariant `sent_after_suppression` | race window = the provider call itself (ms); classifier misses (see EVALUATION.md) |
| T2 | Classifier misses a natural-language opt-out | broad rules, strict gates (opt-out cues / unfamiliar language → human), optional LLM second opinion that can only escalate | measured: 2/50 unsafe misses on the hardest held-out set, rules only |
| T3 | Prompt injection via reply or CRM notes steers the LLM | closed-enum outputs, injection stripping, no tools, guard on generated text, approval for LLM text | a manipulated label can at worst route to a human or produce a guarded template-equivalent message |
| T4 | Forged inbound webhook (fake STOP or fake "interested") | signature verification; generic endpoint replay window | a leaked Twilio auth token defeats it — rotate tokens |
| T5 | Duplicate sends from retries/crashes/concurrency | lease + compare-and-set claims under `BEGIN IMMEDIATE`; idempotency key per step generation; ambiguous outcomes never resent; simulator + 6-thread test | an operator marking an `unknown` message "not sent" when it was sent |
| T6 | Quiet-hours violation for leads with unknown/wrong timezone | unknown → intersection of all fallback zones; DST-correct window math (property-tested) | a stored timezone that is wrong (lead moved) |
| T7 | Runaway LLM spend | per-process USD/call ceiling; classification cache; LLM optional | budget is per process, not global across workers |
| T8 | PII leakage | no request logging in the server; PII only to configured sinks; SQLite file permissions are the operator's job | DB file at rest is not encrypted; LLM prompts contain reply text and notes (disable LLM if unacceptable) |
| T9 | Template/config mistakes | campaign validation at load (placeholders, business identification, email postal footer, window sanity); `preview` command | content judgment is still the operator's |
| T10 | Formula injection via exports | `csv_safe` on every exported cell | — |
| T11 | Tampering with history | replay verifier detects state changed without events | an attacker with DB write access can also forge events (no hash chain) |

## Adversarial review

An independent five-lens review (compliance, integrity/concurrency, security, LLM/cost, architecture)
was run against this code, with each finding then reproduced or refuted by a separate verifier.
Outcomes and fixes are recorded in [RED_TEAM.md](RED_TEAM.md).
