# vibecodingnonsense
For other people who want to save time vibecoding and use templates of stuff I had claude code for days

## Templates

| folder | what it is | status |
|---|---|---|
| [`lazarus/`](lazarus/) | **Dead-lead reactivation engine.** Text old leads, sort the replies, hand warm ones to sales, never text anyone who said stop. Durable SQLite state machine, compliance-first send policy, reply classifier with a human review queue, optional Claude assist, Twilio/SMTP, signed CRM webhooks, fault-injecting simulator. | Working and tested (251 tests; independent adversarial review: 38 of 39 findings confirmed and fixed). Twilio/SMTP/Claude adapters built against official specs but not live-tested. Read `lazarus/docs/EVALUATION.md` before trusting the reply classifier unattended. |

Each template has its own README with install steps, a quickstart that needs no credentials, and a
paste-ready prompt for setting it up with Claude Code.
