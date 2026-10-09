# Opportunity analysis (why this project)

Context at decision time: this repository was empty apart from a README describing it as a collection of
reusable templates. The owner's other public work (a WhatsApp group bot) shows a strong bias toward
operational safety — pacing, audit logs, local-only admin panels. The brief asked to prioritize AI
agents, lead reactivation, CRM automation, business operations, media automation, and tool integrations.

| # | opportunity | problem | value | what incumbents get wrong | buildable here? | riskiest assumption | fastest disproof | reusable? |
|---|---|---|---|---|---|---|---|---|
| 1 | **Dead-lead reactivation engine** | Businesses sit on thousands of old leads; reactivation campaigns ("are you still looking…?") convert but are risky to automate | Direct revenue; a common agency offer | Drip tools blast on a timer, treat replies as a webhook to a human, and leave TCPA/opt-out handling to the operator | Yes, end to end with fakes; live SMS needs Twilio creds | That reply classification can be automated safely | Build a blind labeled set and measure unsafe opt-out misses | Yes — a product or agency template |
| 2 | Durable local-first agent workflow runtime | Agent workflows lose state on crash, double-execute side effects | Infrastructure leverage | Hosted orchestrators are heavy; scripts aren't durable | Yes | That a generic runtime beats a domain-specific state machine | Try expressing #1 on it | Yes, but value comes through an application |
| 3 | Inbound triage / Gmail→CRM connector | Leads arrive by email and get lost | Time savings | Zapier flows don't understand content | Partly (Gmail connector exists; no CRM creds) | That users accept auto-filing | One week of real inbox data | Moderate |
| 4 | Media production pipeline (transcript → clips/chapters/notes) | Repetitive post-production | Time savings | — | Weakly: needs ffmpeg/ASR models and real media | Clip selection quality | Human preference test | Moderate |
| 5 | Claude Code template kit generator | "Vibecoding" templates with CLAUDE.md, hooks, tests | Fits this repo's stated purpose | — | Yes | That templates differentiate | — | Yes, but low moat |
| 6 | WhatsApp Business Cloud API transport for the existing bot | Personal-account automation gets banned | Protects an existing tool | — | Not in this repo's scope; no Meta creds | — | — | Narrow |

**Choice: #1, with #2's ideas (durable state, event log, replay, leases) built in as its core.** It has the
most direct revenue path, the clearest safety problem that existing tools get wrong, and it can be
verified without credentials: a simulator plus a blind evaluation set can show whether it is safe.
The riskiest assumption (automated reply handling) was tested first, and the evidence led to the
human review queue and strict gates rather than a claim of full automation (see EVALUATION.md).
