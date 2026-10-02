# Staff portal: merged spec and hard-won lessons

A design document for the staff side of a small company's web presence: one
application, on its own subdomain, that answers *who works here, what may they
reach, from which devices, and what did they do?* — and that greets everyone
who signs in with a 🔥 streak which never punishes them for a day they could
not have signed in.

Every request is gated before anything is served, stylesheets included.
Signing in takes a password and a real second factor: a passkey, an
authenticator code, a backup code, or — only when nothing better exists — a
code sent by text or email.

It merges two designs, each of which was built and run:

- **A** — a restricted-access portal spec: four gates in a fixed order, a
  fail-open catalogue, tiered grace windows, an audit log that can undo, and
  the arithmetic of a calendar-aware streak window.
- **B** — a staff identity, access and audit build brief: ranked roles, six
  access modes, fingerprinting and risk scoring, a hash-chained audit log,
  protected-period streaks, and the deployment traps.

You never need either source to read this one. Where an idea came from one of
them, a short *Provenance* line at the end of the section says so. Where they
disagreed, the decision is numbered D1–D18 (the numbering `docs/CONTRACTS.md`
uses) and argued in §1. Appendix D maps every source reference that appears in
code comments and in CONTRACTS (`A §14.2`, `B trap 4`, and the older
`SPEC §13.5` form, which uses A's numbering) to the section here.

It is written to be handed to a person or to a coding agent, and it is
deliberately **long on reasoning and short on code**. An agent can write
WebAuthn verification from scratch. It cannot cheaply rediscover that
`Date.parse('42')` returns the year 2042 and will hold a front door open for
sixteen years, or that Cloudflare refuses PBKDF2 above 100,000 iterations in
production while `wrangler dev` runs 210,000 without complaint.

`docs/CONTRACTS.md` is the binding reference for exact module exports, routes,
response shapes and setting values. This document says *why*; that one says
*exactly what*. If they disagree, one of them is a bug: fix whichever is wrong
and keep them in step.

Built on Cloudflare Workers, D1 and Workers Assets, with no framework, no build
step and no runtime dependencies. Nothing here is Cloudflare-specific in
spirit.

---

## 0. How to use this document

Read in this order:

1. **§1 Decisions** — the questions to answer before any code, with this
   design's answers. They change what gets built.
2. **§16 The fail-open catalogue** — the highest-value section. Every entry is
   a real bug that shipped or was caught on the way out, read as correct code,
   and made the system less safe or locked somebody out.
3. **§15 Testing** — the methodology that found most of §16.
4. **§10 The streak** — the feature people see every day, and the best worked
   example in the document of getting a calendar right.
5. **§17 Build order** — the sequence, in which each step leaves something
   usable and testable.
6. Everything else as you reach it. **§13 Operating it** is the section people
   skip and then regret: migrations, secret rotation, retention, and why the
   page is blank.

If you only have patience for two sections, read §16 and §15.

**Scope.** A handful to a few hundred trusted people: a company's staff, a
back office, an operations console. There is no self-service sign-up, no
email verification and no password reset by email. Accounts are created by an
administrator and claimed through a one-time invitation link. That single
assumption simplifies enormously; do not quietly abandon it.

**One company's front door, not an identity product.** That is why it can make
opinionated choices a product could not: one bootstrap owner, one time zone
for the whole portal, soft deletes only, policy as a table of settings rather
than a policy language, and no federation. If you need SSO, SCIM or tenants,
this is the wrong starting point (Appendix C).

**Words used throughout.**

| Term | Meaning |
|---|---|
| *trusted* | the request comes from an allowlisted address **or** an approved device |
| *open* | the time-boxed "open to the internet" switch is on (§8.8) |
| *nothing* | the zero-information refusal: an empty 403 or a decoy 404 (§3.3) |
| *Super Admin* | the owner role; holds `*`, including the reserved capabilities (§5.3) |
| *protected day* | a local calendar day on which nobody is expected to sign in (§10.5) |
| *pinned* | a session that may reach only one task — change a password, or enrol a factor — until it is done (§7.8) |
| `rc` | the per-request context every domain function receives: request, env, clock, address, policy, device, session |

---

## 1. Decisions to make before code

Answer these with whoever owns the system before the first line is written;
each one changes what gets built. The answers given are this design's.

### 1.1 What does an unauthorised visitor see?

A login page, a 403 with text, or nothing at all. **Nothing** is the strongest,
and this design takes it: a visitor the gate refuses gets either an empty 403
(the default) or a decoy 404 that looks like a stock server page — the setting
`deny_style` (D2). Both carry zero information; the decoy also declines to
advertise that anything is here at all. The cost is operational: one day you
will stare at a blank page and have to remember why (§13.5). Choose
deliberately and write it down.

### 1.2 Who is allowed to be locked out?

Every security control is also a lockout risk. This design answers: **never
the last Super Admin, and never anyone through a setting they have just
changed.** Several guards exist only to prevent a self-inflicted lockout
(§12), and they add real complexity. The same principle decides the
second-factor policy (D7): someone with no factor enrolled is pinned to the
enrolment page, never refused a session, because refusing the session makes
the requirement impossible to satisfy — starting with the owner.

If you would rather keep a manual database recovery path and drop the guards,
you can. Decide; don't drift.

### 1.3 Is a phone number a fallback or a requirement?

Texted codes cost money, fail abroad and without signal, and are the weakest
factor on offer. They are also the only factor that works for someone who has
just lost their phone. Here, codes — by text **or** email — are a **fallback**
(D8). They go only to destinations an administrator has added, and they are
sent automatically only when a code is the *only* method an account has.
Someone with a passkey or an authenticator never receives one.

### 1.4 Where do you trade security for the people using it?

Concretely: may a trusted office network skip the second factor for a week?
This design says yes — per account and per device, time-boxed, and scaled to
how trusted the network is (§8.9, D9, on by default). It also softens account
lockout so that a stranger cannot lock a colleague out of their own laptop
(D6, §6.4). Everywhere else it fails closed. If your answer is no, turn
`mfa_grace` off and every sign-in costs a factor.

### 1.5 What does your calendar look like?

It matters to anything that measures "did they come back in time" — here, the
streak (§10). If your people cannot use a computer on certain days — a weekly
sabbath, multi-day religious festivals, a plant shutdown — that measure must
know, or it punishes them for observing it. The default is Shabbos plus
diaspora Yom Tov, computed arithmetically, and the calendar is a swappable
function (D12, §10.14).

### 1.6 How closely do you watch visitors?

Closely, and openly. Every visitor is fingerprinted from the edge and from the
browser, and scored for risk with a plain-English reason for every point
(D14, §9). The score feeds the gate and the console. The device someone signs
in on is still identified by a signed cookie, never by its fingerprint.
Fingerprints are personal data in several jurisdictions, so a notice saying so
is on by default (§9.5).

### 1.7 What can an administrator take back?

Everything that changed state and can meaningfully be put back is recorded
with an undo snapshot at the moment it happens, from one catalogue that is
also the list of things a revert knows how to do (D10, §11). A revert is a new
audit row, re-runs every guard the original action ran, and is reserved to
Super Admins.

### 1.8 How do people arrive and leave?

By an invitation link, created by someone allowed to invite, and emailed as
well if a mail provider is configured (D11, §6.7). In `request_access` mode a
stranger may ask for an invitation (§6.8). Leaving is **disable**, never
delete (D17): the record of what someone did outlives their account.

### 1.9 How exposed is the site?

One setting with six modes, from fully public to fully locked down, changed
without a deploy (D3, §3.2). The default is `allowlist`: known networks and
approved devices see the portal; everybody else sees nothing.

### 1.10 The reconciliation in one table

Where the sources disagreed, or each covered only part of the ground:

| # | Topic | A said | B said | This design | § |
|---|---|---|---|---|---|
| D1 | Content Security Policy | `script-src 'unsafe-inline'`, single-file pages | `script-src 'self'`, build DOM nodes | **B.** No inline script or style anywhere; one module script per page | 3.4 |
| D2 | Refusal | empty 403 | decoy 404 | either, via `deny_style`; empty by default | 3.3 |
| D3 | Gate model | network → device → password → factor | six access modes | B's modes; A's allowlist is the default mode, A's open switch is `gate_open`, A's device gate is `device_gating` | 3 |
| D4 | Authority | superadmin/admin/user and non-grantable capabilities | six ranked roles, rank guards, dangerous permissions | B's ranks plus A's non-grantable set as **reserved** permissions; Super Admins are peers | 5 |
| D5 | Password KDF | PBKDF2, 100k iterations | chained rounds above 100k | chained PBKDF2-SHA256, frozen 100k chunk, 600k by default, count stored per row | 6.1 |
| D6 | Lockout | rate limits only; lockout is a denial-of-service vector | lock for N minutes | both: per-IP limit never cleared on success; 15-minute lock after 10 failures, which a device that has signed in to that account before bypasses | 6.4 |
| D7 | No factor enrolled | prompt, never wall in | forced enrolment in a pinned session | `mfa_policy` `prompt` (default) or `required`; neither ever refuses the session | 7.8 |
| D8 | Second factors | passkey, TOTP, backup code, SMS fallback | adds email codes | passkey > TOTP > backup code > emailed or texted code; codes auto-sent only when the only method | 7.1 |
| D9 | How often a factor is asked | tiered grace windows | — | A's tiers, `mfa_grace` on by default | 8.9 |
| D10 | Audit | undo snapshots, one catalogue of reverters | hash chain, scrubbing, real errors, revert as a new row | both; "reverted" is derived, so the chain never breaks; undo data never leaves the server | 11 |
| D11 | Invitations | no email of any kind | invitations by email | links an admin copies; email too if configured; accepting approves the device | 6.7 |
| D12 | Streak model | 30 h, +24 h per consecutive blocked day, iterate, cap 4 | rolling window, protected time added back, merged blocks, re-entry grace | one algorithm: A's day-counting fixed point, B's merged blocks and re-entry grace, a hard cap, A's read-without-rewriting | 10 |
| D13 | Window anchor | "within 30 hours", plus a claim about calendar days | rolling window | the window runs from the **most recent** sign-in; A's calendar-day claim is false, so the dashboard always shows the exact deadline | 10.4 |
| D14 | Fingerprints | a device is not a fingerprint; inventory only | full fingerprint and risk score | both: the cookie identifies, the fingerprint informs | 9 |
| D15 | Bootstrap | key-gated; allowlist the caller | also approve the device; one-shot claim that expires | both | 6.6 |
| D16 | Session ids | — | — | the cookie holds a random token; the database stores its SHA-256 | 6.9 |
| D17 | Removing people | `users.delete` | soft delete only | disable only; no hard delete anywhere | 5.6 |
| D18 | Retention | the audit log grows forever, page it | trim everything that grows | audit never trimmed; everything else trimmed by the write that creates it | 13.4 |

*Provenance: questions 1.1–1.5 are A §1; 1.6–1.9 make explicit the choices B
took without asking; the table is CONTRACTS §1.*

---

## 2. What it is

### 2.1 Six jobs

1. **Identity** — accounts, roles, permissions, joiners and leavers, employee
   numbers, a staff directory (§4, §5).
2. **Authentication** — a password and a real second factor; sessions; a fresh
   second check before anything dangerous (§6, §7).
3. **Device trust** — which browsers are known and approved, an approval
   queue, and how often each must prove a factor (§8).
4. **Visibility** — a fingerprint and risk score for every visitor, and a
   tamper-evident audit log of every action (§9, §11).
5. **Exposure control** — one setting that moves the site between fully
   public and fully locked down without a deploy, and a time-boxed switch to
   open it to everyone (§3, §8.8).
6. **Engagement** — the 🔥 streak: consecutive days signed in, counted fairly
   around the days nobody can sign in (§10).

The sixth looks like the odd one out. In the product it is not: it leads the
dashboard and it is the reason people open the portal on a day they have
nothing else to do there. In the engineering it is decoration, in one precise
sense — it must never be able to stop anyone signing in (§10.16).

### 2.2 The stack

A **Cloudflare Worker** with **D1** (SQLite) and **Workers Assets**:

- No server to patch, no container, no database to keep warm.
- The edge already knows each visitor's country, network (ASN and
  organisation), TLS version and cipher, HTTP protocol and bot score — the
  signals §9 wants — at no cost.
- D1 is SQLite, so the schema is ordinary SQL, and the tests run the worker's
  real schema and real queries against `node:sqlite` (§15.1).
- Assets are served with **`run_worker_first: true`**. Every request, including
  `/css/app.css`, reaches the worker before any file is served. Without it,
  Assets answers a request for an existing file before the worker runs, the
  gate never sees it, and a refused visitor can read the admin console's
  JavaScript and with it the whole API surface. `html_handling` and
  `not_found_handling` are both `"none"`, so Assets never rewrites a path or
  invents a page: the worker fetches each HTML file from the binding by name,
  and a direct request for `/something.html` is a 404.

**Zero runtime dependencies.** Chained PBKDF2, signed tokens, AES-GCM, TOTP,
the QR encoder, CBOR, DER, COSE, WebAuthn verification, the Hebrew calendar
and the audit hash chain are all written against WebCrypto, `Intl` and
`fetch`. For an authentication system this is a feature: no supply-chain
surface, nothing to upgrade at 2am, and every line of crypto-adjacent code in
one repository where the tests can reach it. It is the part to write most
carefully and to test hardest.

Development dependencies exist only for checking: **esbuild** (the bundle
check, §15.6), **wrangler**, and **jsqr**, an independent QR decoder, so the
tests read the codes the encoder draws instead of trusting the encoder's own
account of them (§15.8).

The same shape runs on any edge runtime with a SQL store and WebCrypto, and on
plain Node with SQLite. The Cloudflare-specific parts are `request.cf`, the
`CF-Connecting-IP` header (which the edge overwrites, so a client cannot
choose its own address), and the D1 and Assets bindings.

### 2.3 Layout

The portal lives in **its own directory**, with its own config, lockfile,
worker name and database, even inside a repository that also holds the
marketing site (§14.1):

```
staff-portal/
  wrangler.jsonc          own worker, own D1, own assets (run_worker_first)
  package.json            own lockfile
  worker.js               pipeline: healthz → secrets → gate → session → routes → headers
  src/
    util.js crypto.js     total coercion, bytes, cookies; PBKDF2 chain, tokens, AES-GCM
    schema.js             DDL, append-only migrations, role seeding
    catalog.js rbac.js    permission catalogue and roles; effective permissions and guards
    policy.js             settings registry: defaults and restrictive readings
    audit.js undo.js      hash-chained audit log; the undo catalogue
    reverters.js          REVERTERS — one object, keys equal to the undo catalogue
    ratelimit.js          attempt counting
    ip.js network.js      address parsing, CIDR; allowlist, blocklist, tiers
    devices.js grace.js   device cookie, inventory, approval; grace windows
    fingerprint.js gate.js  edge and browser signals, risk; the per-request access decision
    sessions.js users.js invitations.js
    mfa/  webauthn/       TOTP, backup codes, sent codes, factors; CBOR, DER, COSE, passkeys
    calendar/ streak.js   Hebrew calendar, protected days; the streak engine
    signin.js             completeSignIn — the one tail every sign-in shares
    guards.js             self-lockout guards
    api/                  public, auth, me, admin, admin-security
  public/                 one HTML file per page, /css/app.css, /js/<page>.js
  tests/                  unit, e2e (drives worker.fetch), pages (DOM stub), helpers
  docs/CONTRACTS.md       exact exports, routes, shapes, settings
```

*Provenance: the jobs and the stack are B §1–§2; "four gates before anything
is served" and the zero-dependency single-file stance are A's preamble;
engagement as a sixth job is this merge.*

---

## 3. The shape

### 3.1 The order of decisions

Each step fully decides before the next one runs. The order is not arbitrary.

```
request
  │
  ├─ /healthz ─────────────────────────────────────────► 200 "ok"  (before everything)
  ├─ SESSION_SECRET or DATA_KEY missing ───────────────► empty 503
  ▼
STEP 1  HARD BLOCKS
        blocked device · no usable address · blocklisted address ──────► nothing
  ▼
STEP 2  EDGE RULES                                (skipped for an allowlisted address)
        country · Tor · datacenter network · automation · risk ≥ threshold ► nothing
  ▼
STEP 3  NO ACCOUNTS YET ──────────────────────────────────────────► setup page only
  ▼
STEP 4  ACCESS MODE  (§3.2) ──────────────────► everything · a shell page · nothing
  ▼
STEP 5  DEVICE GATING  (optional) ──────────► unapproved device: the pending page
  ▼
        a write whose Origin is not ours ─────────────────────────────► empty 403
  ▼
GATE    PASSWORD       rate limit charged first · one reply for every failure
  ▼
GATE    SECOND FACTOR  the strongest method the account has · or a live grace
                       window · or nothing enrolled → signed in, prompted or pinned
  ▼
completeSignIn ──► session · device cookie · grace window · audit row · streak
```

Why this order:

- **Hard blocks first.** A device an administrator blocked, an address on the
  blocklist, or a request with no address the worker can parse must lose in
  every mode, including `public`. Nothing later may override them.
- **Edge rules before the mode, but not for an allowlisted address.** Country
  rules, Tor and datacenter blocking, automation tells and the risk cut-off are
  heuristics; an allowlist entry is an administrator's explicit statement
  about a network. The office VPN that exits in a country you block for
  everyone else, or a branch office behind a hosting provider's ASN, must
  still get in. (This makes the self-lockout guards appear not to fire when
  you test them from an allowlisted address — correct behaviour, §12.)
- **Setup before the mode.** With no accounts, nothing later can succeed, so
  the only thing worth showing is the setup page — and only that (§6.6).
- **The network before the password.** Someone who has stolen a password still
  sees an empty response from anywhere the portal does not trust. The login
  page is not an oracle for "an admin portal runs on this host".
- **Device gating after the mode.** The pending page has to be reachable to be
  useful, and it covers the API too, so an unapproved device cannot call the
  endpoint that would approve it.
- **The password before the account's status.** A suspended or disabled
  account must be indistinguishable from a wrong password to anyone who does
  not already hold the password. Check status *after* verifying it.
- **The rate limit before the password check.** Charge the attempt, then
  verify, so that a correct guess costs exactly what a wrong one does and
  knowing the password does not buy unlimited attempts at the factor behind
  it.

### 3.2 Access modes

One setting, `access_mode`, moves the whole site. *Trusted* means an
allowlisted address or an approved device; *open* means the time-boxed "open
to the internet" switch is on (§8.8), which never applies in `lockdown`.

| Mode | Trusted, or open | Holds a valid invitation link | Anyone else |
|---|---|---|---|
| `public` | everything | everything | the sign-in page (still fingerprinted and logged) |
| `fingerprint_gate` | trusted: everything (the open switch lifts the *network* rule, not the fingerprint requirement) | as anyone else, until the browser has reported a fingerprint | the sign-in page, which must report a browser fingerprint scoring under the risk threshold before a password is accepted; after that, everything |
| `request_access` | everything | the invitation page | a request-access form (§6.8) |
| `allowlist` *(default)* | everything | the invitation page | nothing |
| `invite_only` | an **approved device** (an allowlisted address alone is not enough), or open: everything | the invitation page | an allowlisted address: the device-approval page only; anywhere else: nothing |
| `lockdown` | an allowlisted address **and** an approved device, and only a Super Admin can sign in | nothing | nothing |

Two notes on the table. `allowlist` trusts the network; `invite_only` does
not. Under `invite_only` you are in because you were invited (accepting an
invitation approves the device you accepted it on) or because a device was
approved for you — an unknown laptop on the office network can queue for
approval and read its code to an administrator, but never sees the sign-in
page. And `lockdown` is enforced twice: at the gate, and again when a
session is loaded, so a non-Super-Admin session that was open when lockdown
began stops working on its next request.

An unrecognised stored value for `access_mode` reads as `lockdown`. That is
§16.2 applied to the most consequential setting in the system.

### 3.3 Refusing, and the shells

A refused request gets **nothing**: an empty 403 by default, or with
`deny_style: decoy` a 404 that imitates a stock web server's. Every refusal is
recorded in the visit log with a machine reason (`not_allowlisted`,
`country`, `tor`, `risk`, …) so an administrator can answer "was it me?"
(§13.5).

Between "everything" and "nothing" the gate can allow a **shell**: an exact
list of pages, assets and API routes that let a stranger do one thing. Because
assets go through the worker, a shell must name every script its page loads;
leave one out and the page silently fails to load it.

| Shell | When | Pages | API |
|---|---|---|---|
| `setup` | no accounts exist | `/`, `/setup` | setup status, `POST /api/setup` |
| `request` | `request_access`, untrusted | `/`, `/request-access` | `POST /api/access-request`, `POST /api/fp` |
| `login` | `fingerprint_gate`, no valid fingerprint yet | `/`, `/login` | `POST /api/fp`, `GET /api/auth/whoami`, and the sign-in POSTs — the login API itself answers `403 { fingerprint_required }` until a fingerprint is on file |
| `invite` | a valid invitation pass cookie | `/invite` | invitation lookup and accept, `POST /api/fp` |
| `pending` | device gating with an unapproved device, or `invite_only` on an allowlisted address with an unapproved device | any navigation shows `/pending` | device status, `GET /api/diag` |

Every shell also allows `/healthz`, the stylesheet, the shared script and the
icon. The exact paths are in CONTRACTS §7.8.

### 3.4 Response hardening

Applied to **every** response, including the empty ones:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self';
  form-action 'self'; base-uri 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(),
  publickey-credentials-get=(self), publickey-credentials-create=(self)
Strict-Transport-Security: max-age=63072000; includeSubDomains
Cache-Control: no-store, no-cache, must-revalidate, private
```

**The CSP decision (D1).** A built single-file pages with inline `<script>` and
therefore needed `script-src 'unsafe-inline'`, and said honestly what that
costs: with `'unsafe-inline'`, the policy provides essentially no protection
against an injected inline script. What it still bought — no external script,
no off-origin `fetch` or form post, no framing, no `<base>` hijack — is real
but narrow.

This portal cannot accept that, because its screens are mostly *displays of
hostile input*. The visitor console shows user-agent strings, ASN organisation
names and client-reported fingerprint fields; the requests queue shows
whatever a stranger typed into the access-request form; device labels,
invitation emails and audit details all carry text someone else chose. So the
merged design takes B's policy: **`script-src 'self'` and no `'unsafe-inline'`
anywhere.** Each page is one HTML file plus one module script from `/js/`.
Scripts build DOM nodes and set `textContent`; nothing assigns `innerHTML`,
`outerHTML` or `insertAdjacentHTML`, nothing uses an inline `on…=` handler,
and nothing carries a `style=""` attribute. With no inline script permitted
and no way for a visitor to put a file on this origin, an injected string has
no path to becoming code. Building DOM nodes is the primary defence;
the CSP is the backstop that makes a slip survivable.

The honest costs:

- **A page is no longer one file.** It is an HTML file and a script, and the
  gate's shells must list both (§3.3).
- **Every page needs a small DOM kit** — a `h(tag, attrs, ...children)` helper
  that sets attributes and text only and turns `on…` attributes into
  listeners — and nobody may take the shortcut of assigning a string.
- **No CDN, web font, icon set or QR service, ever.** `default-src 'none'`
  with `connect-src 'self'` means a page cannot load one external byte. Your
  agent will reach for a CDN `<script>` tag; the page will silently fail. That
  is also why the QR code is drawn by our own encoder (§7.4) and why the
  WebRTC fingerprint probe can gather only host candidates, with no STUN
  server.
- **What it still does not stop.** CSP has no shipped `navigate-to`, so if
  script ever does run it can carry data out in a top-level navigation. The
  defence against that is upstream: never build markup from strings.

**Cross-site writes.** Every non-GET request must carry an `Origin` equal to
the configured `ORIGIN` (or, with no `Origin`, `Sec-Fetch-Site:
same-origin`), or it gets an empty 403. JSON bodies are read only with an
`application/json` content type, which a cross-site form cannot send without a
preflight. Cookies are `SameSite=Lax`, `Secure`, `HttpOnly` and use the
`__Host-` prefix, so a sibling subdomain — the marketing site on the parent
domain — cannot plant or overwrite one.

### 3.5 Pages and browser code

No framework and no build step for the browser either. Each page is one HTML
file in `public/`, loading `/css/app.css` and one module script,
`/js/<page>.js`. For a portal this size that is a feature: no toolchain to rot,
and every page readable in one sitting.

- **A shared kit** (`/js/common.js`): `h(tag, attrs, ...children)`, which sets
  attributes and text only; `api(method, path, body)`, which speaks JSON to the
  same origin and throws a typed error; date formatting; `safeNext(url)`, the
  one open-redirect check (§7.10); the step-up dialog that satisfies
  `step_up_required` and retries (§7.9); toasts and error display.
- **Passkey glue** (`/js/webauthn.js`): feature detection, and base64url to
  `ArrayBuffer` and back in both directions (§7.7). A cancelled dialog comes
  back as `{ cancelled: true }`, not as an exception.
- **The fingerprint probe** (`/js/fp.js`): never throws, every probe trapped,
  one overall deadline (§9.2).
- **Dark mode** follows `prefers-color-scheme`, with every colour a token on
  `:root` redefined under the media query, and no in-app toggle — the system
  preference is the whole story. The QR code keeps its own white plate
  regardless (§7.4).
- **System fonts**, Unicode symbols and inline SVG. No web fonts or icon sets:
  the CSP forbids them, and each would tell a third party who visits the
  portal and when.
- **Never echo a session id into a page**, diagnostic pages included.

*Provenance: gate order and its reasons, and the header set, are A §2; access
modes, hard blocks, edge rules and the decoy are B §6; the shells, the merged
CSP (D1) and the `__Host-` cookies are this design; the page notes are A §12
adapted to D1.*

---

## 4. Data model

Twenty-five tables in SQLite types. The DDL, with a comment on every table
that carries a design decision, is `src/schema.js`; this section is the map.

| Group | Table | Holds | The decision it carries |
|---|---|---|---|
| Config | `settings` | every policy knob, key → string | read only through the settings registry, which gives each key a default for *absent* and a restrictive reading for *unrecognised* (§8, §16.1) |
| | `meta` | schema version, the bootstrap claim, the employee-number high-water mark | small singletons that must survive deletes |
| Identity | `users` | email (unique, lowercased), optional username, name, employee number, title, department, manager, phone; password hash, salt, algorithm and iteration count; status; role; per-user grants and denies; second-factor policy; failed-login count and lock; timestamps | iteration count stored **per row**, so the work factor can rise without invalidating anyone (§6.1); no hard delete (D17) |
| | `roles` | key, name, rank, permissions (JSON), whether it is a system role | rank is the authority model (§5) |
| | `user_roles` | extra role grants with an optional expiry | "admin for a week" that lapses on its own |
| | `invitations` | SHA-256 of the token, the invited user, role, expiry, used/revoked | the token itself is never stored (§6.7) |
| | `access_requests` | what a stranger asked for, with address, country, visitor id and risk | evidence for whoever approves it (§6.8) |
| Sessions and devices | `sessions` | **SHA-256 of the cookie token** as id; user; device; idle and absolute expiry; assurance level; when and how a factor was last proved; pin; revocation | a database leak is not a session leak (D16) |
| | `devices` | random id, status `pending`/`approved`/`blocked`, label, user agent, first and last address, visitor id, who approved or blocked it | identity is the signed cookie, never a fingerprint (§8.1) |
| | `device_users` | which accounts have signed in on which device, how often | the ledger behind the lockout bypass (§6.4) and "approve my phone from my laptop" |
| Network | `allowed_ips` | address or CIDR, tier 1–4, label, owner, user, expiry | expired rows are kept and excluded by queries (§8.7) |
| | `blocked_ips` | address or CIDR, reason, optional expiry | a hard block at step 1 |
| | `mfa_grace` | per account **and** per device: tier, when verified, when it expires | a browser that never proved a factor gets no grace (§8.9) |
| Second factors | `user_totp` | encrypted secret, `confirmed_at`, last spent counter | unconfirmed rows cannot sign anyone in; the counter is a replay floor (§7.4) |
| | `user_passkeys` | credential id, public key (JWK), algorithm, signature counter, AAGUID, transports, label | the stored key is re-validated on every use (§7.7) |
| | `backup_codes` | salted hash per code, iteration count, used | one salt per set (§7.5) |
| | `webauthn_challenges` | challenge, user, kind, expiry | single use by deletion (§7.7) |
| | `code_destinations` | where a texted or emailed code may go, primary flag, who added it | adding one is handing out a factor (§7.6) |
| | `otp_challenges` | hashed six-digit code, destination, attempts, expiry, used | |
| Defence | `auth_attempts` | one row per attempt: kind, subject, time | counted in a window; pruned by the write that creates it (§6.4) |
| Visibility | `fingerprints` | one row per distinct fingerprint hash: visitor id, hits, risk, flags, signals | keyed by a hash of client-chosen input, so trimmed by time **and** count (§16.34) |
| | `visits` | append-only hit log with the gate's decision and reason | |
| | `audit_log` | the hash-chained record of every action, with undo snapshots | never updated, never trimmed (§11) |
| Engagement | `streaks` | per person: current, longest, total days, started day, **last counted local day**, **last sign-in instant** | the window runs from the last sign-in; a day counts once (§10.3) |
| | `streak_days` | one row per counted local day | the history strip, and the evidence when someone asks why their streak reset |

Rules that apply to every table:

- **Every stored time is ISO 8601 UTC**, produced by one function from one
  clock (`util.iso(util.now(env))`). Render in the portal's time zone; never
  store a local time. The streak's day columns are the one exception, and they
  are dates (`YYYY-MM-DD` in the portal zone), not times.
- **A JSON column is read with a reader that distinguishes "absent" from
  "present but unreadable"**, and each caller decides what unreadable means —
  always the restrictive reading (§16.3).
- **Nothing that records what a person did is ever hard-deleted.** Sessions,
  challenges, rate-limit rows, visits and stale fingerprints are trimmed (§13.4);
  people are disabled.

*Provenance: A §3's generic sketch merged with B §3's twenty-ish tables; code
destinations and the streak day log are additions of this design.*

---

## 5. Roles, ranks, permissions and guards

### 5.1 Ranks

Six seeded roles. **Rank is the whole authority model**: you act only on people
ranked below you, and you assign only roles ranked below your own.

| Role | Rank | Holds |
|---|---:|---|
| Super Admin | 100 | `*` — everything, including the reserved capabilities |
| Administrator | 80 | every grantable permission: day-to-day operations. Not role editing, security policy, opening the gate, password resets, code destinations or audit revert |
| Auditor | 60 | read-only everywhere, including the audit log and its verification |
| Manager | 50 | the directory, their own reports (status, sign-ins, streaks), invitations |
| Employee | 20 | their own profile, factors, sessions, devices and streak |
| Guest | 10 | signed in, little else |

System roles are **code**: they are re-seeded from `catalog.js` on every cold
start, so a release that changes what Administrator holds takes effect
everywhere, and an edit to a system role made directly in the database is
overwritten. Variations belong in custom roles, which only a Super Admin can
create (`roles.manage` is reserved) and which can never hold `*` or a reserved
permission, and whose rank is capped below 100.

### 5.2 The catalogue

Permissions are data — dotted keys in one catalogue — never scattered
`if (role === 'admin')` checks. *Danger* means a write demands a fresh second
factor (§7.9). *Reserved* means it can never be granted, by role or by flag.

| Group | Permission | Danger | Reserved |
|---|---|:-:|:-:|
| People | `directory.view` — the staff directory | | |
| | `team.view` — your direct reports' status, sign-ins and streaks | | |
| | `users.view` — every account, with status and security posture | | |
| | `users.invite` — invite people with a one-time link | | |
| | `users.edit` — profile fields | | |
| | `users.suspend` — suspend and reinstate, force sign-out, revoke devices | ● | |
| | `users.disable` — disable leavers and re-enable them | ● | |
| | `users.roles` — roles, temporary roles, per-user grants | ● | |
| | `users.reset_mfa` — clear factors after a lost phone | ● | |
| | `users.reset_password` — reset someone else's password | ● | ● |
| | `destinations.manage` — which numbers and addresses receive sign-in codes | ● | ● |
| | `requests.manage` — approve or deny access requests | | |
| Roles | `roles.view` | | |
| | `roles.manage` — create, edit, delete custom roles | ● | ● |
| Devices | `devices.view` | | |
| | `devices.approve` | ● | |
| | `devices.manage` — rename, block, revoke | ● | |
| Network | `network.view` | | |
| | `network.manage` — allowlist and blocklist | ● | |
| | `visitors.view` — fingerprints, risk scores, the visit log | | |
| Sessions | `sessions.view` | | |
| | `sessions.revoke` | ● | |
| Settings | `settings.view` | | |
| | `settings.manage` — time zone, device gating, session lengths, streak calendar | ● | |
| | `security.manage` — access mode, country/ASN/Tor/automation rules, risk threshold, second-factor policy | ● | ● |
| | `gate.open` — open the portal to the internet for a bounded time | ● | ● |
| Audit | `audit.view`, `audit.verify` | | |
| | `audit.revert` | ● | ● |
| Streaks | `streaks.view_all` — everyone's streaks | | |
| | `streaks.manage` — restore or adjust a streak | ● | |

### 5.3 Reserved capabilities

Six capabilities are **absent from everything grantable**. They come only from
the Super Admin's `*`. Each one is a path by which an administrator could mint
a second, more powerful login, take the outer wall down, or rewrite history:

| Reserved | Why nobody else may hold it |
|---|---|
| `users.reset_password` | set someone's password and you can sign in as them |
| `destinations.manage` | add your own phone to someone's account and you hold their second factor; adding a destination is handing out a factor, not editing a contact detail |
| `roles.manage` | edit a role and you have granted yourself whatever it holds |
| `security.manage` | the access mode and the edge rules decide who reaches the portal at all |
| `gate.open` | takes the outer wall down for everyone at once |
| `audit.revert` | puts prior state back — including roles and grants — and is the one action that can undo a demotion (§16.20) |

The interface **hides** a control the caller cannot use rather than offering a
button that will be refused, and shows *where* each permission came from —
`account` (the Super Admin's implicit set), `role`, `temp_role` or `flag` — so
a checkbox never lies about being editable.

### 5.4 Effective permissions

A person's permissions are their role's, plus any unexpired temporary role's,
plus their per-user grants, **minus their per-user denies — denies beat grants
from every source**. Rank is the highest of their role and their unexpired
temporary roles.

Every input is read failing closed:

- `*` is honoured **only** on the seeded system `super_admin` role. A custom
  role whose stored permissions somehow contain `*` gets nothing from it.
- A custom role's stored rank above 99 reads as 0, not as owner-equivalent.
- An unreadable grants list grants nothing. An unreadable **denies** list
  denies **everything** — a deny list we cannot read might have been the only
  thing standing between this account and a permission.
- A temporary role whose expiry cannot be read has expired.
- Reserved keys found in grants or in a custom role are ignored on read and
  refused on write.

### 5.5 The guards

None of these is optional. Each closes a real escalation path, and each lives
in one function that every caller — the API handler **and** the reverter
(§11.4) — uses.

1. **Rank.** You may act only on someone of *strictly lower* rank. Acting on
   yourself is refused except on the self-service routes that explicitly allow
   it. So you cannot suspend, disable, sign out or demote yourself.
2. **Super Admins are peers (D4).** B's strict rule — equal rank cannot act on
   equal rank — would mean a Super Admin could never remove a second Super
   Admin who has left, or whose account is compromised, without database
   surgery. So two Super Admins may act on each other, and the last-superuser
   guard stops them removing the final one. The cost, stated plainly: a
   compromised Super Admin can demote the others. A compromised Super Admin can
   already do everything else; the audit trail and backups (§13.8) are the
   recovery.
3. **No minting authority.** You may assign only a role ranked below your own
   (a Super Admin may assign any), never a role that holds `*` unless you are a
   Super Admin, and never a role carrying a permission you do not hold yourself.
   You may grant only permissions you hold, never a reserved one. A role
   change is checked against the target's rank before *and* the role's rank
   after.
4. **The last Super Admin is immovable.** Demoting, suspending, disabling and
   reassigning all consult one guard that refuses if the change would leave no
   active Super Admin. It **fails closed**: if the count cannot be read, the
   change is refused. The count includes **permanent** Super Admins only — by
   role, or by a temporary-role row with no expiry. A timed grant lapses on
   its own, so it never stands in for the owner: while the last permanent
   owner exists, a week-long Super Admin grant does not make them removable,
   and a week later somebody still holds `*`.
5. **Step-up.** A write that needs a dangerous permission requires a second
   factor proved within `step_up_minutes` (default 15), or the API answers
   `403 { step_up_required: true }` and the console re-prompts (§7.9).

### 5.6 Joiners, movers and leavers

- **Status** is `invited` → `active` ↔ `suspended`, and `active` ↔ `disabled`.
  Suspending is a pause; disabling is how someone leaves. **There is no hard
  delete (D17)**: a deleted row takes the record of what that person did with
  it. Suspending or disabling ends their sessions and drops their grace
  windows on the spot.
- **Employee numbers** (`ACME000001`: the `ORG_CODE` and six digits) are issued
  from the highest number ever issued — a high-water mark in `meta`, checked
  against the largest existing — never from a row count. Disabling employee 12
  must not hand 12 to the next hire, because that number outlives the database
  in payroll and email signatures. A unique index backs it, and an explicit
  duplicate check turns a typo into "that number is taken" rather than an
  unexplained 500.
- **Temporary roles** need an expiry, in the future, at most 90 days out.
- **Managers** see their own reports through `team.view` — status, sign-ins
  and streaks — without seeing everyone.

*Provenance: ranks, danger flags, grants and denies, rank and minting guards,
the last-superuser rule and employee numbers are B §4 and B §9.10; the
non-grantable set, "hide what you cannot use" and grant sources are A §9; peers
(D4) and the fail-closed readings are this design.*

---

## 6. Authentication

### 6.1 Password hashing: chained PBKDF2 (D5)

PBKDF2-HMAC-SHA256 with a 32-byte random salt per user and a 256-bit output.
The work factor is **600,000 iterations by default** (`PBKDF2_ITERATIONS`,
minimum 100,000) — and you cannot simply ask WebCrypto for 600,000, because
**Cloudflare Workers refuses any single PBKDF2 derivation above 100,000
iterations**, and `wrangler dev` does not enforce that limit (§14.6).

So the hash is a **chain of rounds**: each round derives 256 bits with at most
100,000 iterations, and those bits are the next round's key material. An
attacker still performs every iteration in sequence; no single call exceeds the
ceiling.

```
material = utf8(password)
for each chunk of PBKDF2_CHUNK (100,000) in the total:
    material = PBKDF2-SHA256(key = material, salt, iterations = chunk, 256 bits)
hash = material
```

**The chunk size is frozen.** It is not "the platform limit"; it decides how a
total splits into rounds, and the split is part of the digest. If the ceiling
rises one day and someone raises the constant to match, 600,000 becomes three
rounds instead of six and **every stored password stops verifying at once**.
The constant is commented as untouchable for exactly that reason.

Each row stores its algorithm name, salt and iteration count, and verification
uses the row's own values. Raising `PBKDF2_ITERATIONS` affects new hashes only
and invalidates nobody. Verification fails closed on anything unreadable: an
unknown algorithm, an iteration count outside 100,000–10,000,000, a salt
shorter than 16 bytes or a hash that is not 32 bytes all mean "no match", never
"skip the check". Comparison is constant-time: hash both sides to fixed-length
digests and compare every byte; never `===` two secrets.

### 6.2 Password rules

Twelve to 1,024 characters, not equal to the email address or username, not one
character repeated. Nothing else: no composition rules, no expiry. Long
passphrases are what the length floor is for.

### 6.3 One reply to the caller, the truth to the log

The reply to a failed sign-in is **byte-identical** whatever went wrong — no
such account, wrong password, suspended, disabled, locked: `401 { error:
'Invalid credentials.' }`. Telling a stranger which half they got right is how
an account list gets enumerated. To keep timing from telling them instead, an
unknown account still spends one full password derivation against a dummy salt.

Two refusals are deliberately different, and both are reachable only by someone
the gate has already let in. In `fingerprint_gate` mode, a sign-in from a
browser that has not reported a fingerprint gets `403 { fingerprint_required:
true }`, so the page can report one and retry. In `lockdown`, anyone who is not
a Super Admin gets a 403 — and in that mode only an allowlisted address with an
approved device gets as far as the password at all.

**The audit log is a different audience.** Only people trusted to read it can,
and they are the people who must work out why someone cannot get in. So it
records which it was: `No account called 'jsmith'`, `Wrong password for
'jsmith'`, `Account suspended`.

This is not a nicety. Without it, an administrator once reset the same
person's password repeatedly over an hour while that person typed a username
that had never existed — and every line in the log looked exactly like a bad
password.

Status is checked **after** the password is verified (§3.1), and again at every
later step of the same sign-in: a suspension that lands between the password
and the factor must not be completable with a code already in hand.

### 6.4 Rate limits and lockout (D6)

Every limited action is **charged before the check it protects**: insert the
attempt, prune old rows in the same batch, count, then decide. A correct
password costs the same as a wrong one.

| Bucket | Limit | Subject |
|---|---|---|
| `login_ip` | 20 per 10 min (200 for an allowlisted address) | client address |
| `login_id` | 10 per 15 min | normalised identifier |
| `mfa_user` | 5 per 15 min | user — sign-in **and** step-up factor attempts |
| `otp_send` | 5 per 15 min | user — codes sent (texts cost money) |
| `curpw_user` | 10 per 15 min | user — current-password checks |
| `setup_ip` | 5 per hour | address — bootstrap-key guesses |
| `request_ip` | 5 per hour | address — access requests |
| `invite_ip` | 20 per hour | address — invitation-token lookups |
| `fp_ip` | 30 per 10 min | address — fingerprint reports |
| `device_code_user` | 10 per hour | user — device-code guesses when approving your own device |

**The per-IP sign-in bucket is never cleared** — not on success, not by an
administrator, and the clearing function refuses to touch it by construction.
It is the only limit that bounds credential spraying: one guess each against
many accounts never trips a per-account limit. Clearing it on success lets
anyone holding one working credential spray, sign in, and reset the brake —
and resets it for everyone else behind the same office NAT. Per-account
counters *are* cleared on a successful sign-in. The allowlisted ceiling is
higher because a whole office shares one address.

**Lockout, reconciled.** A said lockout is a denial-of-service vector against a
small user base where every account matters; B locked an account for N minutes
after N failures. Both are right, so the merged rule is: **ten consecutive
failures lock the account for fifteen minutes — except on a device that has
signed in to that account before.** A stranger hammering an address from
outside can lock it against strangers; they cannot lock its owner out of their
own laptop. The device ledger (`device_users`) is what makes the distinction,
and a device cookie cannot be forged (§8.1). The lock is invisible to the
caller (§6.3); administrators see `locked: true` on the account, never the raw
counters.

### 6.5 Changing and resetting passwords

A signed-in person may change their own password by supplying the current one
(charged to `curpw_user`); doing so ends every *other* session they have.
There is **no self-service reset**: that is the point of a system whose
accounts administrators create.

Resetting someone else's password is reserved to Super Admins, subject to the
rank guard. It produces a temporary password, shown once to the Super Admin,
ends the person's sessions, drops their grace windows, and pins their next
session to the change-password form. The Super Admin knows that password for
the minutes until it is changed; that is why the capability is reserved and
why the change is forced.

### 6.6 Bootstrap (D15)

A `/setup` page, reachable only while no account exists (the gate's `setup`
shell), creates the first Super Admin. It is guarded three ways:

- **The setup key**, a secret (`SETUP_KEY`) compared in constant time, with
  five guesses per address per hour.
- **A one-shot claim row** in `meta`, so two simultaneous setup requests cannot
  both create an owner.
- **The claim expires after ten minutes.** A claim that never expires is a
  trap: the first production setup of the system B describes failed halfway —
  the PBKDF2 ceiling (§6.1) made every password write fail — and a permanent
  claim would have left a portal with no accounts that refused to create one.
  An expiring claim lets a failed setup be retried.

In the same request, setup **allowlists the caller's address as tier 1** (a
`/32` or `/128`), **approves the caller's device**, and signs the new owner in
— pinned to second-factor enrolment, because a Super Admin's policy is always
`required` (§7.8). Without the allowlist entry or the device approval, the
owner would lock themselves out on their very next request in the default
`allowlist` mode. Once an account exists, the setup shell no longer exists and
the route is unreachable. Delete `SETUP_KEY` afterwards if you like; nothing
needs it again.

### 6.7 Invitations (D11)

Nobody ever knows anyone else's password. An administrator with `users.invite`
creates the account (status `invited`, a role they are allowed to assign) and
receives an **invitation link** containing a 256-bit random token. The
database stores only the token's SHA-256. The link lasts seven days, is single
use, and creating a new one revokes earlier ones for that person.

A said no email of any kind; B sent invitations by email. The merge: the
administrator **copies the link** and sends it however they trust; if a mail
provider is configured, it is emailed as well. The portal never depends on
email arriving.

Opening a valid link sets a short-lived signed **pass cookie**, which lets the
invitee through the gate as far as the invitation page in modes that would
otherwise show a stranger nothing (§3.2). Accepting sets the person's
password, activates the account, signs them in through the one completion path
(§7.3), and **approves the device they accepted on**. The invitation *is* the
administrator's approval: requiring a second, separate device approval for the
browser that opened a link the administrator minted for this person adds a
round-trip and no security. The cost is that a forwarded link approves
whoever's browser opens it first — which is why links expire, are single use,
are revocable, and should travel by a channel you trust.

### 6.8 Access requests

In `request_access` mode a stranger sees a form: email, name, reason. The reply
is identical whether or not the email belongs to anyone. Each request records
the address, country, visitor id and risk score, so whoever reviews it sees
more than a stranger's own description of themselves. Approving one
(`requests.manage`) creates the invited account with a role the approver is
allowed to assign, and an invitation; denying records the decision. Five
requests per address per hour.

### 6.9 Sessions (D16)

The session cookie (`__Host-sid`) holds a 256-bit random token; **the database
stores its SHA-256**. A leaked backup, an export, or a query by a read-only
role exposes no usable session. Session lists show only `id_ref`, the first
twelve hex characters of the stored hash: enough to act on, useless as a
credential.

Sessions end on whichever comes first: **idle** (`session_idle_minutes`,
default 120) or **absolute** (`session_absolute_hours`, default 8). The idle
expiry is extended at most once a minute, so an active page does not write on
every request. Each session records its assurance level (1 = password only,
2 = a factor proved), when and how a factor was last proved, and any pin.

Loading a session refuses: an unknown or revoked token, either expiry passed,
an account that is not `active`, and — in `lockdown` — anyone who is not a Super
Admin. People can see and end their own sessions; administrators with
`sessions.revoke` can end anyone's below them.

**Serve a signed-in visitor past the landing and sign-in pages, server-side.**
Showing someone with a valid session a "Sign in" button reads as though they
were signed out. `/` decides on the server — dashboard, the pinned task, the
sign-in page, or a shell page — so there is no flash of the wrong page.

*Provenance: chained PBKDF2, the frozen chunk, per-row counts, the expiring
setup claim, invitations and lockout are B §5 and traps 1, 3, 4; constant-time
comparison, charging before checking, identical reply with a distinct log, no
self-service reset and the setup allowlisting are A §6 and §15; D6, D11, D15
and D16 are the merge.*

---

## 7. Second factors

### 7.1 Which methods to offer, and in what order (D8)

Ask the account what it can actually prove with, and offer only that,
strongest first:

1. **Passkey** — phishing-resistant, nothing to type.
2. **Authenticator app** (TOTP) — works offline, everywhere.
3. **Backup code** — ten, single use, for the day the phone is lost.
4. **A code by email or text** — to a destination an administrator added.
   Labelled in the interface as the weakest option, because it is.

**A code is sent automatically only when it is the only method the account
has.** This is the most user-visible decision in the design. Someone with a
passkey or an authenticator never receives a text; someone who has not
enrolled, or has lost their device, still does. Nobody is locked out by the
rule and nobody is texted who did not need to be.

Two things do **not** count as "has a factor": an authenticator enrolment that
was never confirmed (§7.4), and backup codes on their own. Backup codes are
what an interrupted admin reset leaves behind, not something the person chose,
and they run out; an account with only backup codes is still prompted to enrol
(§7.8).

### 7.2 The half-finished sign-in

Between the password and the factor, state is carried in a short-lived signed
token, not a session:

```
payload = `${userId}.${destinationId}.${expiresAtMs}`
token   = `${payload}.${b64url(HMAC(SESSION_SECRET, 'mfa.' + payload))}`
```

Five minutes. The purpose prefix (`mfa.`) means a token minted for one job —
a device cookie, a fingerprint cookie — cannot be replayed as another. It
binds **which destination** a code was sent to, because verification is keyed
on where the code went: if that destination is removed from the account, the
code stops being a way in. Choosing a different destination issues a new token
bound to it. Every factor endpoint re-checks that the account is still `active`
and that `lockdown` does not exclude it, and charges `mfa_user` before
verifying.

### 7.3 One completion path

Whatever proved it — a password alone, a live grace window, an authenticator,
a backup code, a sent code, a passkey, an accepted invitation, the setup
page — the session, device record, grace window, counters, audit line and
streak must be established **identically**. One function, `completeSignIn`,
does it, in this order:

1. track the device (mint a device cookie if there is none; update the ledger);
2. record a grace window — only if a factor was actually verified on this
   sign-in **and** the address has a tier (§8.9);
3. work out the pin, if any (forced password change, required enrolment);
4. create the session;
5. stamp `last_login_at`;
6. clear the per-account counters (`login_id`, `mfa_user`, failed logins) —
   **not** the per-IP bucket;
7. audit `login.success` "Signed in with {how}";
8. touch the streak — wrapped so it can never fail the sign-in (§10.16);
9. answer `{ ok, user, pinned, enroll_prompt, next, streak }`.

Four near-copies of this is how one factor ends up not starting a grace
window, or not clearing a counter, or not counting toward the streak, and
nobody notices for months. The `how` label is how the audit log still tells
them apart.

### 7.4 Authenticator apps (TOTP)

Standard RFC 6238 — HMAC-SHA1, six digits, 30-second step, one step of drift
either way — so every authenticator app works. The parts that are easy to get
subtly wrong:

**Minimum secret length, enforced at verification.** Generated secrets are 160
bits; any secret shorter than 128 bits is refused *when verifying*, not only
when generating (RFC 4226 §4, R6). A truncated or corrupted stored secret
otherwise produces normal-looking codes that are brute-forceable — with a
one-byte secret, one observed code narrows it to a single candidate. That is
not a degraded factor; it is none.

**The replay floor fails closed.** Store the counter last spent and refuse any
counter at or below it; a code is otherwise live for its whole step. Three
cases, not two: no stored counter means no floor; a safe integer is the floor;
**anything else — `'garbage'`, `NaN`, an object, `Infinity` — refuses every
code**, and is audited. The presence of a counter means the account *has* spent
one; an unreadable one is exactly when the floor matters most (§16.3).

**Encrypt the secret at rest.** AES-GCM with a 256-bit key derived by HKDF from
`DATA_KEY` — a different secret from the one that signs cookies (§13.3) — a
fresh 96-bit IV per encryption, additional data binding the ciphertext to its
row (`totp:42`, so it cannot be moved to another account), and a version prefix
(`v1.`), so a future algorithm is a new prefix rather than a guess. A row that
will not decrypt is **refused** and audited as `mfa.decrypt_failed` at critical
severity — never treated as "no authenticator configured", which would quietly
fall back to something weaker.

**Unconfirmed until a code is proved.** Enrolment writes the secret with
`confirmed_at` empty, and an unconfirmed row cannot satisfy a sign-in.
Otherwise abandoning the setup screen halfway leaves an account whose second
factor nobody holds. Confirming issues backup codes if the person has no
unused ones.

**Draw the QR code yourself.** The `otpauth://` URI *contains the secret*;
handing it to a third-party QR service hands out a working credential, and the
CSP forbids one anyway. The portal has its own encoder — byte mode, error
correction level M, versions 1–10 — producing an SVG served as a `data:` URI.
Two details: the code always sits on **its own white plate**, because a
dark-on-dark QR in dark mode does not scan and this is the one image on the
page that must work with a camera pointed at it; and a blank or whitespace
margin parameter falls back to the default, never to zero (§16.5). The secret
is also shown as text, grouped in fours, for when a camera will not
cooperate.

### 7.5 Backup codes

Ten codes, shown exactly once with copy and print, stored only as salted
hashes, each single use.

- **An unambiguous alphabet**, `23456789ABCDEFGHJKMNPQRSTUVWXYZ` — no `0`, `1`,
  `I`, `O` or `L` — because these are read off paper and typed by hand.
  Generated by rejection sampling, never `% n`, or the first letters become
  measurably likelier. Format `ABCDE-FGHJK`.
- **Normalise** case, spaces and hyphens: someone reading a code off paper will
  type it lowercase, spaced, or run together, and all of those are the same
  code.
- **Shape-gate before hashing.** Normalising strips separators, so `''`,
  `'   '`, `'-----'`, `null` and `[]` all normalise to the empty string and
  would hash to `hash('')` — which matches any row that happens to hold it: an
  empty slot, a half-finished enrolment, a migration that hashed a missing
  field. That is an absent code opening an account. Require exactly ten
  characters from the alphabet *after* normalising, before any hash is
  computed (§16.4).
- **One salt per set.** All ten codes in a set share a salt, so one derivation
  of the submitted code can be compared against every unused hash. Ten salts
  would mean ten 100,000-iteration derivations per guess, on an endpoint a
  stranger can reach.
- **Same box as the authenticator code.** To the person signing in they are the
  same box: try the authenticator first, then the backup codes, then fail. A
  spent code is audited as `mfa.backup.used`, so the person and their
  administrator can see the count fall.

### 7.6 Codes by email or text

Six digits, valid ten minutes, stored hashed, five attempts per code, single
use; five sends per person per fifteen minutes. Texts go through Twilio and
email through Resend, each called with `fetch` and never allowed to throw —
a provider that is down produces "could not send", not a 500.

Codes go only to **code destinations**: numbers and addresses on the account,
added by a Super Admin (`destinations.manage` is reserved — adding a
destination is handing out a second factor). A destination is usable only if
its provider is configured. Several destinations per person make a lost phone
an inconvenience rather than a lockout. The system will not remove the only
usable destination when it is the last factor, and it promotes another to
primary when the primary is removed. The interface shows destinations masked:
`•••• 1234`, `j•••@acme.com`.

### 7.7 Passkeys (WebAuthn)

Implementable from scratch in a few hundred lines. The thing to understand is
that **a demo works with almost none of the checks in place**. Here is the
full list and what each one prevents.

**Registration.** Under `attestation: 'none'` you verify *no signature at all*,
so the public key — every parameter of it — is entirely attacker-chosen input.

| Check | Without it |
|---|---|
| `clientData.type === 'webauthn.create'` | an assertion replays as a registration |
| `clientData.challenge` equals one we issued, and the challenge row is deleted | no freshness; a captured ceremony replays |
| `clientData.origin` **exactly** equals `ORIGIN` | a lookalike origin enrols keys |
| `rpIdHash` equals SHA-256 of `RP_ID` | the credential is scoped to another site |
| User Present flag set | no human was involved |
| Attested credential data present, well-formed, and authenticator data accounts for every byte | nothing to store, or a structure you have misread |
| COSE key → JWK with **the algorithm matching the key type** | a key claiming ES256 over another curve is imported as whatever the curve label says |
| EC: curve P-256, coordinates exactly 32 bytes | malformed key, undefined behaviour at import |
| RSA: modulus 1,024–8,192 bits **and odd** | tiny or even moduli are cheap to factor |
| RSA: public exponent **odd, ≥ 3, at most 8 bytes** | see below — this is the big one |
| Import the key *at enrolment* | you enrol a key that cannot sign anyone in, and find out at the worst moment |

**The RSA exponent is the one that matters.** RSASSA-PKCS1-v1_5 verification
computes `s^e mod n`. With `e = 1` that is the identity: the "signature" is just
the padded digest, which **anyone who knows the public key can write down, with
no private key in existence.** Registration verifies no signature, so `e`
arrives from whoever is at the enrolment form. A credential enrolled with
`e = 1` is forgeable by anybody and still reads as the strongest factor on the
account. `e = 0` is the mirror image (nothing ever verifies), and an even `e`
shares a factor with φ(n), so it is not a working RSA key at all. Real
authenticators use 65537. Require odd and at least 3, and cap the width so a
megabyte-long exponent is not something you agree to exponentiate by.

**Assertion** — everything above except attestation, plus:

| Check | Without it |
|---|---|
| `clientData.type === 'webauthn.get'` | a registration replays as a sign-in |
| the credential is registered **to this user** | someone else's passkey signs you in |
| signature verifies over `authenticatorData ‖ SHA-256(clientDataJSON)` | the whole point |
| **re-validate the stored key** with the same checks | see below |
| signature counter strictly increases whenever either side is non-zero | a cloned authenticator goes unnoticed |

**Re-validate the stored public key on every use.** A database column is not a
trust boundary. A row that was edited, restored from an old backup, or written
by an earlier version of your own code must fail closed rather than be handed
to WebCrypto on the strength of having once been yours. A stored exponent of 1
makes every assertion for that credential forgeable, so one function,
`validatePublicKey`, runs at enrolment *and* on every assertion, and the two
paths cannot drift.

**The counter.** Synced passkeys (most platform authenticators today) report a
counter of zero forever; both sides zero is normal and accepted. Once either
side is non-zero, the new value must be strictly greater. A regression means a
cloned authenticator: it is refused and audited as
`mfa.passkey.counter_regressed`.

**Three parsing details that are genuinely load-bearing:**

1. **Strict DER for ECDSA signatures.** WebAuthn gives you ASN.1
   `SEQUENCE { INTEGER r, INTEGER s }`; WebCrypto wants raw `r ‖ s`, and
   nothing converts for you. Be strict: exact outer length; minimal length
   encodings (long form only above 127, two-byte form only above 255); no
   trailing bytes; no integer wider than a coordinate; no non-minimal integer
   (a leading `0x00` is legal *only* to keep a high-bit value positive); no
   negative integer. A lenient DER reader is its own bug class: two encodings
   that verify as the same signature is what signature malleability means, and
   anything downstream that identifies a signature by its bytes can then be
   shown two of them.
2. **Refuse duplicate CBOR map keys.** RFC 8949 §5.6 calls such a map invalid.
   "Last one wins" is a parser differential: `{"fmt":"none","authData":A,
   "authData":B}` reads as `B` to you and as `A` to anything that stops at the
   first match, so the bytes you *check* and the bytes something else *logs*
   are different bytes. The decoder also refuses indefinite lengths and
   trailing bytes, and caps depth and size.
3. **Authenticator data accounts for every byte.** It is a 37-byte head, then
   attested credential data if and only if the AT flag is set, then extensions
   if and only if the ED flag is set, and *nothing after that*. Leftover bytes
   do not mean "authenticator data with a suffix"; they mean a structure you
   have misread, and the safe reading of a misread structure is none at all.
   The same for ED set with no extension map behind it.

**Challenges are rows, not tokens.** A table with a five-minute expiry; the row
is **deleted on use whether or not the rest of the ceremony succeeds**, which
is what makes it single-use. A signed self-describing token cannot be single
use without server state anyway, so the table is the simpler honest design.
Issuing a challenge prunes expired ones.

**Options.** Offer `pubKeyCredParams` only for algorithms you can verify —
ES256 (`-7`) and RS256 (`-257`); offering more enrols keys that cannot sign
in. Pass the person's existing credentials as `excludeCredentials`, so the
browser refuses to register the same authenticator twice instead of silently
making a duplicate. `residentKey` and `userVerification` are `preferred`: the
passkey is a second factor after a password, so presence is required and a
PIN or biometric is welcome but not demanded — demanding it would exclude
plain security keys.

**Client-side mechanics.** The browser speaks `ArrayBuffer`; the wire format is
base64url, both directions. Build the base64 string with a loop, not
`String.fromCharCode(...bytes)`, whose spread throws past roughly 120,000
elements (a stack-dependent threshold, not a specified one; the loop costs
nothing). The output must be **url-safe**: a `+` or `/` in a credential id
breaks the lookup. Test with bytes that differ between the alphabets
(`[0xfb, 0xff, 0xbe, 0x01]` → `+/++AQ==` against `-_--AQ`); arbitrary bytes
usually encode identically and the assertion passes against a page that never
made its output url-safe (§16.52).

**Labels.** Let people name each passkey, prompting with a guess from the user
agent, so a list of three reads as three devices.

### 7.8 Enrolment: prompted or required, never refused (D7)

A said: prompt the un-enrolled at every sign-in, but never wall them in. B
said: force enrolment, by pinning the session to the enrolment routes, because
"MFA is required and you have none — ask an administrator" is advice nobody can
act on. The two agree on the essential thing — **never refuse the session** —
and differ on how hard to push. So it is a setting:

- **`prompt`** (the default). A sign-in with nothing enrolled lands on the
  account page with a setup-focused banner, carrying the person's real
  destination so that skipping takes them where they were going. It asks
  again **at the next sign-in**: a one-off notice somebody clicked past is a
  notice that never happened. The "who am I" and `/api/me` responses carry the
  same flag, so a session that is already open gets the nudge too — nobody
  signs in twice a day.
- **`required`.** The session is issued at assurance level 1 and **pinned** to
  the enrolment routes, exactly as a forced password change pins a session to
  the password form; everything else answers 403 until a passkey or an
  authenticator is confirmed.

The global setting can be overridden per person (`inherit`, `prompt`,
`required`). **A Super Admin is always `required`.** An unrecognised stored
value reads as `required`.

The same shape applies to any "you must do X first" state: **pin, never
refuse.** Refusing a session to someone who needs a session to fix the problem
is a lockout that looks like a policy.

**The honest cost.** An account with nothing enrolled is a password-only
account until somebody enrols, and the first person to sign in with that
password chooses the factor. So the windows in which that is true are kept
short and supervised: an invitation (the link is the secret, and the invitee
enrols in the same sitting), setup (the key is the secret), and an admin factor
reset (done with the person, on the phone).

**Never remove the last factor.** One function, `canDropFactor`, called from the
self-service page *and* the admin page, refuses to delete the last passkey,
authenticator or usable code destination standing between the account and
password-only. Without it you can delete your way to a downgraded account from
inside the settings page.

**The admin reset, for the call that actually happens.** "I've lost my phone
and the authenticator went with it." They cannot reach the settings page to
remove it, because they cannot sign in. So `users.reset_mfa` clears the
authenticator, every passkey and the backup codes in one step, **and drops
their grace windows**, so no already-verified browser coasts through without a
check. It **refuses when no usable code destination would remain** — clearing
everything would turn the account password-only, which is the state a
phished password wants — so the usual sequence is that a Super Admin adds a
destination first, then the reset, then the person signs in with a code and is
prompted to enrol a new factor. The reset snapshots what it cleared —
including the still-encrypted authenticator secret, so the app already on
their phone works again — so resetting the wrong person is recoverable. That
revert is refused if they have enrolled anything since, rather than silently
replacing it.

The enrolment page acts only on the caller's own account: its routes carry no
user id, so nobody can add a passkey to someone else's login.

### 7.9 Step-up

Dangerous writes (§5.2) need a factor proved within `step_up_minutes`
(default 15; an unreadable value means 5). Otherwise the API answers
`403 { step_up_required: true }`, and the console's step-up dialog runs the same
methods as sign-in — bound to the current session, charged to the same
`mfa_user` bucket — then retries the original request. A step-up timestamp in
the future (a moved clock, a restore) is not fresh forever: one minute of skew
is allowed and no more. Self-service actions that weaken an account — removing
an authenticator or passkey, regenerating backup codes, approving a device for
yourself — need a step-up too.

### 7.10 The sign-in page's state machine

The login page decides what a person sees, and this is where the dead ends
live.

```
password accepted
      │
      ├─ no factor needed (grace window, or nothing enrolled) ─► signed in
      │
      ├─ the server already sent a code (a code was the only method)
      │     └─► code box, saying where it went
      │
      ├─ exactly one method THIS BROWSER can use
      │     └─► open it directly. A list with one row is not a choice.
      │
      ├─ two or more
      │     └─► chooser, strongest first, nothing fired automatically
      │
      └─ NONE this browser can use                          ◄── the dead end
            └─► explain it. Do NOT render an empty list.
```

The last branch is real: an account whose only factor is a passkey, opened in
a browser without WebAuthn. Naively that renders a chooser with every row
hidden — a card with nothing on it. Name the browsers that work and suggest
asking an administrator for a code destination.

More rules:

- **"Use a different method" keys off what this browser can offer**, not what
  the account has enrolled. Otherwise it leads to a list with one row.
- **A cancelled system dialog is not an error.** Dismissing the passkey prompt
  is usually someone reaching for a different method. `NotAllowedError` and
  `AbortError` return to the chooser; they do not go in the red box.
- **A spent challenge cannot be retried.** The server burns the challenge
  either way, so once an assertion has been posted, a Retry button that
  re-runs the ceremony can only fail. Clear it and turn the button into
  "Start over".
- **After success, ask "who am I?" before navigating.** If that comes back
  unauthenticated, the cookie never made it home — private browsing, a "block
  all cookies" setting, an in-app webview. Say so, in those words, instead of
  bouncing the person into a loop (§8.6).
- **A `?next=` is an open-redirect candidate.** Accept only same-host paths:
  refuse off-site URLs, protocol-relative `//host`, `javascript:`, an `http:`
  downgrade of our own host, and junk. The same check guards the enrolment
  page's skip button and every back link.

*Provenance: the methods, their order, SMS-only-when-only, the half-finished
token, the one completion path, TOTP, backup codes, passkey checks, the client
state machine and the admin reset are A §7; email codes, labelling SMS as
weakest, the monotonic counter, pinned enrolment and step-up are B §4–§5 and
trap 3; D7 and D8 are the merge.*

---

## 8. Devices, grace windows and the gate in detail

### 8.1 Device identity

A device id is a random value in a cookie (`__Host-dev`), **HMAC-signed with
`SESSION_SECRET`** so it cannot be forged, and recorded server-side:

```
cookie value:  <random id>.<b64url(HMAC(SESSION_SECRET, "device." + id))>
```

The signature is verified *before* the database is touched, so a forged or
mangled id costs nothing. It is not a fingerprint and does not pretend to be
one (§9.1).

Every device that signs in is recorded, whether or not device gating is on, so
that when you do want to turn gating on there is a real list to review rather
than an empty one. Each device has a status — `pending`, `approved`, `blocked`
— a label derived from the user agent, first and last address, and a ledger of
which accounts have signed in on it. The pending list is capped at 2,000 rows
and anything pending and unseen for 30 days is pruned, or a scanner hammering
the login page fills it.

### 8.2 Approving devices

With `device_gating` on, an unapproved device sees only the **pending page**,
which shows a short code (`K7F3-9QX2`) to read out to an administrator, and
reports its own status as it changes. Gating covers the API too, so an
unapproved device cannot call the endpoint that would approve it.

Four ways a device becomes approved:

- **An administrator approves it** (`devices.approve`) by its code.
- **Its owner approves it from another device** — "approve my phone from my
  laptop" — by typing the code on the self-service page. This works only from a
  device that is itself approved, needs a step-up, and allows ten code guesses
  per hour.
- **Accepting an invitation** approves the device it was accepted on (§6.7).
- **Setup** approves the owner's device (§6.6).

Blocking a device refuses it at the gate's first step in every mode. Revoking
one returns it to pending. Both drop its grace windows and end the sessions on
it. People can forget a device of their own from their devices page, which
does the same for them.

### 8.3 `SameSite=Lax`, not `Strict`

`Strict` withholds the cookie on *any navigation that began somewhere else* — a
link in a chat message, an email, a QR code. Following one arrives as a
stranger: signed out, on a device the portal has never seen, which then
demands a fresh factor and leaves another row in the pending list. Approving
the device does not help, because the next visit from a link is a "different
device" again. The symptom is "my phone keeps asking me to approve it", and it
is maddening to diagnose. Every cookie here is `Lax`.

### 8.4 Turning gating on approves the device doing it

Before device gating is first enabled, nobody has an approved device unless
setup or an invitation approved it. Refusing the change at that moment would
make the feature impossible to switch on, and allowing it without care would
lock out the person switching it. So enabling `device_gating` — or switching to
`allowlist`, `invite_only` or `lockdown` — **approves the caller's current
device in the same request** (minting it an id if it has none) and says so in a
notice. The trusted, authenticated, stepped-up person making the change is the
one device you can be sure should be approved.

### 8.5 What a browser can tell you about a device

Less than you think. There is no MAC address, no serial number and no machine
name — on any platform, in any browser. What you can get is screen and window
size, pixel ratio, colour depth, time zone, core count, touch points and the
user agent: enough to label a row usefully and nothing like enough to identify
a device.

And specifically: **the `Sec-CH-UA-*` client hints are Chromium-only.** Branching
on `Sec-CH-UA-Mobile` files every Firefox and Safari visitor as a desktop, and
when `Sec-CH-UA-Model` is absent a naive implementation ends up displaying the
literal string `Mobile` as the device model. Labels come from the user agent
first; hints are a bonus. Test with a non-Chromium user agent.

### 8.6 The diagnostic endpoint, and the cookie that did not stick

The most confusing failure in the system is a sign-in that *completes* —
session row written, audit row written — and then lands back on the sign-in
page. From the outside it is indistinguishable from a wrong password. It is
nearly always a browser that refused to keep the cookie: private browsing, a
"block all cookies" setting, or an in-app webview.

Two things answer it. The sign-in page asks "who am I?" after success and
before navigating, and says plainly when the cookie did not come back (§7.10).
And `GET /api/diag` answers "what did the browser actually send?": cookie
**names** and a count — never a value, because this endpoint exists to be
screenshotted — plus the user agent, client hints, the address and country the
edge saw, the TLS version, whether a device cookie was present and its status
and code, and whether a session was present and valid. It is reachable from the
pending page, which is where people are when they need it.

### 8.7 The allowlist and the blocklist

- Entries are bare addresses or CIDR ranges, IPv4 and IPv6, **normalised to
  bytes and compared by prefix** — never string matching. IPv4-mapped IPv6 is
  treated as IPv4; host bits below the prefix must be zero; text is stored in
  canonical form.
- **Private and reserved ranges are refused at entry**: RFC 1918, loopback,
  link-local, carrier-grade NAT, unique-local IPv6, multicast and the
  documentation ranges. Callers always arrive on a public address, so a row for
  `10.0.0.0/8` could never match anyone — it is a misunderstanding, or an
  attempt to widen the list with something that looks harmless. Say so when
  refusing it.
- **A whole-family entry is refused** (`0.0.0.0/0`, `::/0`). That is not an
  allowlist entry; it is turning the gate off, and there is a separate, audited,
  time-boxed control for that (§8.8).
- Where an address matches several entries, **the most specific wins** — a
  `/32` carve-out beats the `/16` around it. On an exact tie, **the stricter
  tier wins**, so an accidental overlap can never buy a longer grace window.
- Each entry has a **tier** (§8.9), an optional label, owner and person, and an
  optional expiry. A tier-4 entry added without an expiry **gets** one — 24
  hours — because a temporary entry that never ends is exactly what the tier
  exists to prevent.
- Expired entries are **kept** — so an administrator can see what lapsed — and
  excluded by every query. "Active" and "live" always mean *not expired*.
- The **blocklist** takes the same address syntax with a reason and an optional
  expiry, and blocks at the gate's first step.

Removing entries is guarded (§12): never the last live entry, and never one
whose removal would leave the caller's own address uncovered.

### 8.8 Opening to the internet

A deliberate, audited, Super-Admin-only switch (`gate.open` is reserved) that
treats every visitor as trusted for a bounded time — the escape hatch for
"half the office is working from hotels this week". Stored as one setting:

- `'0'` — closed.
- `'1'` — open until explicitly closed.
- an **ISO 8601 instant** — open until that moment.
- **anything else — closed.**

That last line is the whole ballgame; this exact feature failed open twice
before it was right (§16.1, §16.2). The endpoint takes `{ hours }` as an
integer from 1 to 168, rejecting `null`, `''`, `undefined` and booleans
*before* any numeric coercion; "open until I close it" needs the explicit
`{ forever: true }`. A stored instant more than 168 hours ahead is refused
too. The switch never applies in `lockdown`, and opening or closing it is
audited but **not revertible** — a revert could reopen a portal somebody just
closed.

An administrator with `settings.manage` may turn device gating on and set the
time zone; they may not take the outer wall down for everyone. That stays with
the Super Admin, alongside password resets.

### 8.9 Grace windows (D9)

The one place this design deliberately trades security for the people using
it. Each allowlist entry's **tier** says how trusted its network is, and that
decides how long a successfully proved factor lasts on a device:

| Tier | Network | A factor is required |
|---|---|---|
| 1 | core admin; nobody else on it | every 7 days |
| 2 | trusted; others are on it | every 24 hours |
| 3 | frequent but shared with many | every 2 hours |
| 4 | temporary | every time, and the entry expires |

The window is remembered **per account and per device**. A browser that has
never completed a factor check does the full sign-in however trusted the
network.

- An address **not** on the allowlist has no tier and therefore **no grace**.
  Every sign-in from the open internet costs a factor, however recently you
  signed in — which is the best argument for enrolling a passkey: from a phone
  on mobile data, the factor is otherwise a code every single time.
- The window is the **shorter** of the stored expiry and the current network's
  window measured from when the factor was proved. Arriving from a lower-trust
  network shortens it; arriving from a higher one never lengthens it.
- A window is recorded only when a factor was **actually proved** on this
  sign-in. A sign-in that rode a grace window does not extend it, or one check
  would last forever.
- **Drop the window whenever trust is withdrawn**: revoking or blocking the
  device, revoking all of someone's devices, resetting their password,
  suspending or disabling them, or clearing their factors. Miss one and a
  revoked device keeps coasting.

`mfa_grace` turns the mechanism off; an unrecognised value reads as off.

*Provenance: device cookies, `Lax`, auto-approve on enable, client hints, the
diagnostic endpoint, allowlist matching and refusals, the open switch and
grace windows are A §4, §5, §8; device statuses, the approval queue,
self-approval from an approved device and the device ledger are B §3, §6;
invitation-as-approval (D11) is the merge.*

---

## 9. Fingerprinting and risk

### 9.1 A fingerprint informs; a cookie identifies (D14)

A said a device is not a fingerprint and the browser's signals are inventory,
not authentication. B fingerprinted every visitor in depth and scored them.
Both are right about different things, and the merge keeps them apart:
**device identity is always the signed cookie** (§8.1); **fingerprints and risk
are evidence** that feeds the gate's edge rules and the console.

Using a fingerprint as identity fails in both directions. Fingerprints
**collide** — a fleet of identical company laptops on the same browser version
looks like one machine — and they **drift** — a browser update or a new monitor
looks like a stranger. Identity built on them either merges two people or
forgets one.

### 9.2 The signals

**From the edge**, free on every request: every header name, the address,
country, ASN and organisation, data centre, city, TLS version and cipher, HTTP
protocol, the bot score, and JA3/JA4 where available, plus the client hints
and fetch metadata headers.

**From the browser**, reported once by a script on the public pages: user agent
and client hints (Chromium only — a bonus), languages, time zone and `Intl`
options, screen and window geometry, core count, memory and touch points, a
media-query matrix (dark mode, reduced motion, contrast, pointer, gamut),
canvas, WebGL and audio render hashes, fonts detected from a fixed list,
storage and network information, permission states, WebRTC host candidates
(host only — the CSP forbids STUN), a hash of the JavaScript engine's maths
results, an API feature matrix, and **named automation tells** (`webdriver`,
`headless-ua`, `no-plugins`, `zero-outer`, `swiftshader`, `cdc`). The full
schema is CONTRACTS §10.1; the server drops unknown keys, caps strings at 256
characters and arrays at 64 items, and refuses a body over 16 KiB.

**Every probe is individually error-trapped behind one overall deadline**
(1.5 s). A browser that blocks any of it must still load the page normally,
and the absence is itself a signal: a probe that threw or timed out is listed
in `blocked`.

### 9.3 Three derived values

- A **fingerprint hash** — this exact configuration.
- A **visitor id** — a hash of the *stable* subset, so a browser update is not a
  new stranger.
- A **risk score from 0 to 100** — the sum of weighted flags, each with a
  **plain-English reason**, so the console can explain the number rather than
  assert it: "automation: navigator.webdriver is set", "datacenter network",
  "time zone disagrees with the address's country".

The score and hash travel in a signed cookie (`__Host-fp`), so the gate can use
them without a database read and a client cannot claim a lower score than it
was given.

### 9.4 Where it is used

- **The gate** (§3.1 step 2): Tor, datacenter networks, automation tells and
  the risk threshold (`risk_threshold`, default 70 — refuse at or above), all
  skipped for an allowlisted address. In `fingerprint_gate` mode a stranger
  must report a fingerprint under the threshold before a password is accepted.
- **The console**: the visitor list and visit log, with reasons (`visitors.view`).
- **Access requests**: each records the requester's visitor id and risk.
- **The person themselves**: everyone can see their own latest fingerprint,
  score and reasons on their account page. What is collected about someone
  should not be a secret from them.

### 9.5 Say so

Profiling every visitor this thoroughly is legitimate security telemetry for a
company's own staff portal, but in several jurisdictions it is regulated
personal data. **Put a one-line notice on the public pages, make it a setting,
and default it on.** Here that is `privacy_notice` (on; an unrecognised value
reads as on) and `privacy_notice_text` (up to 500 characters), delivered with
the sign-in page's "who am I" response. Retention is bounded (§13.4):
fingerprints 90 days, visits 30. This document is not legal advice; ask
someone who gives it.

### 9.6 What risk is not

Every browser signal is attacker-controlled: a careful attacker presents a
clean, ordinary browser and scores zero. The risk score raises the cost of lazy
automation, explains anomalies to an administrator, and gives the gate a
tunable cut-off; it is not authentication, and nothing here treats it as such.
The edge signals — network, TLS, bot score — are much harder to fake, which is
why they carry the heavier weights.

### 9.7 Storage

One row per distinct fingerprint hash, upserted with a hit count, and an
append-only visit log recording every refusal, every page navigation and every
API write, with the gate's decision and reason. The fingerprint table is keyed
by a hash of **client-chosen input**, so a loop of requests with a fresh user
agent each time mints unlimited rows; it is trimmed by `last_seen` *and* by
count, never by id (§16.34). Visit logging runs after the response through
`waitUntil` and never throws.

*Provenance: B §6 (signals, three derived values, reasons, "Say so",
error-trapped probes) and trap 6; A §5 (a browser cannot identify a device;
inventory, not authentication); D14 is the merge.*

---

## 10. The streak

Sign in on consecutive days and the dashboard shows a flame and a number:
**🔥 12 days**. Miss a day and it starts again at 1; the longest is kept either
way. That is the whole mechanic, and counting is the easy part. The
interesting problem — the one this section exists for — is **not punishing
people for time they could never have signed in**.

It is also the best worked example in this document of getting a calendar
right, and that lesson generalises well beyond streaks: anything that asks
"did they come back in time?" has the same shape.

### 10.1 Why a streak, in a workplace

People open a staff portal when they must. A streak gives them a reason to
open it on a quiet day — and a portal people visit every day is one they know.
They notice a device in their list they do not recognise, a session they did
not start, a line in their activity that is not theirs. They keep their factors
current and do not forget their password. Grace windows (§8.9) make a daily
sign-in from the office cheap, so the habit costs almost nothing.

It has to be fair, or it is a tax on the people it fails. A streak that ends
every week for everyone who keeps Shabbos tells them, every Sunday morning,
that the portal was not built for them. The fairness *is* the feature.

And it is encouragement, not measurement. It counts days on which someone
signed in. It knows nothing about sickness, leave, travel or work, and it must
never be used as an attendance record. The leaderboard is a setting, and it can
be off (§10.17).

### 10.2 The core problem

A plain 30-hour window ends every streak every week for anyone who cannot use
a computer on Saturday. Festivals make it worse: a two-day Yom Tov on Thursday
and Friday runs straight into Shabbos, and nobody who keeps them can sign in
from Wednesday evening until Saturday night. Three-day stretches are not
exotic; they happen most years.

Making the window longer for everyone does not fix it. A 72-hour window would
cover the long weekends and also let anybody skip two ordinary weekdays. The
window has to grow by **exactly the days nobody could sign in, and no more**:
what it measures is *hours of opportunity*, not hours of the clock.

### 10.3 The window

- After a sign-in at instant *t*, the streak continues if the next sign-in on
  a **new local day** arrives before the **deadline**, which starts as
  *t* + 30 hours (`streak_window_hours`, 24–72) and grows only for protected
  days (§10.6).
- **The window runs from the most recent sign-in** (D13). Every sign-in moves
  the anchor forward, including a second sign-in on a day that has already
  counted.
- **A local day counts once.** The row stores the local date of the last day
  that counted; two sign-ins on the same local day add nothing. That is what
  stops it being a login counter.
- **A sign-in is what counts** — not a page view, not a session that stays open
  across midnight. The streak is touched only by the one completion path every
  sign-in goes through (§7.3). Sessions last at most eight hours, so someone
  who uses the portal daily signs in daily.
- **Missing the deadline restarts at 1**, on the day of the sign-in that missed
  it. `longest` keeps the best run and `total_days` counts every day that ever
  counted.

Why thirty hours: a day plus slack. It means *the same time tomorrow, with six
hours to spare*, so starting an hour later than yesterday is not a failure,
and starting a whole working day later is.

### 10.4 What thirty hours does not promise (D13)

A's spec justified the window with this sentence: *"Thirty means a sign-in at
any time on one day is always in range from a sign-in at any time on the day
before, with six hours to spare."* It reads well and it is false. A sign-in at
00:30 on Monday followed by one at 23:30 on Tuesday is **47 hours** apart, well
outside 30.

What the window actually guarantees is narrower: a sign-in at clock time *h*
covers the following day from midnight until *h* + 6 hours. No hour-based
window can make A's sentence true without also letting people skip a day:
"any time Monday" to "any time Tuesday" can be almost 48 hours apart, and a
48-hour window also accepts 23:00 Monday followed by 22:00 Wednesday —
Tuesday skipped entirely. The alternative, a calendar rule ("sign in on
consecutive local days"), gives anywhere from about 24 hours to just under 48
depending on when you happened to sign in, and still needs all the
protected-day machinery below.

So the design keeps the rolling window and **never states a rule of thumb**.
The dashboard always shows the exact deadline, in the portal's time zone, named:
"keep it going — sign in before Tue 6:30 AM". The rules line says what is true:
"within 30 hours of your last sign-in, plus protected days". And the anchor on
the most recent sign-in softens the 00:30 case in practice: whoever signs in at
00:30 Monday and again at 09:00 has until 15:00 on Tuesday.

### 10.5 Protected days, and how they merge into blocks

A **protected day** is a whole local calendar day on which nobody is expected
to sign in. By default that is every Saturday and every Yom Tov (§10.12). The
decision belongs to one function — `isProtected(day) → { protected, names }`
— which is the only part of the engine that knows anything about a calendar
(§10.14).

Consecutive protected days form a **block**. Blocks need no special case: the
deadline counts protected days one by one, so a three-day block is simply
three days, and a festival adjacent to Shabbos merges with it without anybody
writing code for "a festival adjacent to Shabbos".

Two deliberate simplifications:

- **Whole days, not sunset to nightfall.** Shabbos actually runs from Friday
  sundown to Saturday nightfall. Protecting by the minute would need every
  person's location and an astronomical calculation, and would be far harder to
  verify. The model protects the Saturday calendar day and treats Friday evening
  and Saturday night as ordinary time; the six hours of slack and the re-entry
  grace (§10.7) absorb the difference.
- **Protection excuses absence; it does not forbid presence.** A sign-in on a
  protected day — after Shabbos on Saturday night, or by someone who does not
  observe it — counts like any other.

### 10.6 The deadline, solved to a fixed point

The answer feeds back into the question: extending the window for a protected
day can bring *another* protected day inside it, which extends it again. So the
deadline is found by iteration. With `H` an hour and `D` 24 hours, both in real
milliseconds, and days in the portal's time zone:

```
lastDay  = localDay(lastAt)
anchor   = lastAt
if maxLeewayDays > 0 and isProtected(lastDay):   // signed in DURING a protected block
    end     = the last day of that block (at most maxLeewayDays days long)
    anchor  = firstInstantOf(end + 1)             // the window opens when the block ends
    lastDay = end
base     = anchor + windowHours·H
hardCap  = lastAt + windowHours·H + maxLeewayDays·D + graceHours·H   // nothing can exceed this
deadline = base
repeat at most 8 rounds:
    endDay = localDay(deadline)
    count  = number of protected days d with  lastDay < d ≤ endDay
    closed = the latest protected d with lastDay < d < endDay whose next day
             is NOT protected — a block that ends inside the window — or none
    next   = base + min(count, maxLeewayDays)·D
    if closed and graceHours > 0:
        next = max(next, firstInstantOf(closed + 1) + graceHours·H)   // §10.7
    next   = min(next, hardCap)                                         // §10.8
    if next == deadline: stop                                           // converged
    deadline = next
```

Read it term by term:

- **Days strictly after the sign-in's own day** are counted. A day you signed in
  on needs no excuse — and if that day was itself protected, the window does
  not start until the block ends (below).
- **Each protected day adds 24 real hours**, up to the leeway cap
  (`streak_max_leeway_days`, default 4). A day of protection is a day of
  opportunity given back, which is the same thing B called "adding protected
  time back to the window": for whole days, the two formulations agree.
- **It terminates.** Each round can only add days, so `next` never decreases;
  it is bounded by the hard cap; and there is a round limit regardless. With the
  default calendar, every sign-in over several years converges within five
  rounds.

**A sign-in during a protected block opens the window when the block ends.**
B's formulation — the clock does not run in protected time — matters here.
Counting only days *after* the sign-in's own day, with the window anchored on
the most recent sign-in, has a trap: sign in at 11:30 PM on Friday and the
deadline is 5:30 AM Monday; sign in again at 12:10 AM — now Saturday, a
protected day — and a plain 30-hour window from there ends at 6:10 AM
**Sunday**. A later sign-in would have *cost* a day. An early draft of this
design shipped exactly that, and a sweep over every half hour of two years
found 146 such cases, all sign-ins made on protected days.

So when the sign-in's own day is protected, the window starts at the first
instant after that block (midnight, in the day model), and the block's days are
not counted again as leeway. Saturday 12:10 AM and Saturday 9:00 PM both open
the window at midnight going into Sunday and run to 6:00 AM Monday. The
invariant is now unconditional and tested every half hour over two years on
three calendars: **a later sign-in never yields an earlier deadline.** The hard
cap is measured from the sign-in itself, so the late opening cannot widen it.

### 10.7 Re-entry grace

Leeway preserves the time of day: it adds whole days to "the same time
tomorrow plus six hours". If the last sign-in before a block was late in the
evening, the first deadline after the block lands in the small hours of the
morning after it. Sign in at 11 PM Thursday and leeway alone gives
**5:00 AM Sunday** — the person would need to be at a keyboard before dawn on
the first morning after Shabbos, or to have signed in on Friday, which in
winter is a short day ending mid-afternoon.

B's fix, adopted: **a re-entry grace after every block**
(`streak_reentry_grace_hours`, default 12). When a block ends inside the
window, the deadline is at least twelve hours after the first instant
following the block — noon on the first day back. The 11 PM Thursday sign-in
gets until **noon Sunday**. Nobody loses a run because a block ended twenty
minutes before their window did.

The grace only ever **lengthens** a window (it is a `max`), so it can never
take away time leeway gave. It is also what compensates for whole-day
protection: Friday is an ordinary day in the model, and the grace is the
cushion for the hours of it that are not.

### 10.8 The hard cap, and why it exists

```
hardCap = lastAt + windowHours·H + maxLeewayDays·D + graceHours·H   // defaults: 30 + 96 + 12 = 138 hours
```

The cap is **not for the calendar.** A real calendar with the defaults never
produces more than three consecutive protected days: Yom Tov on Thursday and
Friday into Shabbos, or Shabbos into a Sunday–Monday Yom Tov. The cap exists so
that a **bug** — in the calendar, the loop, a refactor, a corrupted setting —
cannot hand out unbounded leeway. That bug would read as a streak nobody can
ever lose, and it would generate no complaints at all, which is why nobody
would find it.

Keep `streak_max_leeway_days` **above** the longest stretch your calendar can
really produce. With the defaults that is three, so the default of four has one
day of room. Protect both weekend days *and* keep two-day festivals and the
longest real stretch becomes four (Thursday–Friday Yom Tov, then Saturday and
Sunday) — raise the cap to five. A closure longer than the cap ends streaks by
design; restore them afterwards (§10.18).

Real calendar data never reaches the cap, so a test suite built on real dates
will pass with the cap deleted — that mutation went undetected once (§15.8).
The cap is tested with an absurd calendar in which every day is protected.

### 10.9 Worked examples

Defaults throughout: 30-hour window, 12-hour re-entry grace, leeway cap 4,
Shabbos plus diaspora Yom Tov, portal zone America/New_York. Each row is
checked against the algorithm above.

| Last sign-in | In the way | Deadline | Window | Decided by |
|---|---|---|---|---|
| Tue 6 Jan 2026, 10:00 AM | nothing | Wed 4:00 PM | 30 h | the base window |
| Fri 9 Jan 2026, 10:00 AM | Shabbos | Sun 4:00 PM | 54 h | one day of leeway |
| Tue 7 Apr 2026, 10:00 AM | last days of Pesach, Wed–Thu | Fri 4:00 PM | 78 h | two days |
| Fri 2 Oct 2026, 10:00 AM | Shemini Atzeres on Shabbos, Simchas Torah on Sunday | Mon 4:00 PM | 78 h | two days |
| Wed 1 Apr 2026, 10:00 AM | Pesach Thu–Fri, then Shabbos | Sun 4:00 PM | 102 h | three days |
| Thu 8 Jan 2026, 11:00 PM | Shabbos | **Sun 12:00 PM** | 61 h | re-entry grace; leeway alone gave Sun 5:00 AM |
| Fri 9 Jan 2026, 11:00 PM | Shabbos | Mon 5:00 AM | 54 h | one day of leeway; the grace (Sun noon) adds nothing |
| Wed 1 Apr 2026, 11:00 PM | Pesach Thu–Fri, then Shabbos | Mon 5:00 AM | 102 h | three days of leeway |
| Sat 10 Jan 2026, 9:00 PM | the rest of Shabbos | Mon 6:00 AM | 33 h | the sign-in fell inside a block, so the window opens at midnight when it ends |
| Fri 6 Mar 2026, 10:00 AM | Shabbos, then clocks spring forward | Sun **5:00 PM** | 54 h | one day of leeway; reads 5 PM because the night lost an hour |
| Mon 5 Jan 2026, 12:30 AM | nothing | Tue 6:30 AM | 30 h | the base window: a sign-in at 11:30 PM Tuesday is 47 h later and starts again at 1 |

The first five rows are A's 30 / 54 / 78 / 102-hour table on real dates. The
two 11 PM rows are worth reading together, because an earlier draft of this
example said "11 PM **Friday** gives until noon Sunday". Run the arithmetic: 11
PM Friday's own window already reaches 5 AM Monday, so the grace has nothing to
add. It is 11 PM *Thursday* — the evening before the last ordinary day — where
leeway alone would land the deadline before dawn and the grace moves it to
noon. A sentence in a spec is not a property of the system (§16.36); the table
is checked, the prose was not.

### 10.10 Reading without rewriting

Showing someone their streak is a GET, and **a GET must not write.** Whether a
streak has lapsed is computed at read time by a pure function of the stored
row, the clock and the configuration. A lapsed streak *displays* 0 — with the
longest intact — while the stored row is left exactly as it was; the next
sign-in reconciles it.

Two reasons. A read that writes races with a concurrent sign-in and surprises
every cache and prefetcher that assumed GET was safe. And it destroys evidence:
if the lapse was the portal's fault — an outage, a clock that moved — the
untouched row and the day log are exactly what an administrator restores from.

The status the dashboard renders has one of six states, decided in this order:

| State | When | The dashboard says, for example |
|---|---|---|
| `none` | no streak row yet | "No streak yet — it starts with your next sign-in" |
| `held` | the last sign-in is recorded in the future (§10.15) | the stored count, "on hold" — nothing is judged |
| `lapsed` | now is past the deadline | 0, longest 12 — "sign in to start again" |
| `paused` | today is protected and has not counted | "Paused for Shabbos — safe until Sun 4:00 PM" |
| `at_risk` | today has not counted and less than 6 hours remain | "Sign in before 4:00 PM to keep your 12-day streak" |
| `active` | everything else | "🔥 12 days — sign in before Wed 4:00 PM" |

The status also carries the current and stored counts, longest, total days,
whether today has counted, the deadline as an instant and as local text, the
hours left, the names of today's protection if any, and the time zone. The
exact shape is CONTRACTS §7.4.

### 10.11 Time zones and daylight saving

- **One portal time zone decides what "a day" is for everyone** (`timezone`, an
  IANA name, default `America/New_York`; an unrecognised value reads as `UTC`).
  11 PM on the 17th in New York is the 18th in UTC; a UTC day boundary would
  split every evening in two.
- **Resolve an instant to a local day with `Intl.DateTimeFormat(…)
  .formatToParts` and an explicit `timeZone`**, then turn year, month and day
  into a day number arithmetically. Never do date arithmetic with `Date`
  objects and local offsets; daylight saving will eat a streak.
- **The first instant of a local day is computed, not assumed to be 00:00.** A
  spring-forward day is 23 hours long, a fall-back day 25, and in a few zones the
  clocks change at midnight, so 00:00 does not exist on that day at all. "First
  instant of the day" is the definition that survives all three.
- **Hours are real hours.** The window is 30 elapsed hours and each protected
  day adds 24 elapsed hours, so across a clock change the deadline's
  wall-clock time moves by an hour (the 5:00 PM row in §10.9). That is
  deliberate: the window measures opportunity in real time, a second code path
  for twice a year is not worth its bugs, and the dashboard shows the exact
  deadline anyway.
- **Changing the portal time zone** changes no stored instant, only where day
  boundaries fall. The next sign-in is judged under the new zone, and at most
  one boundary day counts differently. Change it rarely.
- People elsewhere see deadlines in the portal's zone, with the zone named. The
  portal's day is the company's day.

### 10.12 The Hebrew calendar, computed

Yom Tov dates move against the civil calendar every year. There are three ways
to know them, and two are traps:

- **An API.** A feature that silently stops protecting Yom Tov the day an API
  key lapses, a provider changes its format, or an outbound request fails, is
  worse than no feature: it fails without a sound, and the first anyone hears
  of it is someone losing a streak weeks later.
- **A lookup table.** Correct until it runs out, and then silently wrong.
  Somebody has to remember to extend it. That somebody will have left.
- **The arithmetic.** More work once, then correct forever with nobody touching
  it. This is the one.

The Hebrew calendar is entirely rule-based, and *Calendrical Calculations*
(Dershowitz and Reingold) gives the algorithm as pure integer arithmetic on
**fixed day numbers** (RD 1 is Monday 1 January 1 CE, proleptic Gregorian):

- **The epoch** is RD −1,373,427: 7 October 3761 BCE in the Julian calendar.
  This is the constant that was once written two days out (§10.13).
- **Leap years** follow the 19-year cycle: year *y* has a second Adar when
  (7*y* + 1) mod 19 < 7 — years 3, 6, 8, 11, 14, 17 and 19 of each cycle.
- **The new year** is computed from the *molad*, the mean lunar conjunction,
  counted in "parts" (1,080 to the hour), then moved by the postponement
  rules: Rosh Hashanah never falls on Sunday, Wednesday or Friday; a molad at or
  after noon postpones it a day; and two further rules about Tuesdays and
  Mondays keep every year to a legal length.
- **Month lengths** follow from the year's length: Marcheshvan and Kislev
  stretch or shrink by a day to absorb it.

No table, no network, no ICU at runtime. `Intl` can format a date in the
Hebrew calendar, but what it returns is a display string with month names that
vary by locale and ICU version, and not every runtime ships full ICU. Parsing a
display string is not an API to build on in production. It is, however,
perfect for a test (§10.13).

**What is protected** — Yom Tov, the days on which using a computer is
forbidden:

| Day | Hebrew date | Diaspora | Israel |
|---|---|---|---|
| Rosh Hashanah | 1–2 Tishrei | 2 days | 2 days |
| Yom Kippur | 10 Tishrei | 1 | 1 |
| Sukkos, first days | 15 (and 16) Tishrei | 2 | 1 |
| Shemini Atzeres | 22 Tishrei | 1 | 1, which is also Simchas Torah |
| Simchas Torah | 23 Tishrei | 1 | — |
| Pesach, first days | 15 (and 16) Nisan | 2 | 1 |
| Pesach, last days | 21 (and 22) Nisan | 2 | 1 |
| Shavuos | 6 (and 7) Sivan | 2 | 1 |
| **Total per year** | | **13** | **8** |

Plus every Saturday, named "Shabbos" when Hebrew holidays are on. The region is
`streak_region` (`diaspora` by default).

**What is deliberately not protected**: chol hamoed (the intermediate days of
Sukkos and Pesach), Purim, Chanukah, the fasts other than Yom Kippur (Tisha
B'Av, Tzom Gedaliah, the Tenth of Teves, the Seventeenth of Tammuz, Ta'anis
Esther), Rosh Chodesh, and minor days such as Tu BiShvat and Lag BaOmer. On all
of them people work and can sign in. **Only count days on which the activity is
genuinely impossible.** Protect more and the streak becomes generous to the
point of meaning nothing, and the cap starts deciding real cases. A workplace
that closes for chol hamoed adds those dates as extra protected dates (§10.14).

### 10.13 Verifying the calendar

> **Verify the calendar against an independent implementation, never against
> itself.**

The Hebrew epoch constant was once written **two days out**. Every festival
landed two days early — and every date was still a plausible autumn date. The
calendar was internally consistent and wrong about every single day. The only
symptom in the product would have been somebody losing a streak weeks later,
with nothing in any log to explain it. A test written against the
implementation's own output passes forever. What caught it were the two kinds
of check below: a comparison with an independent implementation, which
disagreed about every date, and structural invariants asserted over centuries.
(A credits the first and B the second; each is enough for this bug, and
neither is enough for every bug.)

**The independent implementation is free.** `Intl.DateTimeFormat` with
`calendar: 'hebrew'` is ICU's Hebrew calendar, in any runtime with full ICU:

```js
new Intl.DateTimeFormat('en-u-ca-hebrew', { timeZone: 'UTC',
  day: 'numeric', month: 'long', year: 'numeric' }).format(date)
// "15 Nisan 5786"
```

The test walks **every day of three centuries** and asserts that the
arithmetic's year, month and day agree with ICU's, mapping the month names
(ICU says "Tishri" and "Heshvan"; the code says Tishrei and Marheshvan) in the
test, never in production.

**Then assert the structural invariants**, over the same centuries. They encode
*why* the postponement rules exist, so they fail loudly when a rule is
dropped:

- Rosh Hashanah never falls on Sunday, Wednesday or Friday.
- Pesach (15 Nisan) never falls on Monday, Wednesday or Friday.
- Yom Kippur is exactly nine days after Rosh Hashanah, and never falls on
  Friday or Sunday — never adjacent to Shabbos.
- Every year is one of six lengths: 353, 354, 355, 383, 384 or 385 days.
- Leap years follow the 19-year cycle.
- Two anchors: 1 Tishrei 5786 is 23 September 2025; 15 Nisan 5786 is 2 April
  2026.

**Notice which checks catch which bug.** A constant offset preserves every
*difference*: year lengths, the nine days from Rosh Hashanah to Yom Kippur, the
leap cycle — all still pass with the epoch two days out. What fails is
everything *absolute*: the weekday rules (Rosh Hashanah starts landing on
Sundays), the anchors, and ICU on every date. A dropped postponement rule is
the opposite: dates near the anchors may still look right, but illegal year
lengths appear. You need both kinds. Every rule-based calendar has equivalent
invariants; find them and assert them.

### 10.14 The protected-day function is swappable

The engine asks one question — is this local day protected, and what is it
called? — and the answer comes from a function built from configuration:

```
makeProtectedDayFn({ weeklyDays, hebrew, israel, extraDates })
    → (day) → { protected: boolean, names: string[] }      // memoised
```

| Setting | Default | What it does |
|---|---|---|
| `streak_weekly_days` | `[6]` | weekday numbers, 0 = Sunday, protected every week |
| `streak_hebrew_holidays` | on | add Yom Tov (§10.12) |
| `streak_region` | `diaspora` | which Yom Tov schedule |
| `streak_extra_dates` | `[]` | up to 366 `{ date: "YYYY-MM-DD", label }` entries |

The same mechanism serves any other workplace by changing data, not code:

| Workplace | Configuration |
|---|---|
| Observant, outside Israel (the default) | `[6]`, Hebrew on, diaspora |
| Observant, in Israel | `[6]`, Hebrew on, `israel` |
| A Sunday sabbath | `[0]`, Hebrew off |
| A Friday day of rest, or a Friday–Saturday weekend | `[5]` or `[5, 6]`, Hebrew off |
| Nobody works weekends | `[0, 6]`, Hebrew off — and keep the cap above the longest stretch your closures create |
| A plant shutdown, an office move, national holidays | extra dates, each with a label the dashboard shows |
| No protection at all | `[]`, Hebrew off: a plain 30-hour window |

Another rule-based calendar is a new function behind the same interface, with
its own independent cross-check and invariants; the engine does not change.
Observances fixed by sighting rather than arithmetic are better entered each
year as extra dates than computed and wrong.

### 10.15 Recording a sign-in

`touchStreak` runs inside `completeSignIn`, after the session exists, and
nowhere else:

- **No row** → current, longest and total are 1; the started day and last
  day are today; the anchor is now.
- **The stored anchor is unreadable** → restart at 1, keep the longest, and
  report it so the sign-in path audits `streak.error`. For a streak, the
  restrictive reading is the one that does not invent a run we cannot prove;
  the audit row is the evidence an administrator restores from.
- **The stored anchor is more than five minutes in the future** — a clock moved,
  or a backup was restored — **hold**: change nothing. Treating it as expired
  punishes the person for our clock; treating it as valid forever invents a
  streak. Neither; wait for real time to catch up.
- **Same local day as the last counted day** → only move the anchor forward to
  the later of the two instants.
- **A later day** → if now is at or before the deadline computed from the
  stored anchor, `current + 1`; otherwise restart at 1 with today as the
  started day. Either way update longest, add one to total days, set the last
  day to today and the anchor to now, record today in the day log, and prune
  that person's day log older than 400 days in the same batch.

**Concurrency.** Two sign-ins at once — a laptop and a phone — must not count a
day twice. The update is conditional on the last day it read (`… WHERE user_id
= ? AND last_day IS ?`); if no row changed, another sign-in won, so re-read
and treat this one as same-day. The first insert is `ON CONFLICT DO NOTHING`
followed by a re-read. No read-then-write race, no double counting.

### 10.16 Never let a streak block a sign-in

A streak is decoration on the critical path. All of `touchStreak` is wrapped:
any failure is logged and the function returns nothing, and the sign-in
proceeds. **The worst a streak failure may do is fail to count today.** It runs
after the session has been created, so nothing it does can stop one being
issued.

The test for this **drops the `streaks` table entirely** and asserts that a
sign-in still succeeds end to end. That is the right shape of test for any
non-essential subsystem hanging off a critical path.

### 10.17 What the dashboard shows

The dashboard leads with the streak:

- **the flame and the count**, and the longest run;
- **the state in words** (§10.10) — never only a colour;
- **the exact deadline** in the portal's time zone, with the zone named;
- **"Paused for Shabbos"** (or the festival's name) when today is protected;
- **a twelve-week history strip**: each day counted, protected, missed, today,
  or still to come, so a reset is explained by the picture rather than argued
  about;
- **coming up**: the protected days in the next three weeks, with their names,
  so nobody is surprised by a festival;
- **the rules in one sentence**, generated from the configuration — window,
  protected days, re-entry grace — never a rule of thumb (§10.4);
- **the leaderboard**, if the setting allows: the ten longest current streaks,
  with names, current and longest.

**The leaderboard publishes who signs in and how regularly**, which is
information about colleagues that some workplaces will not want shared.
`streak_leaderboard` is `all` (the default), `managers` — shown only to people
who can already see others' streaks, through `team.view` or `streaks.view_all`
— or `off`. An unrecognised value reads as `off`: when in doubt, publish
nothing.

### 10.18 The admin view, and restoring a streak

Managers see their reports' streaks (`team.view`); auditors and administrators
see everyone's (`streaks.view_all`). The day log behind the history strip is
the evidence for "why did my streak reset?"

`streaks.manage` (a dangerous permission, so it needs a step-up) can set a
person's current and longest counts, with a **reason**. The write is audited
as `streak.adjust` with an undo snapshot of the prior row (undo kind `streak`),
so a mistaken restore is itself revertible by a Super Admin (§11.4). Use it
after a portal outage, a clock problem, a closure longer than the leeway cap,
or a calendar bug found after the fact.

### 10.19 Testing the streak

- **The arithmetic is pure.** The deadline and the status are functions of a
  row, a clock and a configuration: test them with tables, including every row
  of §10.9.
- **Invariants over large ranges**, every half hour for several years in the
  portal zone: the deadline is never before the base window and never after
  the hard cap; the loop converges before its round limit; and a later
  sign-in never yields an earlier deadline — on every half hour, protected
  days included (§10.6 tells how that invariant was once false).
- **The cap**, with a calendar on which every day is protected. Delete the cap
  and this must fail.
- **Daylight saving**, with windows across both transitions in the portal zone
  and in a zone whose clocks change at midnight.
- **End to end**: a sign-in on a new day counts; two on the same day count once;
  two concurrent ones count once; a stored anchor in the future holds; and the
  dropped table does not stop a sign-in.
- **When a test fails, check the expectation first.** Several streak failures
  in A's work were the test's arithmetic: a "regular week" that
  happened to contain a festival, an expected deadline computed in UTC instead
  of the portal zone.

*Provenance: the 30-hour window, counting a day once, the day-counting fixed
point, the leeway cap, read-without-rewriting, time-zone handling, computing
and cross-checking the calendar, the drop-table test and the clock hold are A
§10, §11 and §14.10; protected periods merging into blocks, re-entry grace,
the arithmetic Hebrew calendar instead of an API, swappable observances and the
two-days-out epoch story are B §8 and trap 7; the hard cap, the D13 correction,
the six states, the dashboard, the leaderboard setting and the admin restore
are this design (D12, D13).*

---

## 11. The audit log

It is the table the whole system is judged on. Every meaningful action writes
a row, and the log has to be three things at once: **complete** enough to
answer "what happened?", **tamper-evident** enough to trust the answer, and
**useful** enough to put things back.

### 11.1 What a row holds

Who (actor id and label), what (a dotted action name from one fixed list —
`user.suspend`, `network.allow.remove`, `mfa.passkey.add`, …), to whom (target
type and id), from where (address), on which device, in which session (the
first twelve characters of the stored session hash), the state before and
after, an outcome (`success`, `failure` or `denied`), a severity (`info`,
`notice`, `warning`, `critical`; by default success is info, denied is notice
and failure is warning), one human sentence of detail, the real error if there
was one, and — for revertible actions — an undo snapshot.

**Who writes it.** Domain functions enforce their guards and return the prior
state; the **API handler** writes the audit row, including the undo snapshot
built from that prior state. That way a reverter can call the same domain
function without writing a second row. Four events are audited by the domain
function itself, because no caller could know they happened: an authenticator
secret that will not decrypt, an unreadable replay floor, a passkey counter
that went backwards, and a backup code being spent.

**The writer never throws.** A logger that can break the operation it reports
on is worse than none: `audit()` resolves to the new row's id or to nothing,
whatever happens inside it.

### 11.2 The hash chain

Each row's hash covers the previous row's hash and the row's own content:

```
hash = SHA-256( prev_hash + "\n" + canonicalJson(every column except id and hash) )
```

The first row chains from 64 zeros; `seq` is unique and gapless; canonical JSON
has sorted keys and one spelling for every value, so the same row always hashes
the same way. Text is cleaned before it is stored — a lone surrogate cannot
survive UTF-8 and a NUL is not safe in every driver — because a value that
comes back from the database a byte different would make an honest row "break"
the chain. A new row is inserted only if the head has not moved since it was
read; two writers racing for the same position cannot both win, and the loser
retries.

**Verify** recomputes the chain from the first row, in pages, and reports
either *intact across N rows* or the first row where it stops matching. That
is the difference between a log and an audit log: editing or deleting any row
breaks every hash after it.

Be precise about what that proves. A chain detects a row edited, deleted or
inserted *in the middle*. It does not detect the tail being cut off — what
remains is still a valid chain — nor a wholesale rewrite by someone with write
access to the database who recomputes every hash. Both are answered the same
way: **keep an anchor outside the system.** Note the head sequence number (and
its hash) somewhere else now and then — a ticket, an email, a printed report —
and a later verification that does not reach that head, or reaches it with a
different hash, proves loss.

### 11.3 Record the real failure

When a write path catches an exception, the person gets a polite sentence —
and **the real error goes into the audit log** at critical severity, with its
name, message and first stack frames.

This is the single highest-value habit in the codebase. The original
"create user" in B's system caught its exception, sent it to `console.error`
and returned "That account could not be created." The audit log recorded the
polite version. Diagnosing it took a deploy whose only purpose was to make the
error visible, after which the cause — the PBKDF2 ceiling — was obvious in one
request. Write it correctly the first time: every write path's `catch` calls
`auditError` with the exception. Anything that escapes to the worker becomes a
500 with "Something went wrong." and the same audit call.

### 11.4 Undo: one catalogue

Record the undo snapshot **at write time**: the prior state, enough to put it
back. That is what makes an entry revertible later; without the snapshot a
removal is unrecoverable.

A's first implementation recorded snapshots for **21 action kinds** and could
revert **12**. The console offered a Revert button whenever a snapshot existed,
so for nine kinds it answered "Unknown undo type" — under a heading that
promised anything which changed state could be reverted. Do not reproduce that.
**The kinds that record an undo and the kinds that can be reverted are one set,
enforced:** `undo.js` lists the kinds and refuses to record any other;
`reverters.js` exports one object, `REVERTERS`, whose keys must equal that list
or the module throws at import; and a test scans the source for every
`undoFor('…')` call and checks its kind. The console offers Revert from a
`revertible` flag computed from that catalogue, never from "this row has an
undo payload".

| Kind | Snapshot | Revert does |
|---|---|---|
| `user.status` | prior status | set it back — rank, self and last-Super-Admin guards |
| `user.role` | prior role, grants, denies | change it back — rank, minting, grant and last-Super-Admin guards |
| `user.temp_role` | prior grant, or none | restore it, or revoke it |
| `user.profile` | prior values of the fields changed | write them back |
| `device.status` | prior status | set it back |
| `device.label` | prior label | rename it back |
| `network.allow.add` | the new entry's id | remove it — through the anti-lockout guards |
| `network.allow.remove` | the removed row | re-add it — through validation |
| `network.allow.edit` | prior tier, label, owner, person, expiry | edit it back — guards |
| `network.block.add` | the new block's id | remove it |
| `network.block.remove` | the removed row | re-add it — the self-block guard applies |
| `setting` | the prior raw value | write it back through validation and the self-lockout guards; never recorded for the gate switch |
| `mfa.reset` | the cleared authenticator (still encrypted), passkeys, backup codes and grace windows | restore them — refused if anything was enrolled since |
| `role.create` | the new role's id | delete it — refused while anyone holds it |
| `role.edit` | prior name, rank, permissions, description | edit it back — reserved and minting checks |
| `role.delete` | the deleted row | recreate it with the same key |
| `streak` | the prior streak row, or none | restore it, or delete it |
| `destination.add` | the new destination's id | remove it — never the last usable factor |
| `destination.remove` | the removed row | re-add it |

**Not revertible, by design:** sign-ins (there is nothing to put back);
password changes and resets (restoring an old hash restores a credential that
may be the reason for the change); session revocations (reviving a session
revives a credential); invitations (revoke or reissue instead); opening or
closing the gate (a revert could reopen what someone just closed); and reverts
themselves.

### 11.5 A revert is a new action, with the same guards

A revert is itself an action and runs **every guard the original ran**, because
it calls the same domain function. Restoring a recorded state writes roles,
grants and denies straight back; if reverting skipped the guards, anyone able
to revert could undo their own demotion. Undoing an *add* is a *removal*, so it
passes the same anti-lockout checks as any removal (§12).

The revert is recorded as a **new row**, `audit.revert`, pointing at the
original by `reverts_id` (D10). A's design marked the original row as reverted
in place — which a hash chain forbids, since changing any row breaks every hash
after it. So "reverted" is **derived**: an entry is reverted if some later row
reverts it, and the console shows by whom and offers no second revert.
Reverting is reserved to Super Admins (`audit.revert`) and is a dangerous
action, so it needs a fresh step-up.

### 11.6 Scrubbing, and what is never returned

- Before- and after-state are **scrubbed** on the way in: any key matching
  `/pass|secret|token|hash|salt|code|cookie|session/i`, at any depth, is
  dropped. That is deliberately over-broad: losing an innocent field called
  `postcode` is cheaper than storing one credential.
- The undo snapshot is **not** scrubbed — it must be able to restore what it
  recorded, and the `mfa.reset` snapshot holds an encrypted authenticator
  secret — so **it is never returned by any API.** Only the revert endpoint
  reads it. B's adversarial review found exactly this class of bug: a token
  readable by a role that was supposed to be read-only.
- Each person can read their own last fifty rows on their activity page,
  without undo data.
- Size caps keep one row from bloating the table: 16 KiB for each state
  column, 512 KiB for an undo snapshot (a larger one is not stored, and the
  entry is not revertible).

### 11.7 Reading it

Filter by action, actor, target, outcome, severity and free text; page by
sequence number, never by offset, because the table only grows. It is never
trimmed (§13.4) — the chain verifies from the first row.

*Provenance: undo snapshots at write time, the single REVERTERS catalogue, and
revert-as-an-action are A §9 and §14.9; the hash chain, verification, real
errors, scrubbing, outcome and severity, revert as a new row and revert
re-running guards are B §7 and traps 2 and 5; derived "reverted", never
returning undo data, and the external anchor are this design (D10).*

---

## 12. Self-lockout guards

Every security setting is also a way to lock yourself — or the owner — out. A
change can be answered three ways, and getting the line between them right is
the difference between a guard rail and a wall.

**Blocking** — refused with `409 { code: 'self_lockout' }` and a sentence that
says what to do instead:

| Change | Refused when |
|---|---|
| remove an allowlist entry | it is the last live entry — an empty allowlist locks out everyone |
| remove, edit or expire an allowlist entry | afterwards, no live entry would cover the caller's own address — "add your new address first" |
| add a block | the range contains the caller's address |
| `country_allow` / `country_deny` | it would refuse the caller's country — unless the caller's address is allowlisted |
| `block_tor`, `block_datacenter`, `block_automation` | the caller currently trips it — unless allowlisted |
| `risk_threshold` | it is at or below the caller's current score — unless allowlisted |
| `access_mode: lockdown` | the caller is not a Super Admin on an allowlisted address |

The same principle runs through the account guards described elsewhere: the
last Super Admin (§5.5), acting on yourself (§5.5), the last factor and the
admin reset with nothing left (§7.8), the only usable code destination
(§7.6).

**"Live" means not expired.** An expired allowlist entry grants nothing, so
counting one as cover waves through the exact removal the guard exists to stop.

**Auto-approve** — the change goes ahead and fixes the one thing that would
otherwise lock the caller out: enabling device gating, or switching to
`allowlist`, `invite_only` or `lockdown`, approves the caller's current device
in the same request and says so (§8.4).

**Warnings** — saved, with a sentence: changes that cost only *other people's
next* sign-in, and that someone can fix. Enabling device gating or a
restrictive mode while N active people have no approved device and no
allowlisted address; requiring a second factor while N active people have
none. Refusing these would make the settings impossible to change; staying
silent would surprise N people tomorrow.

Three more rules:

- **The guards are one module**, called by the settings and network endpoints
  *and* by the reverters, so undoing an "add" cannot do what a "remove" may
  not.
- **An allowlisted address legitimately bypasses the edge rules** (§3.1), so
  the country, Tor, datacenter, automation and risk guards will *appear* not to
  fire when you test them from an allowlisted address. That is correct
  behaviour, not a bug; test them from somewhere else.
- **Opening the gate is not guarded this way** — it cannot lock anyone out —
  but it is reserved, time-boxed and audited (§8.8).

*Provenance: B trap 8 (blocking against warnings, the country and threshold
guards, the allowlisted-bypass note); A §4 and §5 (the last entry, covering
your own address, "live" means unexpired, auto-approving the enabling
device).*

---

## 13. Operating it

The part that is easy to leave until it bites.

### 13.1 Schema creation and migration

With no build step and no migration tool, the schema is created
**idempotently on demand**: a batch of `CREATE TABLE IF NOT EXISTS` and
`CREATE INDEX IF NOT EXISTS`, run once per isolate before the first query. It
is cheap, safe to repeat, and a fresh database needs no separate step. A
failure is not remembered, so the next request retries rather than serving from
a half-made schema. A version stamp goes into `meta`.

Evolving it is the awkward part, because `IF NOT EXISTS` does not add a column
to a table that already exists. So there is a short list of forward-only
statements that are allowed to fail ("already applied"):

```js
export const MIGRATIONS = [
  // 'ALTER TABLE users ADD COLUMN pronouns TEXT',
  // APPEND ONLY. Never edit or reorder a line that has shipped.
];
```

Ugly, and correct for a system this size. Two rules. **Append only**: editing a
line that has already run in production does nothing there and silently
diverges your environments. **Never destructive**: dropping or rewriting a
column is a deliberate, manual, backed-up operation, not something in a list
that runs on every cold start.

System roles are re-seeded from code on every cold start (§5.1); custom roles
are never touched.

### 13.2 When the settings cannot be read

Every read of a setting has a default for *absent* and a separate,
**restrictive** value for *present but unrecognised*. If the settings table
itself cannot be read, every key resolves to its restrictive value at once —
which means `lockdown`: only a Super Admin, on an approved device, from an
allowlisted address, gets in. That is the intended failure.

| Setting | Unrecognised reads as |
|---|---|
| `access_mode` | `lockdown` |
| `gate_open` | closed |
| `country_allow` / `country_deny` | allow none / deny all |
| `block_tor`, `block_datacenter`, `block_automation` | on |
| `risk_threshold` | 50 |
| `mfa_policy` | `required` |
| `mfa_grace` | off |
| `device_gating` | on |
| `step_up_minutes` / `session_idle_minutes` | 5 / 30 |
| `timezone` | `UTC` |
| `privacy_notice` | on |
| `streak_leaderboard` | `off` |

(Streak calendar settings fall back to their defaults: for decoration there is
no "safe" direction, only the documented one.) Going the other way, a blank
string, `null`, a boolean or an object *submitted* as a value is a validation
error, never a default; an explicit `0` stays legal where the range allows it.
The full registry is CONTRACTS §5.

### 13.3 Secrets, and rotating them

Three secrets, each at least 32 characters (generate 48 random bytes):

- **`SESSION_SECRET`** signs device cookies, half-finished sign-in tokens,
  fingerprint cookies and invitation pass cookies.
- **`DATA_KEY`** derives the AES-GCM key for secrets stored at rest — today,
  authenticator secrets. **Never the same value as `SESSION_SECRET`.**
- **`SETUP_KEY`** guards the one-time bootstrap.

If `SESSION_SECRET` or `DATA_KEY` is missing or short, every request except
`/healthz` gets an empty 503 and the reason goes to the log. Secrets live in
the platform's secret store (`wrangler secret put`) and, for local
development, in `.dev.vars`, which is ignored by git — never in
`wrangler.jsonc` and never in the repository.

**Why two.** A's portal had one secret that signed everything *and* derived the
encryption key, so rotating it did four things, and A's own warning was that
the fourth would ruin an afternoon: every stored authenticator secret becomes
undecryptable, a correct implementation refuses those rows rather than treating
them as "no factor", and every enrolled person is pushed onto their fallback at
once. Separating the keys keeps the cheap rotation cheap.

| Rotate | What happens |
|---|---|
| `SESSION_SECRET` | Device cookies stop verifying: every browser reads as a new, pending device. Anyone who passes the gate only through an approved device — not an allowlisted address — is a stranger again, and in `allowlist`, `invite_only` or `lockdown` sees nothing until they reach an allowlisted network or the gate is opened. Grace windows are per device, so everyone owes a factor. Half-finished sign-ins and invitation passes fail and are retried; fingerprints are re-reported on the next page load. Session cookies are random tokens looked up by hash, not signatures (D16), so the rotation does not itself invalidate them. **Annoying and recoverable**: rotate from the office, or open the gate for an hour. |
| `DATA_KEY` | **Every authenticator app stops working.** Each row is refused and audited as `mfa.decrypt_failed`; people fall back to passkeys, backup codes (hashed, so unaffected) or sent codes, and anyone with nothing else needs an admin factor reset. Do not rotate it without re-encrypting every row under the new key — an operation this design does not yet include (Appendix C). The `v1.` prefix on every blob is what will let that migration tell the generations apart. |
| `SETUP_KEY` | Nothing; it is used only while no account exists. Delete it after setup. |

### 13.4 Retention (D18)

There is no scheduled job, and none is needed. **Each table that accumulates
is trimmed in the same batch as the write that creates the pressure**, so the
work is spread across normal traffic and the tables stay small by
construction.

| Table | Trimmed by | Rule |
|---|---|---|
| `auth_attempts` | charging an attempt | older than 1 day |
| `visits` | recording a visit | older than 30 days; newest 50,000 kept |
| `fingerprints` | recording a fingerprint | last seen over 90 days ago; newest 20,000 by last seen kept |
| `webauthn_challenges` | issuing a challenge | expired |
| `otp_challenges` | sending a code | expired more than a day ago |
| `sessions` | creating a session | absolute-expired or revoked more than 7 days ago |
| `devices` (pending only) | minting a device | pending and unseen for 30 days; at most 2,000 pending |
| `streak_days` | recording a sign-in | that person's days older than 400 (the strip shows 84; a year of evidence for restores) |
| `audit_log` | **never** | paged in the console; the chain verifies from the first row |
| `allowed_ips` | **never** | expired rows are kept for the record and excluded by queries |

A said the audit log grows forever and B said trim everything that grows;
both, applied to the right tables. Two notes. A table keyed by a hash of
client-chosen input is trimmed by **time and count**, never by id (§16.34).
And a growing table is not only a storage cost: filling the database breaks
*every* write in the system — sessions, audit, rate-limit counters — so an
untrimmed table reachable without signing in is an outage waiting for a loop.

### 13.5 Debugging the empty 403

The decision in §1.1 has an operational cost: from outside, an empty response
is indistinguishable from an outage. Give yourself, and the people using the
portal, the means to tell them apart:

1. **`/healthz`** answers `ok` before the gate does anything. If it answers and
   everything else is empty, the gate is working and you are not trusted from
   here. If nothing answers, it is an outage.
2. **An empty 503** means a secret is missing (§13.3).
3. **The visit log** records every refusal with the address, country, network
   and a machine reason (`not_allowlisted`, `country`, `tor`, `risk`, …). It
   is the first thing to look at for "was it me?" — from somewhere the portal
   does trust, or by asking a colleague who is in the office.
4. **A decoy 404 makes this harder.** If you chose `deny_style: decoy`, write
   that down where the team will look, because a refused administrator will
   otherwise conclude the site is gone.
5. **`/api/diag`**, from the pending page, says what the browser actually sent
   (§8.6).

And tell people what to expect, in writing, somewhere they can reach from a
phone: "The staff portal shows a blank page when you are not on an approved
network or device. That is normal — contact …" saves a lot of calls.

### 13.6 What must never be logged

Anywhere — the audit log, `console.log`, an error message:

- anything that *is* a credential: session tokens, device and pass cookie
  values, half-finished sign-in tokens, invitation tokens (log a short prefix
  if you need correlation);
- passwords, authenticator secrets, backup codes and one-time codes —
  **including on the failure path**, where the temptation is strongest;
- the contents of a WebAuthn assertion;
- undo snapshots, anywhere but the audit table.

Log freely: email addresses and usernames, the *reason* something was refused,
which factor was used, addresses, and device ids — those are inventory labels,
not secrets; the signed cookie carrying one is.

### 13.7 Races and clocks

- **Per-person singleton rows** use `INSERT … ON CONFLICT DO UPDATE` or an
  update conditional on the value just read — never read-then-write. The
  streak (§10.15), the audit chain's head (§11.2) and the setup claim (§6.6) all
  depend on it.
- **One clock.** Every module reads time from `util.now(env)`, never
  `Date.now()`. Tests inject `env.__clock`, a function; configuration
  variables are always strings, so production can never set it.
- **Store UTC ISO 8601 from one formatter, and compare timestamps as strings in
  SQL only when both sides came from it.** `…T15:00:00.000Z` and `…T15:00:00Z`
  are the same instant, but `.` sorts before `Z`, so mixing the two spellings
  orders instants wrongly — an expiry check that is wrong by up to a second, in
  either direction.
- **A stored timestamp in the future** means a clock moved or a backup was
  restored. Do not treat it as expired and do not treat it as valid forever;
  decide explicitly for each use. The streak holds (§10.15); a step-up allows
  one minute of skew (§7.9).
- If you ever **generate a secret on first use** instead of injecting it, write
  it with `INSERT OR IGNORE` and re-read: two cold starts can race, and both
  must end up with the same value.

### 13.8 Backups

D1 holds the only copy of who may get in. Know what its point-in-time restore
(Time Travel) covers on your plan, and **test a restore once, before you need
it**; `wrangler d1 export` gives a dump you can keep off the platform.

A restore rewinds sign-in state as well as data: sessions, grace windows,
device approvals, used backup codes and **spent authenticator counters** go
backwards, so a restored database can accept a code that was already used. That
is usually acceptable; know that it is true. A restore rewinds the audit log
too — and the chain still verifies, because what remains is a prefix of the
old one. If the trail must survive a restore, export it and keep the external
anchor (§11.2).

*Provenance: A §11 (migrations, rotation, pruning in the write, never-log,
the empty 403, races and clocks, backups); B traps 2 and 6 and B §3 (settings
in a table); the two-secret split, the restrictive-readings table and D18 are
this design.*

---

## 14. Deployment traps

Deployment configuration ate more time than the code. Every item here actually
happened, and each cost at least one deploy cycle.

### 14.1 Its own directory, its own lockfile

Keep the portal in its own directory with its own `package.json`,
**lockfile**, `wrangler.jsonc`, worker name, database and assets — even in a
repository that also holds the marketing site. If the build runs `npm ci`, it
fails outright without a lockfile. Commit it.

### 14.2 A root directory or `--config`, never both

Point the build at the portal's directory with a "root directory" setting **or**
pass a config path. Doing both doubles the path
(`staff-portal/staff-portal/wrangler.jsonc`) and the build fails looking for a
file that exists.

### 14.3 Never repurpose another application's config

Renaming the marketing site's config to deploy the portal deploys the wrong
application under the portal's name and binds it to the wrong database. Each
deployable has its own config, written for it.

### 14.4 The config file replaces dashboard variables

Wrangler v4 **replaces** the deployed variable set with the `vars` in the
config file on every deploy. Any variable set only in the dashboard is silently
wiped by the next deploy. So every variable — `ORG_NAME`, `ORG_CODE`,
`RP_ID`, `ORIGIN`, `PBKDF2_ITERATIONS`, `MAIL_FROM` — lives in
`wrangler.jsonc`. Secrets are separate (`wrangler secret put`) and survive
deploys.

### 14.5 A retry rebuilds the same commit

A dashboard "retry" usually rebuilds the **same commit**, and build settings are
snapshotted when the build starts — so a fix that is already pushed, or a
setting already changed, can appear to do nothing. Trust the log line that
echoes the command actually run, not the settings page.

### 14.6 Local is more permissive than production

The defining example: **Cloudflare Workers refuses a single PBKDF2 derivation
above 100,000 iterations** —

```
Pbkdf2 failed: iteration counts above 100000 are not supported
```

— and `wrangler dev` does not enforce it. 210,000 iterations ran locally in 31
ms and were rejected outright in production, so every password write failed and
the first account could not be created. The chained hash (§6.1) is the fix; the
lesson is wider. Locally, `request.cf` holds placeholder values, and your
address is loopback, which the allowlist refuses — so setup must still succeed
when the caller's address cannot be allowlisted, relying on the device approval
it also performs. And locally the client address is only *defaulted*: the local
runtime sets `CF-Connecting-IP` to the loopback address unless the request
already carries one, so a local client can claim any address it likes. That is
handy — `curl -H 'CF-Connecting-IP: 81.2.69.142'` tests the gate as a public
visitor — and it means a local result about the gate says nothing about
production, where the edge overwrites the header. **A passing local run is
evidence, not proof.** Run the dry-run deploy on every change, and test in
production-like conditions before trusting a new crypto path.

### 14.7 The first deploy

- Replace the placeholder `database_id` (all zeros) with the one
  `wrangler d1 create` printed.
- Set `SESSION_SECRET`, `DATA_KEY` and `SETUP_KEY` before the first request, or
  every page is an empty 503.
- Keep `assets.run_worker_first: true`, `html_handling: "none"` and
  `not_found_handling: "none"` (§2.2). Without the first, the gate never sees an
  asset request.

### 14.8 One origin

- `ORIGIN` is the exact origin — scheme, host and port if any, no trailing
  slash — and `RP_ID` is its hostname. Writes from any other origin get an
  empty 403, and passkeys refuse other origins.
- **Changing `RP_ID` orphans every passkey**, because a passkey is scoped to its
  RP ID. Choose the hostname before anyone enrols.
- Serve the portal from its own subdomain on a custom domain, and turn off the
  `workers.dev` address and preview URLs (`"workers_dev": false`) so it answers
  on one origin only.
- For local development, override `ORIGIN` and `RP_ID` in `.dev.vars`
  (`http://localhost:8787`, `localhost`).

*Provenance: B trap 9, B trap 1 and B §11; the one-origin rules follow from
A §7.4's exact-origin check and the merged CSRF rule (§3.4).*

---

## 15. Testing

No test framework. Plain `.mjs` suites, a small assertion helper, one runner.
What matters is not the harness; it is these ideas, and together they found
most of §16.

### 15.1 Real SQLite, not a mock

Node ships `node:sqlite`. A small adapter exposes D1's interface —
`prepare().bind().first() / all() / run() / raw()`, `batch()` (atomic) and
`exec()` — over an in-memory database, so the tests run **the worker's own
schema and its real SQL**. A mock would have accepted every query this found
wrong. Normalise parameters the way the real binding does — `undefined` and
`null` become `NULL`, booleans become 0 and 1, anything unbindable throws — or
you will chase differences that are the adapter's fault.

### 15.2 Drive the real `fetch` handler

Not units: build a `Request`, set the client-address header the platform uses,
attach a `cf` object, call `worker.fetch(request, env, ctx)`, read the
`Response`, keep the cookies from `Set-Cookie` and send them on the next call.
One test client is one browser, with its own cookie jar, address and user
agent. A test then reads like the thing a person does:

```
sign in → enrol an authenticator → sign in again → assert no text was sent
```

That test *is* the feature. Assert the absence of the text by configuring **no**
SMS provider at all and recording every outbound call, so a regression cannot
pass by texting a stub. The injected clock (`env.__clock`, with helpers to set
and advance it) is how a test makes a streak lapse, a lock expire or a grace
window run out without waiting days.

**Test addresses must look public.** The allowlist rightly refuses the
documentation ranges (`203.0.113.0/24` and friends), so a test that "allowlists"
one fails for the right reason. Use addresses from real public allocations,
such as `81.2.69.0/24`, `91.198.174.0/24` or `185.15.56.0/24`.

### 15.3 Import the worker as it is

Every module imports its siblings with explicit `.js` specifiers, so plain
Node imports `worker.js` and every module directly — no build, no rewriting.
A's harness had to rewrite relative imports into temporary files from a
**hardcoded list**; the list went stale twice, and each time the worker gained
an import, two suites stopped running and **reported nothing rather than
failing**. If you ever need such a step, discover the specifiers from the
source, throw if one names a missing file, and throw if you find none. Never
widen a module's real exports just to reach an internal from a test.

### 15.4 A runner with three outcomes

`npm test` runs every `*.test.mjs` in its own process and distinguishes
**passed**, **failed**, and **did not report**. Every suite ends by printing
exactly one line, `N passed, M failed`; a suite whose imports broke prints
nothing and exits, and a runner that only looks for failures calls that
success. This one reports it as `DID NOT REPORT`, treats `0 passed, 0 failed` as
broken too, and exits non-zero for either. That is how the stale-import
breakage was caught both times.

### 15.5 Page scripts against a minimal DOM

Each page is an HTML file and one module script (§3.4). Load the script with a
tiny fake DOM and drive its real handlers: `getElementById`, `querySelector`,
element creation for the `h()` kit, `textContent`, `value`, `classList`,
`dataset`, `disabled`, attributes, listeners and `focus`; `location`,
`navigator.credentials` and the clipboard; and a `fetch` that records every
call and returns canned replies per URL.

- **Seed initial state from the real markup** — ids and `hidden` classes parsed
  from the HTML — or you are testing a starting state you invented.
- **Drain unawaited promises before asserting.** Pages correctly fire some work
  without awaiting it, so awaiting the handler is not enough; a dozen rounds of
  `setTimeout(0)` is.
- **Make a stubbed endpoint reflect sequence where it matters.** "Who am I"
  answers 401 before sign-in and 200 after; a stub that always says 401 looks
  exactly like the refused-cookie failure the page checks for, and every
  navigation assertion silently fails.

The cheapest high-value check in the suite: **every element id a script looks
up exists in the markup.** A lookup that returns `null` throws on the next line
and the page just stops — no error shown, nothing in any console a person can
see. Also check that every `<label for>` resolves and that no id is declared
twice, counting ids the script itself creates.

### 15.6 Static checks and the bundle check

Some properties cannot be proved by driving the handler. Assert them against
the source text: no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, inline
handler or `style=""` anywhere in `public/`; no `Date.now()` in `src/`; no
reserved permission in any system role; every `undoFor('…')` kind present in
`REVERTERS`. Coarse and brittle to refactors, and worth it for the handful of
properties where the alternative is no check at all.

**`npm run check`** bundles `worker.js` and every browser script with esbuild,
the way the platform will. It catches unresolved imports *and* missing named
exports across modules, which a syntax check does not. **`npm run dry-run`**
validates the config and bindings without shipping.

### 15.7 Invariants over large ranges, and hostile input

The worst bugs here were found by asserting what must **never** be true, over
ranges far larger than anyone would spot-check: the calendar against ICU for
every day of three centuries and its structural invariants (§10.13); the
streak deadline's bounds and convergence every half hour for years (§10.19);
address parsing and normalisation round trips.

Every module reachable from unauthenticated input is tested against
`[null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol()]`.
`Number(Symbol())` throws; `Number(obj)` runs arbitrary `valueOf`; one crafted
JSON field should never be one exception away from a 500 on the sign-in path.

### 15.8 Mutation-check your tests

**The one habit that matters most.** After writing tests, deliberately break the
code and confirm a test notices. If none does, the test is decoration. In A's
codebase this found:

- a base64url assertion that passed against a page emitting plain base64,
  because the test's bytes encoded identically in both alphabets;
- QR pad codewords that were never checked: swapping them changed 376 of 395
  output symbols and all 311 tests still passed;
- a mask tie-break that could be inverted, because no sample contained a tie,
  and a whole penalty rule that could be deleted;
- QR geometry that was essentially unverified — transposed axes, a dropped
  margin, swapped colours and mirrored rows all passed;
- the streak's leeway cap, removable without a failure, because real calendar
  data never reaches it.

The QR tests here therefore decode every generated symbol with an independent
decoder (jsqr) rather than trusting the encoder's own matrix, and the cap is
tested with an absurd calendar. When a mutation survives, you have learned
something specific about what your test measures. Fix the test, not the
mutation.

### 15.9 Assert absence, and suspect the test

- **Assert on absence**: no text was sent; no key material in this payload;
  exactly one new audit row. Positive assertions miss the regressions that
  *add* behaviour.
- **Treat a surprising failure as possibly the test's fault.** Several failures
  in this work were bad arithmetic in the test — a "regular week" that
  contained a holiday, an expectation computed in the wrong time zone. Check
  the expectation before changing the code.

### 15.10 Local runs, dry runs, and an adversarial review

Run it locally against D1's local SQLite and drive the real flows — setup,
sign-in, second factor, an admin call — then edit the local database between
requests (`wrangler d1 execute --local`) to make a streak lapse or a lock expire
on demand. Remember §14.6: local is more permissive than production.

Finally, **have something adversarial review the authentication paths before
trusting them.** On B's system an independent review found five real issues,
including a token readable by a read-only role and an unauthenticated path that
could fill the database. None was visible from reading the happy path.

*Provenance: A §13 (real SQLite, the real fetch handler, import discovery, the
DOM stub, the three-outcome runner, static checks, mutation-checking, absence,
suspecting the test) and B §11 (bundle check, dry run, local flows, database
manipulation, invariants, adversarial review); public-looking test addresses
are this repository's own lesson.*

---

## 16. The fail-open catalogue

Every entry below is grounded in one of the two systems this design merges, or
in the work of merging them. Most shipped, or were caught on the way out: they
read as correct code and made the system less safe or locked somebody out. The
rest are the specific hazards one of the sources wrote a rule against, told as
the failure the rule prevents. If you read nothing else, read this. The section
where the fix lives is given with each.

### Values that read as permission

#### 16.1 A missing value that selects the most permissive option

The gate switch stored `'1'` (open until closed), an ISO instant (open until
then) or `'0'` (closed), and the write path took a duration:
`const hours = Number(input.hours); if (!hours) return '1';`. `Number('')` is 0
and `Number(null)` is 0, so an empty form field, an absent JSON key or a
`false` all landed on the most permissive option in the set. A missing duration
should have been a rejection, not a blank cheque. (§8.8)

> **Rule.** Reject `null`, `undefined`, `''` and booleans explicitly, before any
> numeric coercion. A missing value is an error, never a choice.

#### 16.2 `Date.parse` accepts almost anything

The same setting could hold an instant, so its expiry check was
`Date.parse(stored) > Date.now()` — and `Date.parse('42')` is
2042-01-01T00:00:00Z. One stray digit in that column held the portal open to
the internet for sixteen years, and it would never have looked wrong: the
feature worked. (§8.8, §13.2)

> **Rule.** Require the shape with a regex before parsing a date, and make every
> unrecognised stored value mean the restrictive option: a corrupt row, a
> half-written value or a string from a future release means *closed*.

#### 16.3 Unreadable is not absent

The authenticator replay floor was `const floor = Number(row.last_counter); if
(Number.isFinite(floor) && counter <= floor) reject;`. If the column held
`'garbage'`, `NaN`, `{}` or `Infinity`, the floor silently did not apply and an
already-spent code was accepted again — though the column's presence meant the
account *had* spent one. The same shape recurs wherever a stored value guards
something: a secret that will not decrypt read as "no authenticator", a deny
list that will not parse read as "no denies", a settings table that will not
load read as "defaults". (§5.4, §7.4, §13.2)

> **Rule.** Distinguish *absent* from *present but unreadable*, and fail closed
> on the second. An unparseable value in a security-relevant column is a reason
> to refuse, never a reason to skip the check.

#### 16.4 Normalising to the empty credential

Backup-code verification stripped non-alphanumerics, then hashed. So `''`,
`'   '`, `'-----'`, `'\t\n'`, `null`, `undefined` and `[]` all became `''` and
hashed to `hash('')`, matching any row that happened to hold it — an empty
slot, a half-finished enrolment, a migration that hashed a missing field. An
empty submission opened an account. (§7.5)

> **Rule.** Shape-gate before you hash or compare, so that nothing a caller can
> send normalises to a value a degenerate stored row could match. It also stops
> junk paying for a full key derivation on an unauthenticated endpoint.

#### 16.5 A blank that becomes a legal zero

The QR encoder's margin parameter: `Number('')` is 0, and 0 is a *legal*
margin, so no range check could catch it. The result was a symbol with no quiet
zone, unreadable against dark page content — and an empty query parameter or
unfilled form field looks exactly like that by the time it arrives. (§7.4)

> **Rule.** When zero is a legal value, a blank must not be able to become it.
> Reject blanks before coercion, and keep an explicit 0 working.

#### 16.6 A coercion that throws on hostile input

`Number(Symbol())` throws, and `Number(obj)` runs `valueOf`, which can throw
anything. A module whose stated contract was "nothing here throws on bad input"
coerced with a bare `Number()` in several places and was reachable from
unauthenticated JSON — one crafted field away from a 500 on the sign-in path.
(§15.7)

> **Rule.** Everywhere a request can reach, use total coercion helpers that
> return `NaN` instead of throwing, and test every entry point against the
> hostile-values list.

### Cryptographic inputs

#### 16.7 Attacker-chosen crypto parameters

Under WebAuthn `attestation: 'none'` no signature is verified at registration,
so the submitted public key — modulus *and exponent* — is attacker-controlled.
With RSA `e = 1`, verification is the identity function and anyone holding the
public key can write a valid signature with no private key in existence. The
implementation checked the modulus length and never looked at `e`. (§7.7)

> **Rule.** Enumerate which inputs are attacker-chosen at each step and validate
> every crypto parameter, not just the ones that look like sizes. Then apply the
> same validation to the stored copy on every use: a database column is not a
> trust boundary.

#### 16.8 A lenient parser

A DER reader that accepts non-minimal encodings admits two byte strings for one
signature; a CBOR decoder where the last duplicate key wins reads
`{"authData":A,"authData":B}` as `B` while anything that stops at the first
reads `A`; authenticator data with leftover bytes is a structure you have
misread. Each opens a gap between the bytes you checked and the bytes something
else believes. (§7.7)

> **Rule.** Parse security-relevant formats strictly: canonical encodings only,
> duplicate keys refused, every byte accounted for, anything left over a reason
> to reject.

#### 16.9 A secret too short to be one

A truncated or corrupted stored authenticator secret still produces
normal-looking codes, and with a one-byte secret a single observed code
identifies it. Checking the length when the secret was generated did nothing for
a row that went bad later. (§7.4)

> **Rule.** Enforce minimum key sizes where keys are *used*, not only where they
> are made.

#### 16.10 A challenge that survives a failed ceremony

A WebAuthn challenge deleted only when the ceremony succeeded could be replayed
after a failure, and a signed self-describing challenge cannot be single use at
all without server state. (§7.7)

> **Rule.** Store challenges as rows and delete the row on use, whether or not
> the rest of the ceremony then succeeds.

### The platform

#### 16.11 A ceiling only production enforces

Cloudflare refuses a single PBKDF2 derivation above 100,000 iterations;
`wrangler dev` does not. 210,000 iterations ran locally in 31 ms and failed in
production, so every password write failed and the first account could not be
created. The fix — chaining rounds — introduced its own trap: the chunk size is
part of the digest, so "raising it to the new limit" one day would invalidate
every stored password at once. (§6.1, §14.6)

> **Rule.** Chain rounds under the ceiling, freeze the chunk size as part of the
> format, and never trust a local run about a platform limit.

#### 16.12 `SameSite=Strict` destroys device identity

`Strict` withholds cookies on any navigation that began off-site, so every visit
from a link, an email or a QR code arrived as a brand-new device: signed out,
asked for a fresh factor, another row in the pending list. Approving the device
did not help, because the next link was a different device again. (§8.3)

> **Rule.** `Lax` for session and device cookies. When a device "keeps being
> new", suspect cookie policy before your id generation.

#### 16.13 Platform-specific headers treated as universal

`Sec-CH-UA-Mobile` and friends are Chromium-only. Branching on them filed every
Firefox and Safari visitor as a desktop, and with `Sec-CH-UA-Model` absent the
literal string `Mobile` was displayed as the device model. (§8.5)

> **Rule.** Client hints are a bonus, never a basis. Keep a user-agent fallback
> and test with a non-Chromium browser.

#### 16.14 A refused cookie looks like a wrong password

A sign-in completed — session row written, audit row written — and the person
landed back on the sign-in page. From outside it was indistinguishable from a
wrong password. It was nearly always a browser that refused to keep the cookie:
private browsing, a "block all cookies" setting, an in-app webview. (§8.6,
§7.10)

> **Rule.** After sign-in, ask the server who you are before navigating, and say
> in plain words when the cookie did not come back. Ship a diagnostic that shows
> what the browser sent — names only.

#### 16.15 Deployment configuration eats more time than the code

A missing lockfile, a doubled config path, a renamed config that deployed the
wrong application to the wrong database, dashboard variables silently wiped by
a deploy, and a "retry" that rebuilt the old commit. Each cost a deploy cycle;
together they cost more than any bug in the code. (§14)

> **Rule.** Prove the pipeline with a worker that returns 200 before writing any
> logic, give the portal its own directory and lockfile, and keep every
> variable in the config file.

### Structure

#### 16.16 A second copy of a shared path

Four sign-in routes each built their own session, device record, grace window
and audit line. One of them is always going to be missing a step — not starting
a grace window, not clearing a counter — and nobody notices for months. (§7.3)

> **Rule.** One function for the tail every path shares. Pass a label for the
> part that legitimately differs.

#### 16.17 A promise in the interface the code cannot keep

The audit log recorded an undo snapshot for 21 action kinds; the revert
function implemented 12. The console offered Revert whenever a snapshot existed,
so nine kinds answered "Unknown undo type" — under a heading that said anything
which changed state could be reverted. (§11.4)

> **Rule.** When two sets must match, make them one set in code — a single object
> whose keys are the catalogue — and add a test that closes the loop.

#### 16.18 A catch that swallows the exception

"Create user" caught its exception, logged it to the console and returned "That
account could not be created." The audit log recorded the polite version.
Finding the cause took a deploy whose only purpose was to make the error
visible; after that it was obvious in one request. (§11.3)

> **Rule.** Every write path's `catch` records the real exception in the audit
> log. The person gets the polite sentence; the log gets the truth. The logger
> itself never throws.

#### 16.19 A secret readable by a role that only reads

An independent review of B's system found a token readable by a read-only role.
Anything an endpoint returns, the lowest-ranked person who can reach it can
read; "read-only" is not "harmless". (§11.6, §6.7, §6.9)

> **Rule.** Store tokens as hashes, never return undo snapshots or secrets from
> any API, and review every read endpoint for what its weakest reader learns.

#### 16.20 A revert that skips the guards

Restoring a recorded state wrote role, grants and denies straight back. With
`audit.revert` on a low-ranked custom role, someone demoted could revert their
own demotion. (§11.5)

> **Rule.** A revert calls the same guarded function as the original action.
> Restoring state is an action, not a database edit — and the capability to do
> it is reserved.

### Lockouts, and the doors left open avoiding them

#### 16.21 Requiring a factor nobody has enrolled

"A second factor is required and you have none — ask an administrator" is
advice nobody can act on: enrolling needs a session, and refusing the session
makes the requirement unsatisfiable. For the first Super Admin it was worse —
they *are* the administrator — and the system became unreachable the moment the
first account existed. (§7.8)

> **Rule.** Pin, never refuse. A "you must do X first" state allows exactly the
> routes that do X.

#### 16.22 A one-shot claim that never expires

B's setup was guarded by a claim row so that two requests could not both
create an owner, and B's first production setup failed partway — the PBKDF2
ceiling made every password write fail. A claim that never expires turns a
failure like that into a portal with no accounts that refuses to create one.
(§6.6)

> **Rule.** Every claim or lock guarding a one-time action expires, so a failure
> halfway can be retried.

#### 16.23 Clearing the per-IP limit on success

It is tempting to wipe the failure counters when someone authenticates. The
per-address bucket is the only limit that bounds credential spraying — one guess
each against many accounts never trips a per-account limit — so clearing it lets
anyone with one working credential spray, sign in and reset the brake, and
resets it for everyone behind the same office NAT. (§6.4)

> **Rule.** Clear per-account counters on success; never the per-address
> bucket. Make the clearing function refuse it.

#### 16.24 Charging the rate limit after the check

Counting only failed attempts makes a correct password free, so whoever holds
it can run the password step as often as they like and earn a fresh set of
attempts at the factor behind it each time. (§6.4)

> **Rule.** Charge the attempt first, then check.

#### 16.25 Checking status before the password

A "this account is suspended" check placed before password verification
answers anyone who types a username, confirming the account exists and is
interesting. (§3.1, §6.3)

> **Rule.** Check status after the password, and give every failure the same
> reply.

#### 16.26 Saying the same thing to the log as to the caller

The identical reply was right for the caller and wrong for the log. An
administrator reset the same person's password repeatedly for an hour while
that person typed a username that had never existed; every log line read like a
bad password. (§6.3)

> **Rule.** The caller gets one identical reply. The log, whose readers are the
> people who must fix it, gets the specific reason.

#### 16.27 An expired entry counted as cover

The guard against removing the allowlist entry that covers your own address
counted expired entries as cover. An expired entry grants nothing, so it waved
through the exact removal the guard existed to stop. (§12)

> **Rule.** In every guard that counts what remains, "active" means unexpired.

#### 16.28 A security setting with no self-lockout guard

An administrator changing policy could switch to lockdown from an unapproved
device, block a range containing their own address, block their own country, or
set a risk threshold below their own score — each a lockout of the person
making the change, sometimes of the owner. And refusing everything risky made
the settings unusable. (§12)

> **Rule.** Every setting that can refuse someone gets a guard that refuses the
> change if it would refuse the person making it. Changes that cost only someone
> else's *next* sign-in get a warning, not a refusal.

#### 16.29 A switch nobody can turn on

Devices are recorded only while someone is watching, so before device gating is
first enabled nobody has an approved device. Refusing the change at that moment
made the feature impossible to switch on. (§8.4)

> **Rule.** When enabling a control would lock out the person enabling it, trust
> and approve their device in the same transaction.

#### 16.30 A grace window that outlives the trust behind it

Revoking a device, revoking all of someone's devices, resetting their password,
suspending them, clearing their factors: miss dropping the grace window in any
one of these and a revoked device keeps skipping the factor. (§8.9)

> **Rule.** Every action that withdraws trust drops the grace windows it covers.
> List them, and test each.

#### 16.31 A temporary entry that never ends

A tier-4 "temporary" allowlist entry added without an expiry would be
permanent — the one thing the tier exists to prevent. (§8.7)

> **Rule.** A temporary grant without an expiry gets one.

#### 16.32 A half-finished sign-in that outlives its facts

A token carried between the password and the factor did not record where the
code had been sent, so removing a number from the account did not stop a code
already sent to it from working; and a suspension landing mid-flow could be
completed with a code in hand. (§7.2)

> **Rule.** Bind an in-flight token to everything verification depends on, and
> re-check the account's status when it is redeemed.

#### 16.33 Counting a factor nobody holds

Count an authenticator enrolment abandoned halfway as a factor, and the
account has a second factor nobody holds. Count the backup codes an interrupted
admin reset leaves behind as "has set something up", and the person is never
prompted to enrol — until the codes run out. (§7.1, §7.4)

> **Rule.** A factor counts only once it has been proved, and backup codes alone
> are not enrolment.

### Growth

#### 16.34 An append-only table with no trim

The visit and audit tables were bounded; the fingerprint table was not, and its
key is a hash of request headers, which the client chooses. A loop of requests
with a fresh user agent each time minted unlimited rows — and filling the
database breaks *every* write in the system: sessions, audit, lockout counters.
(§9.7, §13.4)

> **Rule.** Trim everything that grows, in the write that grows it. A table keyed
> by client-chosen input is trimmed by timestamp and count, never by id. No
> unauthenticated request may be able to fill the database.

### Calendars and time

#### 16.35 A calendar off by a constant

The Hebrew epoch constant was two days out. Every festival landed two days
early, every date still looked plausible, the calendar was internally
consistent — and wrong about every single day. A test written against its own
output would have passed forever; the only symptom would have been a lost
streak weeks later with nothing in any log. (§10.13)

> **Rule.** Verify any calendar against an independent implementation (ICU via
> `Intl` is free) and assert the structural invariants — those about
> differences *and* those about absolutes.

#### 16.36 A sentence in the spec that the arithmetic does not support

Found while merging these designs. A's spec promised that with a 30-hour window
"a sign-in at any time on one day is always in range from a sign-in at any time
on the day before" — but 00:30 Monday to 23:30 Tuesday is 47 hours. And a draft
of the worked examples said 11 PM Friday gives until noon Sunday; the algorithm
gives 5 AM Monday (§10.9). Both sentences read well. Neither was computed.
(§10.4)

> **Rule.** Every number and promise in a spec is a test case: compute it or
> delete it. Show people the exact value, never a rule of thumb.

#### 16.37 A read that rewrites

Resetting a lapsed streak when it is *displayed* races with a concurrent
sign-in, surprises every cache that trusted GET, and destroys the stored record
an administrator needs if the lapse was the portal's fault. (§10.10)

> **Rule.** A GET never writes. Compute derived state at read time and let the
> next real write reconcile it.

#### 16.38 Decoration on the critical path

A streak, a counter, a notification: anything non-essential called inside
sign-in can, by throwing, stop people signing in — a feature nobody needs
breaking the one everybody does. (§10.16)

> **Rule.** Wrap every non-essential subsystem so that its worst failure is not
> happening, and test that by dropping its table.

#### 16.39 A clock in the future

A stored timestamp ahead of now — after a clock moved or a backup was restored —
treated as expired punishes the person for your clock; treated as valid, it
never expires. (§10.15, §13.7)

> **Rule.** Decide explicitly what a future timestamp means for each use. For
> anything streak-like, hold.

### The interface

#### 16.40 A chooser with nothing in it

An account whose only factor is a passkey, opened in a browser without
WebAuthn, rendered a method chooser with every row hidden — a card with nothing
on it and no explanation. (§7.10)

> **Rule.** Every branch of a state machine renders something a person can act
> on. "None available" is a branch, and it has words.

#### 16.41 A cancel shown as an error, a retry that cannot work

Dismissing the passkey dialog is usually someone reaching for another method;
treated as an error, it lands them in the red box. And after an assertion has
been posted, a Retry that re-runs the ceremony uses a challenge the server has
already burned, so it can only fail again. (§7.10)

> **Rule.** Distinguish a person changing their mind from a failure, and never
> offer a retry the server has already made impossible.

#### 16.42 An open redirect in `?next=`

The enrolment page carries the person's real destination in `?next=`, so that
skipping still takes them there. That makes its skip button and its back link
open-redirect candidates, on a page people reach right after signing in.
(§7.10)

> **Rule.** Accept only same-host paths in any redirect parameter, everywhere it
> is used, and test against off-site URLs, `//host`, `javascript:`, an `http:`
> downgrade of your own host, and junk.

#### 16.43 A QR code on a dark page

Drawn in the page's own colours, a QR code in dark mode is dark-on-dark and
does not scan — and it is the one image on the page that must work with a camera
pointed at it. (§7.4)

> **Rule.** A scannable code always sits on its own white plate with its quiet
> zone.

#### 16.44 A signed-in person shown the sign-in button

Showing someone with a valid session the landing page's "Sign in" button
reads as though they had been signed out. (§6.9)

> **Rule.** Decide signed-in versus signed-out on the server, before the first
> byte, so there is no flash of the wrong page.

#### 16.45 HTML strings in the browser

These screens render attacker-controlled strings — user agents, network
organisation names, invitation emails, access-request reasons — and every
`innerHTML` is one unescaped field away from running one. With
`'unsafe-inline'` in the policy, nothing else stands in the way. (§3.4)

> **Rule.** Build DOM nodes and set text. No HTML strings, no inline script, no
> inline handlers, no inline styles.

### Records and operations

#### 16.46 Identifiers issued from a row count

Issue employee numbers from a count of rows and a departed person's number goes
to the next hire — and that number outlives the database, in payroll and in
email signatures. Without an explicit duplicate check, a typo that collides
with an existing number is an unexplained 500. (§5.6)

> **Rule.** Issue identifiers from a high-water mark, never a count, back them
> with a unique index, and check for duplicates explicitly so a collision is a
> sentence.

#### 16.47 A hard delete

Deleting an account deleted the record of what that person had done. (§5.6)

> **Rule.** Disable people; never delete them.

#### 16.48 Editing a migration that already ran

A migration line edited after it had run in production did nothing there and
silently diverged production from every new environment. (§13.1)

> **Rule.** Migrations are append-only and never destructive; drops and rewrites
> are manual, backed-up operations.

#### 16.49 One secret doing two jobs

A's portal had one secret that signed every cookie and derived the encryption
key for stored authenticator secrets. Rotating it — routine and recoverable for
cookies — makes every stored authenticator secret undecryptable, and every
authenticator app stops working at once. (§13.3)

> **Rule.** Derive at-rest encryption keys from a different secret from the one
> that signs cookies, and version every encrypted blob.

### Tests

#### 16.50 A hardcoded list that went stale

The harness rewrote the worker's imports from a hardcoded list. Each time the
worker gained an import, two suites stopped running — and reported nothing,
which the runner counted as success. It happened twice. (§15.3, §15.4)

> **Rule.** Discover lists from the source instead of maintaining them, and make
> "reported nothing" a failure.

#### 16.51 A test address the allowlist rightly refuses

This repository's test client first defaulted to `203.0.113.10`, an address
from a documentation range — the kind every example reaches for. The allowlist
refuses reserved ranges, so any test that allowlisted the test client would
fail, correctly. The fix was the fixture, not the guard. (§15.2)

> **Rule.** Test fixtures must pass the same validation as real input.

#### 16.52 A test that cannot tell the right answer from the likely wrong one

A base64url assertion passed against a page that emitted plain base64, because
the test's bytes encoded identically in both alphabets. (§7.7, §15.8)

> **Rule.** Choose test inputs that distinguish the right answer from the most
> likely wrong one, and confirm it by breaking the code.

*Provenance: A §14.1–§14.12 are 16.1–16.7, 16.12, 16.13, 16.16, 16.17 and
16.35; B traps 1–10 are 16.11, 16.18, 16.21, 16.23, 16.20, 16.34, 16.35,
16.28, 16.15 and 16.44–16.47; the remainder are drawn from the bodies of both
sources, and 16.36 and 16.51 from this merge (Appendix D).*

---

## 17. Build order

Each step ends somewhere testable, and its tests are written with it, not
after. Do not skip ahead to the console.

1. **Skeleton.** The portal's own directory, config and lockfile; a worker that
   returns 200 and `/healthz`; deployed. Prove the pipeline before writing
   logic (§14).
2. **Schema and settings.** Tables, idempotent creation, append-only
   migrations, the version stamp; the settings registry with a default and a
   restrictive reading for every key. Test every key against absent,
   unrecognised and hostile values.
3. **Primitives.** Total coercion, bytes and cookies; chained PBKDF2, signed
   tokens and AES-GCM; address and CIDR parsing; the QR encoder, decoded in its
   tests by an independent decoder. Everything above inherits their bugs.
4. **Authority and audit.** The permission catalogue and roles; effective
   permissions; the rank, minting and last-Super-Admin guards, tested directly —
   they are the security model. The hash-chained audit log with real-error
   recording, and the undo catalogue with `REVERTERS` as one object, **before**
   anything that can fail or destroy, so every destructive action is revertible
   from birth.
5. **The calendar and the streak arithmetic.** Pure functions with no
   dependencies beyond step 3, so build them now, while nothing depends on them:
   the Hebrew calendar with its ICU cross-check over three centuries and its
   invariants, the protected-day function, the deadline and the status, with
   every row of §10.9 as a test.
6. **The gate.** Hard blocks, the `allowlist` mode, the empty refusal, security
   headers, shells. Verify that a non-allowlisted address gets a zero-byte body
   on every path, assets and API included.
7. **Bootstrap.** Setup with the key, the expiring claim, the caller's address
   allowlisted and device approved in the same request.
8. **Password and sessions.** Chained hashing, the session cookie, the sign-in
   page, change-password, the identical reply and distinct log, rate limits and
   the tempered lockout; signed-in visitors routed past the sign-in page.
9. **A read-only console.** People, the allowlist, devices, the audit log. Now
   you can see what the system thinks.
10. **People.** Invitation links, statuses, employee numbers, temporary roles,
    access requests.
11. **Devices.** The signed cookie, inventory, approval and self-approval, the
    pending page, `Lax`, the diagnostic endpoint.
12. **One second factor, end to end.** An authenticator with backup codes —
    enrol, confirm, sign in — with the real schema, through the one completion
    path; prompted and required enrolment; step-up.
13. **The streak, wired in.** Recording a sign-in inside the completion path,
    the read-only status, the history and coming-up lists, the dashboard that
    leads with them, and the test that drops the table. People see this every
    day; get it right before the long tail.
14. **Passkeys.** The long one. Write the §7.7 checklist as tests first,
    negative cases included — the RSA exponent above all — then make them pass.
15. **Codes by email or text.** Last of the factors: the weakest, and they cost
    money. Destinations, masking, sent only when they are the only method.
16. **The sign-in state machine.** Every branch, the dead end included.
17. **Grace windows**, and every place that must drop them.
18. **The rest of the gate.** The other access modes, fingerprinting and risk
    with reasons, the privacy notice, the edge rules, the open switch; the
    self-lockout guards; a reverter for every undo kind.
19. **The full admin console**, including the streak view and restore. Last: it
    is the largest part and the least subtle.

Then go back and **mutation-check** the suite (§15.8) — that pass will find
things; it always does — run an adversarial review of the authentication paths,
dry-run the deploy, and ship.

*Provenance: A §15 and B §10, interleaved; the streak split into a pure early
step and a wiring step is this design.*

---

## Appendix A. Reference constants

Starting points, not gospel. Settings can be changed at runtime (CONTRACTS §5);
the rest are constants in code.

| Area | Constant | Value |
|---|---|---|
| Sessions | idle / absolute | 120 min (5–1,440) / 8 h (1–72); idle extension written at most once a minute |
| | step-up freshness | 15 min (1–120); one minute of future skew tolerated |
| Sign-in | half-finished sign-in token | 5 min |
| | WebAuthn challenge | 5 min, single use |
| | sent code | 6 digits, 10 min, 5 attempts, single use |
| Passwords | algorithm | PBKDF2-SHA256, chained; 32-byte salt; 256-bit output |
| | iterations | chunk 100,000 (**frozen**); default 600,000; minimum 100,000; maximum 10,000,000 |
| | length | 12–1,024 characters |
| Lockout | account | 10 failures → 15 min; bypassed by a device that has signed in to the account before |
| Rate limits | per address / identifier / user | §6.4 |
| Backup codes | set | 10, single use, shown once; `XXXXX-XXXXX` from `23456789ABCDEFGHJKMNPQRSTUVWXYZ`; one salt per set; one 100,000-iteration round |
| TOTP | | SHA-1, 6 digits, 30 s step, ±1 step; 160-bit secret; 128-bit minimum enforced at verification |
| Passkeys | algorithms | ES256 (−7), RS256 (−257) |
| | RSA key | modulus 1,024–8,192 bits and odd; exponent odd, ≥ 3, ≤ 8 bytes |
| Grace windows | by tier | 1: 7 days · 2: 24 h · 3: 2 h · 4: none (entry expires after 24 h unless set) |
| Invitations | link | 256-bit token, SHA-256 stored, 7 days, single use |
| Roles | temporary role | expiry required, ≤ 90 days |
| Bootstrap | claim | expires after 10 min; 5 key guesses per address per hour |
| Gate | open switch | 1–168 h, or an explicit "until closed" |
| Risk | threshold | 70 (refuse at or above; 1–100) |
| Fingerprints | collection | 1.5 s deadline; body ≤ 16 KiB; strings ≤ 256 chars; arrays ≤ 64 items |
| Devices | | code `XXXX-XXXX`; at most 2,000 pending; pending pruned after 30 days unseen |
| Audit | sizes | 16 KiB per state column; 512 KiB per undo snapshot |
| Streak | window | 30 h (24–72) |
| | re-entry grace | 12 h (0–24) |
| | leeway cap | 4 days (0–7) |
| | hard cap | window + cap × 24 h + grace = 138 h by default |
| | iteration | at most 8 rounds |
| | hold | anchor more than 5 min in the future |
| | at risk | under 6 h left |
| | dashboard | 84-day history; 21 days coming up; top 10 leaderboard |
| | day log | 400 days per person |
| Retention | | §13.4 |
| Employee numbers | | `ORG_CODE` + 6 digits, from a high-water mark |

## Appendix B. Secrets and variables to provision

| Name | Kind | Required | Notes |
|---|---|---|---|
| `SESSION_SECRET` | secret | yes | ≥ 32 characters (48 random bytes recommended); signs device, sign-in, fingerprint and pass tokens |
| `DATA_KEY` | secret | yes | ≥ 32 characters; at-rest encryption key material; **never** the same as `SESSION_SECRET` |
| `SETUP_KEY` | secret | until setup | ≥ 32 characters; delete after the first account exists |
| `ORG_NAME` | var | yes | display name, e.g. `Acme Inc.` |
| `ORG_CODE` | var | yes | `[A-Z]{2,8}`, the employee-number prefix |
| `RP_ID` | var | yes | the portal's hostname; changing it orphans every passkey |
| `ORIGIN` | var | yes | the exact origin, e.g. `https://staff.example.com` |
| `PBKDF2_ITERATIONS` | var | no | default 600,000, minimum 100,000; affects new hashes only |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` | secrets | no | texted codes |
| `RESEND_API_KEY` | secret | no | emailed codes and invitation emails |
| `MAIL_FROM` | var | with Resend | sender address |
| `DB` | D1 binding | yes | the portal's own database |
| `ASSETS` | assets binding | yes | `public/`, with `run_worker_first: true` |

Secrets go in the platform's secret store, and in `.dev.vars` for local
development; never in the config file or the repository. Every `var` lives in
`wrangler.jsonc`, because a deploy replaces the dashboard's (§14.4).

## Appendix C. What this does not cover

Deliberately out of scope, and worth knowing you are choosing to omit:

- **Impersonation** ("sign in as"). B's Administrator was explicitly denied it;
  here it is not built at all. It gives one person another's authority in a
  session, which is exactly the "second, more powerful login" the reserved set
  exists to prevent, and it blurs the one question the audit log must answer —
  who did this. Support does not need it: the person's own screen, the
  diagnostic endpoint, their activity page, the audit log and the visit log
  answer nearly every "why can't I…". If you must have it, build it as a
  separate, reserved, read-only, time-boxed, visibly bannered mode whose audit
  rows name both people, and accept that you have added an attack surface.
- **Federation**: SSO, OAuth, OIDC, SAML; and directory sync (SCIM, an HR
  system).
- **Self-service sign-up and account recovery by email.** Accounts come from
  administrators; recovery is an administrator's factor reset.
- **Re-encrypting stored secrets under a new `DATA_KEY`** (§13.3). The `v1.`
  prefix is there for the day it is written.
- **Hardware-attested device management.** A browser cannot prove what machine
  it runs on; that is MDM's job.
- **Scheduled jobs and notifications.** Nothing runs on a timer, and nothing
  tells anyone their streak is at risk except the dashboard itself.
- **Scale and tenancy** beyond what one D1 database comfortably handles for one
  organisation.
- **Sunset-precise protected periods**, and other observances' calendars beyond
  weekly days and explicit dates — each is a new protected-day function with its
  own cross-check (§10.14).
- **Legal advice** about fingerprinting and its notice (§9.5).

## Appendix D. Source crosswalk

`docs/CONTRACTS.md` and comments in the code cite the two sources directly. Code
comments written as `SPEC §n` use **A's** numbering.

**A — restricted-access portal spec**

| A | Here |
|---|---|
| §0 How to use, scope | §0 |
| §1 Decisions | §1 |
| §2 Four gates, why this order, response hardening | §3 |
| §3 Data model | §4 |
| §4 Network allowlist, deleting entries, the open switch | §8.7, §8.8, §12 |
| §5 Device identity, `Lax`, auto-approve, client hints, diagnostic endpoint | §8.1–§8.6 |
| §6 Password, identical reply / distinct log | §6.1–§6.5 |
| §7.1 Which methods | §7.1 |
| §7.2 Half-finished sign-in, one completion path | §7.2, §7.3 |
| §7.3 TOTP, QR, backup codes | §7.4, §7.5 |
| §7.4 Passkeys | §7.7 |
| §7.5 Enrolment, last factor, admin reset, `?next=` | §7.8, §7.10 |
| §7.6 Client state machine | §7.10 |
| §8 Grace windows | §8.9 |
| §9 Permissions catalogue, audit undo, REVERTERS | §5.2–§5.3, §11.4–§11.5 |
| §10 Calendar-aware streaks | §10 |
| §11 Operating it: migration, rotation, cleanup, never-log, empty 403, races, backups | §13.1, §13.3, §13.4, §13.6, §13.5, §13.7, §13.8 |
| §12 Front-end notes | §3.4, §3.5 |
| §13.1 Real SQLite · §13.2 real fetch · §13.3 imports | §15.1 · §15.2 · §15.3 |
| §13.4 DOM stub · §13.5 three-outcome runner · §13.6 static checks | §15.5 · §15.4 · §15.6 |
| §13.7 Mutation-checking · §13.8 two more habits | §15.8 · §15.9 |
| §14.1 · §14.2 · §14.3 · §14.4 | §16.1 · §16.2 · §16.3 · §16.4 |
| §14.5 · §14.6 · §14.7 · §14.8 | §16.7 · §16.12 · §16.13 · §16.16 |
| §14.9 · §14.10 · §14.11 · §14.12 | §16.17 · §16.35 · §16.5 · §16.6 |
| §15 Build order | §17 |
| Appendix, constants and secrets | Appendices A, B |
| What this does not cover | Appendix C |

**B — staff identity, access and audit build brief**

| B | Here |
|---|---|
| §1 What this is | §2.1 |
| §2 Stack, layout | §2.2, §2.3 |
| §3 Data model | §4 |
| §4 Roles, permissions, guards | §5 |
| §5 Authentication, flows | §6, §7 |
| §6 Devices, access modes, fingerprinting | §3.2, §8, §9 |
| §7 Audit log | §11 |
| §8 Streaks | §10 |
| trap 1 PBKDF2 ceiling | §6.1, §14.6, §16.11 |
| trap 2 swallowed exception | §11.3, §16.18 |
| trap 3 required factor, none enrolled | §7.8, §16.21 |
| trap 4 per-IP limit | §6.4, §16.23 |
| trap 5 revert guards | §11.5, §16.20 |
| trap 6 trims | §13.4, §16.34 |
| trap 7 calendar invariants | §10.13, §16.35 |
| trap 8 self-lockout guards | §12, §16.28 |
| trap 9 deployment configuration | §14, §16.15 |
| trap 10 small ones | §6.9, §5.6, §3.4, §16.44–§16.47 |
| §10 Build order | §17 |
| §11 How to verify | §15 |

**Decisions D1–D18** are §1.10.
