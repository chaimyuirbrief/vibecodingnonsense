# Internal contracts

The binding reference for everyone writing code in this repository — people
and agents. `SPEC.md` explains *why*; this file says *exactly what*: module
exports, settings, routes, response shapes, and the streak algorithm. If code
and this file disagree, one of them is a bug — fix whichever is wrong and keep
them in step.

Two source designs were merged to make this portal. They are referred to as
**A** (the restricted-access portal spec: four gates, fail-open catalogue,
grace windows, revert, streak window arithmetic) and **B** (the staff
identity/access/audit build brief: ranked roles, access modes, fingerprinting,
hash-chained audit, protected-period streaks, the deployment traps).
Section references like *A §14.1* or *B trap 4* point into those.

---

## 0. Non-negotiables

1. **Zero runtime dependencies.** WebCrypto, `fetch`, `Intl`, D1. Dev
   dependencies (esbuild, wrangler, jsqr) are for checks and tests only.
2. **Fail closed.** Every read of a stored or submitted value has a default,
   and anything unrecognised resolves to the *restrictive* option (A §14.1–3).
   "Absent" and "present but unreadable" are different, and the second is a
   reason to refuse.
3. **Total coercion** on anything reachable from a request: `util.toNum`,
   `util.toInt`, `util.str`, `util.strStrict`, `util.parseIsoStrict`. Never
   `Number(x)`, `parseInt(x)` or `Date.parse(x)` on untrusted input (A §14.12).
4. **Every write path's `catch` records the real exception** in the audit log
   at `critical` severity (`audit.auditError`) and then returns its polite
   sentence (B trap 2). The audit writer itself never throws.
5. **No HTML strings in the browser.** CSP is `script-src 'self'` with no
   `'unsafe-inline'`. Pages build DOM nodes with `textContent`; nothing assigns
   `innerHTML`/`outerHTML`/`insertAdjacentHTML`, and nothing uses inline event
   handlers or inline `style=""` attributes (B §10).
6. **No external resources at all** — no CDN, web fonts, icon sets or QR
   services (A §2, §7.3).
7. **Time:** stored as ISO-8601 UTC (`util.iso`), compared as strings in SQL
   only when both sides came from `util.iso`. Wall-clock from `util.now(env)`
   only — never `Date.now()` in `src/` (tests inject `env.__clock`).
8. **One function per shared path** (A §14.8): one `completeSignIn`, one
   `canDropFactor`, one `assertNotLastSuper`, one `validatePublicKey`.
9. **The undo catalogue is one object** (A §9, §14.9): `reverters.js` exports
   `REVERTERS`; `undo.js` refuses to record an undo for a kind not in it; a
   test closes the loop.

---

## 1. Reconciliation decisions

Where A and B disagreed or each covered only part of the ground, this is what
the merged portal does. `SPEC.md` gives the reasoning at length.

| # | Topic | A says | B says | Merged |
|---|---|---|---|---|
| D1 | CSP | `script-src 'unsafe-inline'`, single-file pages | `script-src 'self'`, build DOM nodes | **B.** Pages render attacker-controlled strings (user agents, ASN orgs, invite emails), so inline script is off. External same-origin JS modules. |
| D2 | Unauthorised visitor | empty 403 | decoy 404 | Setting `deny_style`: `empty` (default) or `decoy`. Both zero-information. |
| D3 | Gate model | network allowlist → device → password → factor | six access modes | B's modes, with A's allowlist as the `allowlist` mode (default), A's time-boxed "open to the internet" switch as `gate_open`, A's device gate as `device_gating`. |
| D4 | Roles | superadmin/admin/user + non-grantable capabilities | six ranked roles, rank guards, danger perms | B's ranked roles **plus** A's non-grantable set as `reserved` permissions only Super Admin's `*` holds. Super Admins may act on each other (peers), guarded by the last-superuser rule. |
| D5 | Password KDF | PBKDF2 100k | chained rounds above 100k | Chained PBKDF2-SHA256, frozen 100k chunk, 600k default, per-row iteration count. |
| D6 | Lockout | rate-limit only; lockout is a DoS vector | lock for N minutes | Per-IP and per-identifier rate limits (per-IP **never cleared on success**, B trap 4) **plus** a 15-minute account lock after 10 failures that a device which has previously signed in to that account bypasses. Strangers cannot lock a colleague out of their own laptop. |
| D7 | No factor enrolled | prompt, never wall in | forced enrollment, pin the session | Per-user/global `mfa_policy`: `prompt` (default; A) or `required` (B's pinned enrolment). Neither ever refuses the session. |
| D8 | Second factors | passkey, TOTP, backup, SMS fallback | + email OTP | Passkey > TOTP > backup code > email/SMS code. Codes go to admin-managed `code_destinations` (SMS or email) and are auto-sent only when a code is the *only* method. |
| D9 | MFA frequency | grace windows by network tier | — | A's tiered grace windows, setting `mfa_grace` (default on). |
| D10 | Audit | undo snapshots + single REVERTERS object | hash chain, scrub, real errors, revert writes a new row | Both. Revert is a new row with `reverts_id`; "reverted" is derived so the chain never breaks. `undo_payload` is never returned by any API. |
| D11 | Invitations / email | no email of any kind | invitations by email | Invitation **links** the admin copies; email is sent too if a provider is configured. Accepting an invitation approves the device it was accepted on — the invitation *is* the admin's approval. |
| D12 | Streak model | 30h, +24h per consecutive blocked day, iterate, cap 4 | 30h, protected time added back, blocks merge, re-entry grace | One algorithm (§9): A's day-counting fixed point with B's merged blocks and re-entry grace, a hard cap that a calendar bug cannot exceed, and A's never-mutate-on-read rule. Calendar is pluggable (weekly days + Hebrew Yom Tov + explicit dates). |
| D13 | Streak window anchor | "within 30 hours" | rolling window | The window runs from the **most recent** sign-in; a new local day counts once. (A's "any time on one day is always in range of any time the day before" is false — 00:30 Monday to 23:30 Tuesday is 47h — so the dashboard always shows the exact deadline instead of implying a calendar rule.) |
| D14 | Fingerprinting | device ≠ fingerprint; inventory only | full edge + browser fingerprint, risk score with reasons | Both: device identity stays a signed cookie (never a fingerprint); fingerprints and risk feed the gate and the console, with a privacy notice on by default. |
| D15 | Bootstrap | key-gated, allowlist caller IP | + approve device, one-shot expiring claim | Both. |
| D16 | Session id storage | — | — | Cookie holds a random token; the DB stores its SHA-256. |
| D17 | Soft delete | `users.delete` | soft delete only | "Disable" (status `disabled`) only; no hard delete anywhere. |
| D18 | Retention | audit grows forever, page it | trim everything that grows | Audit is never trimmed (the chain verifies from genesis); visits, fingerprints, rate-limit rows, challenges, pending devices and streak history are trimmed by the write that creates them. |

---

## 2. Layout and ownership

```
worker.js                 router, gate, pages, security headers           (api-core)
src/util.js               coercion, bytes, cookies, responses             (foundation — done)
src/crypto.js             PBKDF2 chain, HMAC tokens, AES-GCM              (foundation — done)
src/catalog.js            permission catalogue, system roles              (foundation — done)
src/errors.js             HttpError, GuardError, ValidationError          (foundation — done)
src/router.js             route table                                     (foundation — done)
src/schema.js             DDL, migrations, seeding                        (foundation — done)
src/rbac.js               effective permissions, rank & minting guards    (rbac)
src/policy.js             settings registry, resolvePolicy, gate_open     (rbac)
src/audit.js              hash-chained audit, scrub, verify, list         (rbac)
src/undo.js               UNDO_KINDS, undoFor                             (rbac)
src/ratelimit.js          attempt counting                                (rbac)
src/ip.js                 IPv4/IPv6, CIDR                                 (primitives)
src/qr.js                 QR encoder → SVG                                (primitives)
src/calendar/hebrew.js    arithmetic Hebrew calendar                      (streak)
src/calendar/protected.js local days, time zones, protected-day function  (streak)
src/streak.js             streak engine                                   (streak)
src/webauthn/*.js         cbor, der, cose, webauthn                       (webauthn)
src/mfa/*.js              totp, backup, token, otp, factors               (mfa)
src/notify.js             SMS + email providers                           (mfa)
src/users.js              accounts, lifecycle, employee numbers, lockout  (identity)
src/invitations.js        invitations + access requests                   (identity)
src/sessions.js           sessions, pins, step-up                         (identity)
src/devices.js            device cookie, inventory, approval              (edge)
src/grace.js              MFA grace windows                               (edge)
src/network.js            allowlist + blocklist                           (edge)
src/fingerprint.js        edge/client signals, risk, visits               (edge)
src/gate.js               access decision per request                     (edge)
src/context.js            build `rc` for a request                        (api-core)
src/signin.js             completeSignIn — the one tail                   (api-core)
src/pages.js              page routing + decoy/deny responses             (api-core)
src/api/index.js          registers every API module                      (foundation — done)
src/api/public.js         setup, invite, request access, fp, diag, device (api-core)
src/api/auth.js           login + MFA                                     (api-core)
src/api/me.js             self-service                                    (api-core)
src/api/admin.js          people, roles, devices, sessions, streaks, audit (api-admin)
src/api/admin-security.js settings, network, gate, visitors               (api-admin)
src/reverters.js          REVERTERS                                       (api-admin)
src/guards.js             self-lockout guards for settings/network        (api-admin)
public/                   pages, css, browser JS                          (ui-public, ui-app; fp.js: edge)
tests/                    see §12
```

Every module is an ES module with explicit `.js` import specifiers so plain
`node` can import the worker directly.

---

## 3. Environment

| Binding | Kind | Notes |
|---|---|---|
| `DB` | D1 | |
| `ASSETS` | Workers Assets (`run_worker_first: true`) | the worker gates every request before serving a file |
| `SESSION_SECRET` | secret, ≥32 chars | signs device / MFA / fp / pass tokens |
| `DATA_KEY` | secret, ≥32 chars | at-rest encryption key material — never the same as `SESSION_SECRET` |
| `SETUP_KEY` | secret, ≥32 chars | one-time bootstrap |
| `ORG_NAME` | var | e.g. `Acme Inc.` |
| `ORG_CODE` | var | employee-number prefix, `[A-Z]{2,8}`, e.g. `ACME` |
| `RP_ID` | var | WebAuthn RP ID, e.g. `staff.example.com` |
| `ORIGIN` | var | exact origin, e.g. `https://staff.example.com` |
| `PBKDF2_ITERATIONS` | var | default 600000, min 100000 |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` | secrets, optional | SMS codes |
| `RESEND_API_KEY`, `MAIL_FROM` | secret/var, optional | email codes and invitation emails |
| `__clock` | **tests only** | `() => ms`; vars are strings so production can never set it |
| `__fetch` | **tests only** | replaces `fetch` for outbound provider calls |

Missing `SESSION_SECRET` or `DATA_KEY` → every request except `/healthz`
answers an empty 503 (fail closed) and logs why.

---

## 4. Conventions

### 4.1 The request context `rc`

Built once per request by `context.buildContext(request, env, ctx)`:

```js
rc = {
  request, env, ctx,            // ctx = ExecutionContext (waitUntil)
  url,                          // URL
  method, path,                 // 'GET', '/api/me'
  nowMs,                        // util.now(env) at request start
  ip,                           // canonical address string (ip.normalizeIp) or null
  cf,                           // request.cf || {}
  ua,                           // user-agent string ('' if absent)
  cookies,                      // util.parseCookies(...)
  policy,                       // await policy.resolvePolicy(env) — parsed settings
  edge,                         // fingerprint.edgeSignals(request, rc.cf)
  fp,                           // fingerprint.readFpCookie(rc) → {hash, risk} | null
  device,                       // { id: string|null, row: object|null } from devices.readDevice(rc)
  ipTier,                       // network.tierForIp(env, ip, nowMs) → 1..4 | null
  ipBlocked,                    // network.isIpBlocked(env, ip, nowMs)
  gate,                         // gate.evaluateGate(rc) result
  session, user, authz,         // set by sessions.loadSession(rc); null when signed out
  setCookies: [],               // Set-Cookie strings to append to the response
}
```

Domain functions that write take `rc` first so they can audit with the actor,
IP, device and session. Code with no request (tests, migrations) may pass
`{ env, nowMs }` — every consumer must tolerate the other fields being absent.

### 4.2 Audit calls

```js
import { audit, auditError } from './audit.js';
import { undoFor } from './undo.js';

await audit(rc, {
  action: 'user.suspend',            // dotted lowercase, from the list in §4.3
  outcome: 'success',                // 'success' | 'failure' | 'denied'  (default 'success')
  severity: 'notice',                // 'info' | 'notice' | 'warning' | 'critical'
                                     //   default: success→info, denied→notice, failure→warning
  target: { type: 'user', id: 42 },  // or null
  detail: 'Suspended jane@acme.com', // one human sentence
  before: { status: 'active' },      // scrubbed before storing
  after: { status: 'suspended' },
  error: err,                        // Error or string; the REAL message
  undo: undoFor('user.status', { userId: 42, status: 'active' }),
});
await auditError(rc, 'user.create', err, { target, detail });   // critical + real error
```

`audit` and `auditError` resolve to `{ id, seq }` or `null` and **never
throw**. Scrubbing removes any key matching
`/pass|secret|token|hash|salt|code|cookie|session/i` from `before`/`after`
(recursively). `undo_payload` is not scrubbed — it is server-only.

### 4.3 Action names

```
login.success login.fail login.denied mfa.fail mfa.code_sent logout
stepup.success stepup.fail password.change password.reset setup.complete
invite.accept
mfa.totp.enroll mfa.totp.remove mfa.passkey.add mfa.passkey.rename
mfa.passkey.remove mfa.backup.generate mfa.backup.used mfa.reset
mfa.decrypt_failed mfa.replay_floor_unreadable mfa.passkey.counter_regressed
user.invite user.edit user.status user.role user.temp_role.grant
user.temp_role.revoke user.sessions_revoked user.devices_revoked
user.destination.add user.destination.remove
invitation.revoke invitation.reissue
request.create request.approve request.deny
role.create role.edit role.delete
device.approve device.self_approve device.block device.unblock device.rename device.revoke
network.allow.add network.allow.edit network.allow.remove network.block.add network.block.remove
setting.change gate.open gate.close
audit.verify audit.revert
streak.adjust streak.error
session.revoke
error
```

### 4.4 Errors

Throw `HttpError`/`GuardError`/`ValidationError` (src/errors.js) from
anywhere; the worker turns them into `json(status, body)`. Anything else is a
bug: the worker answers 500 `{ error: 'Something went wrong.' }` and calls
`auditError` with the real exception.

All API responses are JSON. Errors are `{ error: string, code?: string, ... }`.

### 4.5 JSON shapes for people

`users.publicUser(row, authz?)` is the only way a user row leaves the server:

```js
{ id, email, username, full_name, employee_no, job_title, department,
  manager_id, status, role: { id, key, name, rank }, mfa_policy,
  last_login_at, created_at }
```

Never: password fields, `failed_logins`, `locked_until` (admins see
`locked: bool` instead), secrets, session ids.

---

## 5. Settings (policy.js)

Each key: default, how a stored string parses, what an unrecognised value
becomes (always the restrictive choice), and which permission may change it
through `PUT /api/admin/settings`. `gate_open` is changed only by the gate
endpoints.

| key | type / values | default | unrecognised → | perm |
|---|---|---|---|---|
| `access_mode` | `public` `fingerprint_gate` `request_access` `allowlist` `invite_only` `lockdown` | `allowlist` | `lockdown` | security.manage |
| `deny_style` | `empty` `decoy` | `empty` | `empty` | security.manage |
| `gate_open` | `'0'` closed · `'1'` open until closed · ISO instant | `'0'` | closed | gate.open |
| `country_allow` | JSON array of ISO-3166 alpha-2 (uppercase); `[]`/absent = no restriction | `null` (no restriction) | `[]` **allow none** | security.manage |
| `country_deny` | JSON array of alpha-2 | `[]` | `['*']` **deny all** | security.manage |
| `block_tor` | `'0'`/`'1'` | `'1'` | `'1'` | security.manage |
| `block_datacenter` | `'0'`/`'1'` | `'0'` | `'1'` | security.manage |
| `block_automation` | `'0'`/`'1'` | `'1'` | `'1'` | security.manage |
| `risk_threshold` | integer 1–100; deny when score ≥ threshold | `70` | `50` | security.manage |
| `mfa_policy` | `prompt` `required` | `prompt` | `required` | security.manage |
| `mfa_grace` | `'0'`/`'1'` | `'1'` | `'0'` | security.manage |
| `device_gating` | `'0'`/`'1'` | `'0'` | `'1'` | settings.manage |
| `step_up_minutes` | integer 1–120 | `15` | `5` | settings.manage |
| `session_idle_minutes` | integer 5–1440 | `120` | `30` | settings.manage |
| `session_absolute_hours` | integer 1–72 | `8` | `8` | settings.manage |
| `timezone` | IANA zone accepted by `Intl` | `America/New_York` | `UTC` | settings.manage |
| `privacy_notice` | `'0'`/`'1'` | `'1'` | `'1'` | settings.manage |
| `privacy_notice_text` | string ≤ 500 | see policy.js | default | settings.manage |
| `streak_enabled` | `'0'`/`'1'` | `'1'` | `'1'` | settings.manage |
| `streak_window_hours` | integer 24–72 | `30` | `30` | settings.manage |
| `streak_reentry_grace_hours` | integer 0–24 | `12` | `12` | settings.manage |
| `streak_max_leeway_days` | integer 0–7 | `4` | `4` | settings.manage |
| `streak_weekly_days` | JSON array of weekday numbers 0–6 (0 = Sunday) | `[6]` | `[6]` | settings.manage |
| `streak_hebrew_holidays` | `'0'`/`'1'` | `'1'` | `'1'` | settings.manage |
| `streak_region` | `diaspora` `israel` | `diaspora` | `diaspora` | settings.manage |
| `streak_extra_dates` | JSON array of `{ "date": "YYYY-MM-DD", "label": string }` (≤ 366) | `[]` | `[]` | settings.manage |
| `streak_leaderboard` | `all` `managers` `off` | `all` | `off` | settings.manage |

Blank strings, `null`, booleans and objects submitted as values are
**validation errors**, never defaults (A §14.1). An explicit `0` stays legal
where the range allows it (A §14.11).

`policy.js` exports:

```js
SETTINGS                       // registry: { [key]: { default, perm, description, type, options?, min?, max?,
                               //                      parse(raw) → value, serialize(input) → string (throws ValidationError) } }
resolvePolicy(env) → object    // { access_mode, deny_style, gate_open: {open, until, forever, raw}, country_allow,
                               //   country_deny, block_tor, ..., streak: {...} } — every key parsed; one query
getSettingRaw(env, key) → string|null
writeSetting(rc, key, input) → { prior, value, raw }   // validates + writes; NO guards, NO audit (callers do both)
gateOpenState(raw, nowMs) → { open, until: ms|null, forever: bool }
```

`gateOpenState`: `'0'` → closed; `'1'` → open forever; a string passing
`util.parseIsoStrict` and in the future → open until then; **anything else →
closed** (A §14.2: `'42'` must not mean 2042).

---

## 6. Permissions and guards (rbac.js)

`catalog.js` holds the data. `rbac.js` exports:

```js
effectivePermissions(env, user, nowMs) → authz
  authz = {
    userId, isSuper,                 // isSuper: holds '*' via role or unexpired temp role
    rank,                            // max(role.rank, unexpired user_roles ranks)
    role: { id, key, name, rank },
    perms: Set<string>,              // after denies; '*' expanded to every catalogue key
    sources: { [perm]: 'account' | 'role' | 'temp_role' | 'flag' },
    denied: Set<string>,             // keys removed by perm_denies
  }
can(authz, perm) → bool
canAll(authz, perms[]) → bool
routeNeedsStepUp(perm | perm[]) → bool           // any danger perm
requireStepUp(rc) → void | throws stepUpRequired()   // session.aal === 2 && mfa_at within step_up_minutes
assertCanActOn(actorAuthz, targetAuthz, { allowSelf = false }) → void | throws GuardError('rank')
    // actor.rank > target.rank, or both Super Admins (peers). Self only when allowSelf.
assertCanAssignRole(actorAuthz, role) → void | throws GuardError('minting')
    // role.rank < actor.rank, or actor isSuper. Never a role holding '*' unless actor isSuper.
assertCanGrantPerms(actorAuthz, perms[]) → void | throws
    // every key in the catalogue, none reserved, every one held by the actor
assertNotLastSuper(env, targetUserId, nowMs) → void | throws GuardError('last_superuser')
    // call BEFORE any change that could make the target not an active Super Admin.
    // Counts active super admins (role or unexpired temp role); refuses if the
    // target is one and the count is ≤ 1. Fails CLOSED: if the count cannot be
    // read, refuse.
userAuthz(env, userId, nowMs) → authz            // loads the user, then effectivePermissions
validateRolePermissions(perms) → string[]        // catalogue keys only, no '*', no reserved; throws ValidationError
```

Denies beat grants. Reserved keys in `perm_grants` or in a custom role's
permissions are ignored when reading and refused when writing.

---

## 7. Module contracts

Signatures are binding. "rc" means the request context (§4.1).

### 7.1 ratelimit.js

```js
LIMITS = {
  login_ip:        { max: 20,  windowSec: 600 },   // per IP (allowlisted IPs: max 200)
  login_id:        { max: 10,  windowSec: 900 },   // per normalised identifier
  mfa_user:        { max: 5,   windowSec: 900 },   // factor attempts, login AND step-up
  otp_send:        { max: 5,   windowSec: 900 },   // codes sent per user
  setup_ip:        { max: 5,   windowSec: 3600 },
  curpw_user:      { max: 10,  windowSec: 900 },   // current-password checks
  request_ip:      { max: 5,   windowSec: 3600 },  // access requests
  fp_ip:           { max: 30,  windowSec: 600 },
  invite_ip:       { max: 20,  windowSec: 3600 },  // invitation token lookups
  device_code_user:{ max: 10,  windowSec: 3600 },  // self-approve code guesses
}
charge(env, kind, subject, nowMs, { max }?) → { allowed, count, retryAfterSec }
    // Inserts the attempt AND prunes rows older than 1 day in the same batch,
    // then counts. Charged BEFORE the check it protects (A §6).
peek(env, kind, subject, nowMs) → count
clear(env, kind, subject) → void
```

The per-IP login bucket is **never cleared on success** (B trap 4).

### 7.2 ip.js

```js
parseIp(s) → { v: 4|6, bytes: Uint8Array } | null      // strict; IPv4-mapped IPv6 → v4
normalizeIp(s) → string | null                          // canonical text (RFC 5952 for v6)
parseCidr(s) → { v, bytes, prefix } | null              // bare address = full prefix; host bits must be zero
normalizeCidr(s) → string | null
cidrContains(cidr, ip) → bool                           // strings or parsed; never throws
isPrivateOrReserved(cidr) → bool                        // RFC1918, loopback, link-local, CGNAT, ULA, multicast, doc ranges, etc.
isWholeFamily(cidr) → bool                              // prefix 0
bestMatch(entries, ip) → entry | null                   // entries: [{ cidr, tier, ... }]; most specific wins; tie → higher tier number (stricter)
```

### 7.3 qr.js

```js
qrMatrix(text, { ecc = 'M' }?) → boolean[][]      // byte mode, versions 1–10, ECC M; throws RangeError if too long
qrSvg(text, { margin = 4, scale = 4 }?) → string  // inline SVG, black modules on its OWN white rect
qrDataUri(text, opts?) → 'data:image/svg+xml;base64,...'
```

A blank or whitespace margin falls back to the default, never to 0 (A §14.11);
an explicit `0` is honoured.

### 7.4 calendar/hebrew.js, calendar/protected.js, streak.js

See §9 for the algorithm. Exports:

```js
// hebrew.js — Dershowitz & Reingold, Calendrical Calculations
fixedFromGregorian(y, m, d) → rd          // RD 1 = Monday 1 January 1 CE (proleptic Gregorian)
gregorianFromFixed(rd) → { year, month, day }
weekday(rd) → 0..6                        // 0 = Sunday
HEBREW_EPOCH                              // = fixed-from-julian(3761 BCE, Oct 7) = -1373427
NISAN=1 IYYAR=2 SIVAN=3 TAMMUZ=4 AV=5 ELUL=6 TISHREI=7 MARHESHVAN=8 KISLEV=9 TEVET=10 SHEVAT=11 ADAR=12 ADAR_II=13
isHebrewLeapYear(y), lastMonthOfHebrewYear(y), daysInHebrewYear(y), lastDayOfHebrewMonth(m, y)
hebrewNewYear(y) → rd of 1 Tishrei
fixedFromHebrew(y, m, d) → rd
hebrewFromFixed(rd) → { year, month, day }
yomTovName(rd, { israel = false }) → string | null
    // Rosh Hashanah (1–2 Tishrei), Yom Kippur (10), Sukkos (15; +16 diaspora),
    // Shemini Atzeres (22), Simchas Torah (23 diaspora; in Israel 22 is both),
    // Pesach (15, 21 Nisan; +16, 22 diaspora), Shavuos (6 Sivan; +7 diaspora).
    // Chol hamoed, Purim, Chanukah and fasts are working days → null.

// protected.js
dayString(rd) → 'YYYY-MM-DD'
parseDayString(s) → rd | NaN               // strict shape
isValidTimeZone(tz) → bool
localDay(ms, tz) → rd                       // via Intl formatToParts with an explicit timeZone
zonedMidnightUtc(rd, tz) → ms               // first instant of that local day (DST-safe)
makeProtectedDayFn(cfg) → (rd) => { protected: bool, names: string[] }   // memoised
    // cfg: { weeklyDays: number[], hebrew: bool, israel: bool, extraDates: [{date, label}] }
    // weekly day 6 with hebrew on is named 'Shabbos'; otherwise the weekday name.

// streak.js
streakConfig(policy) → cfg     // { enabled, tz, baseHours, graceHours, maxLeewayDays,
                               //   weeklyDays, hebrew, israel, extraDates, leaderboard, isProtected }
computeDeadline(lastAtMs, cfg) → { deadline, base, leewayDays, graceApplied, blocks: [{ from, to, names }] }
    // from/to are 'YYYY-MM-DD'
streakStatus(row, nowMs, cfg) → status        // PURE — never writes (A §10 "read without rewriting")
touchStreak(env, userId, nowMs, cfg) → status | null   // NEVER throws; null on any failure
getStreak(env, userId, nowMs, cfg) → status
streakHistory(env, userId, nowMs, cfg, days = 84) → [{ day, counted, protected, names, today, future }]
upcomingProtected(cfg, nowMs, days = 21) → [{ day, names }]
leaderboard(env, nowMs, cfg, limit = 10) → [{ user_id, full_name, current, longest }]
adjustStreak(env, userId, { current, longest }, nowMs, cfg) → { prior, row }   // admin restore; caller audits
streakRules(cfg) → { window_hours, reentry_grace_hours, max_leeway_days, calendar: string }

status = {
  state: 'none' | 'active' | 'at_risk' | 'paused' | 'lapsed' | 'held',
  current,            // what to DISPLAY (0 when lapsed)
  stored_current,     // what the row holds
  longest, total_days,
  counted_today,      // bool
  last_at, last_day, started_day,
  deadline,           // ISO or null
  deadline_local,     // e.g. 'Sun 12:00 PM' in the portal zone, or null
  hours_left,         // number (1 decimal) or null
  protected_today: { names } | null,
  timezone,
}
```

### 7.5 webauthn/*

```js
// cbor.js — strict decoder: definite lengths only, refuses duplicate map keys,
// refuses trailing bytes, caps depth/length. Maps decode to Map.
decodeCbor(bytes) → value          // throws CborError
decodeCborPrefix(bytes) → { value, length }   // for COSE keys embedded in authData

// der.js — strict DER ECDSA → raw r||s (A §7.4 point 1)
derToRaw(der, coordinateBytes = 32) → Uint8Array   // throws on any non-canonical encoding

// cose.js
coseToJwk(coseMap) → { jwk, alg }          // ES256 (-7, EC2 P-256) or RS256 (-257, RSA)
validatePublicKey(jwk, alg) → void          // throws; THE one validator, used at enrolment and every assertion
    // EC: crv P-256, x/y exactly 32 bytes, alg matches kty
    // RSA: modulus 1024–8192 bits and ODD; exponent ODD, ≥ 3, ≤ 8 bytes (A §14.5)
importVerifyKey(jwk, alg) → CryptoKey

// webauthn.js
registrationOptions(rc, user) → options JSON            // stores challenge (kind 'register'), excludes existing credentials
verifyRegistration(rc, user, credential, label) → passkey row (inserted)
assertionOptions(rc, user, kind = 'auth' | 'stepup') → options JSON
verifyAssertion(rc, user, credential, kind) → { passkeyId }   // throws HttpError(400/401) with a reason
```

Checks are the full lists in A §7.4 (registration and assertion tables),
including: challenge row deleted on use whether or not the ceremony then
succeeds; origin equals `env.ORIGIN` exactly; `rpIdHash` equals
SHA-256(`env.RP_ID`); UP flag; credential registered to *this* user; stored key
re-validated on every use; signature counter strictly increases when either
side is non-zero (a regression is refused and audited as
`mfa.passkey.counter_regressed`); authenticator data accounts for every byte.
`pubKeyCredParams` offers only -7 and -257. Challenge TTL 5 minutes; issuing
one prunes expired rows.

Wire format (base64url everywhere):

```js
// options → browser
{ challenge, rp: { id, name }, user: { id, name, displayName }, pubKeyCredParams, timeout,
  attestation: 'none', authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
  excludeCredentials: [{ type: 'public-key', id, transports? }] }
{ challenge, rpId, timeout, userVerification: 'preferred', allowCredentials: [{ type, id, transports? }] }
// browser → server
{ id, rawId, type: 'public-key', response: { clientDataJSON, attestationObject, transports? } }
{ id, rawId, type: 'public-key', response: { clientDataJSON, authenticatorData, signature, userHandle? } }
```

`tests/helpers/authenticator.js` (owned by the webauthn work) is a software
authenticator that produces real ES256 and RS256 responses for these shapes,
with knobs for every negative case.

### 7.6 mfa/* and notify.js

```js
// totp.js — RFC 6238: SHA-1, 6 digits, 30 s step, ±1 step
base32Encode(bytes), base32Decode(str) → Uint8Array | null
generateTotpSecret() → Uint8Array(20)
totpCode(secretBytes, counter) → '123456'
verifyTotp(secretBytes, code, nowMs, lastCounter) → counter | null
    // secret < 16 bytes → null (A §7.3); code must be /^\d{6}$/ after removing spaces;
    // lastCounter: null/undefined = no floor; a safe integer = floor (refuse ≤ floor);
    // ANYTHING ELSE = refuse every code (A §14.3).
otpauthUri({ issuer, account, secretB32 }) → string
groupSecret(b32) → 'ABCD EFGH ...'
beginTotp(rc, userId) → { secret_b32, secret_grouped, otpauth, qr }   // qr = data URI; stores encrypted, confirmed_at NULL
confirmTotp(rc, userId, code) → { backup_codes: string[] | null }    // generates backup codes if the user has none unused
checkTotp(rc, userId, code) → bool          // sign-in / step-up; advances last_counter; audits decrypt failures + unreadable floors
removeTotp(rc, userId) → void               // caller must have checked canDropFactor

// backup.js
BACKUP_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'   // no 0 1 I O L
generateBackupCodes(n = 10) → ['ABCDE-FGHJK', ...]    // rejection sampling
normalizeBackupCode(input) → 'ABCDEFGHJK' | null        // uppercase, strip spaces/hyphens, SHAPE-GATED (A §14.4)
storeBackupCodes(env, userId, codes, nowMs) → void       // replaces unused set; one salt per set; PBKDF2 one chunk
consumeBackupCode(rc, userId, input) → bool              // one KDF per attempt; marks used_at
countUnusedBackupCodes(env, userId) → number

// token.js — the half-finished sign-in (A §7.2)
issueMfaToken(env, userId, destinationId, nowMs) → token   // 5 minutes; signed 'mfa'
readMfaToken(env, token, nowMs) → { userId, destinationId } | null

// otp.js — texted / emailed codes
listDestinations(env, userId, { usableOnly }) → [{ id, kind, hint, label, is_primary }]
primaryDestination(env, userId) → row | null             // usable only (provider configured)
sendCode(rc, userId, destinationId) → { sent, kind, hint }   // 6 digits, 10 min, hashed; rate-limited (otp_send)
verifyCode(rc, userId, destinationId, code) → bool        // ≤ 5 attempts per challenge; single use
addDestination(rc, userId, { kind, address, label }) → row      // caller enforces destinations.manage
removeDestination(rc, userId, destinationId) → void       // never the only usable one if it is the last factor; promotes a new primary

// factors.js
userFactors(env, userId) → { totp: bool, totpUnreadable: bool, passkeys: n, backup: n, destinations: n (usable) }
availableMethods(env, userId) → ['passkey' | 'totp' | 'backup' | 'email' | 'sms', ...]   // strongest first
hasStrongFactor(env, userId) → bool          // passkey or confirmed TOTP; backup codes alone do NOT count (A §7.1)
canDropFactor(env, userId, dropping: 'totp' | 'passkey' | { destinationId }) → bool
resetFactors(rc, userId) → { cleared }       // admin "lost phone": totp + passkeys + backup + grace;
                                             // refuses (GuardError 'nothing_left') unless a usable destination remains;
                                             // records undo 'mfa.reset' with the encrypted TOTP blob, passkey rows, backup rows

// notify.js
smsConfigured(env), emailConfigured(env) → bool
sendSms(env, to, body) → { sent, provider, error? }     // Twilio REST; never throws
sendEmail(env, to, subject, text) → { sent, provider, error? }   // Resend; never throws
maskPhone(s) → '•••• 1234', maskEmail(s) → 'j•••@acme.com'
```

A TOTP row that will not decrypt is **refused** and audited as
`mfa.decrypt_failed` (critical), never treated as "no authenticator" (A §7.3).

### 7.7 users.js, invitations.js, sessions.js

```js
// users.js
getUser(env, id) → row | null
findUserByIdentifier(env, identifier) → row | null       // email or username, case-insensitive
listUsers(env, { status?, q?, role?, managerId?, limit, offset }) → { users: publicUser[], total }
publicUser(row, role?) → object                          // §4.5
validatePassword(pw, { email, username }?) → void | throws ValidationError
    // 12–1024 chars; not equal to email/username; not all one character
setPassword(env, userId, password, { mustChange = false }) → void
changeOwnPassword(rc, current, next) → void              // charges curpw_user; drops OTHER sessions; clears password_change pin
adminResetPassword(rc, userId) → { temporary_password }  // reserved perm; rank guard; drops sessions + grace; must_change
createUser(rc, { email, full_name, role_id, username?, employee_no?, job_title?, department?, manager_id?, status = 'invited' }) → row
    // rank + minting guards; auto employee number; explicit duplicate checks → 409 with a sentence
updateProfile(rc, userId, patch) → { prior, row }        // full_name, username, job_title, department, manager_id, employee_no, phone
setStatus(rc, userId, status) → { prior, row }           // 'active' | 'suspended' | 'disabled'; guards: rank, self, last super; suspend/disable drops sessions + grace
changeRole(rc, userId, { role_id, perm_grants, perm_denies }) → { prior, row }   // guards: rank on target (before AND after), minting, grant, last super
grantTempRole(rc, userId, roleId, expiresAtIso) → { prior }   // expiry required, future, ≤ 90 days
revokeTempRole(rc, userId, roleId) → { prior }
nextEmployeeNo(env) → 'ACME000001'                       // from the highest issued (meta high-water + max existing), never a count
recordLoginFailure(env, user, nowMs) → void              // failed_logins++, lock 15 min at 10
clearLoginFailures(env, userId) → void
isLocked(user, nowMs) → bool
mfaPolicyFor(user, policy) → 'prompt' | 'required'      // user.mfa_policy 'inherit' → policy.mfa_policy; Super Admin → 'required'
countActiveUsers(env) → n
anyUsers(env) → bool

// invitations.js
createInvitation(rc, userId, { roleId, email }) → { token, url, expires_at }   // token stored as SHA-256 only; 7 days; revokes earlier ones for that user
lookupInvitation(env, token, nowMs) → { invitation, user } | null    // unused, unrevoked, unexpired, user status 'invited'
acceptInvitation(rc, token, { password, full_name? }) → user          // sets password, activates, approves rc.device (minting one if needed)
revokeInvitation(rc, invitationId), reissueInvitation(rc, userId) → {token, url, expires_at}
listInvitations(env, { pending }) → rows (no token material)
createAccessRequest(rc, { email, full_name, reason }) → { id }      // request_ip rate limit; records ip/country/visitor/risk
listAccessRequests(env, { status }) → rows
approveAccessRequest(rc, id, { role_id }) → { user, invitation }      // creates the invited user + invitation
denyAccessRequest(rc, id) → void

// sessions.js
SESSION_COOKIE = '__Host-sid'
createSession(rc, user, { aal, mfaAt, mfaMethod, pinned, deviceId }) → { id, cookie }
    // prunes expired sessions in the same batch
loadSession(rc) → { session, user, authz } | null   // sets rc.session/user/authz
    // refuses: unknown, revoked, idle- or absolute-expired, user not 'active',
    // access_mode lockdown and user not Super Admin. Extends idle expiry at most once a minute.
nextPin(env, user, policy) → null | 'password_change' | 'mfa_enroll'
setPin(env, sessionId, pin) → void
markStepUp(env, sessionId, method, nowMs) → void     // aal = 2, mfa_at = now
hasFreshStepUp(rc) → bool
revokeSession(env, id, reason), revokeUserSessions(env, userId, reason, { exceptId }) → n
listUserSessions(env, userId, currentId) → [{ id_ref, created_at, last_seen_at, ip, ua, aal, current }]
    // id_ref = first 12 hex of the stored hash: enough to act on, useless as a credential
clearSessionCookie() → string
```

### 7.8 devices.js, grace.js, network.js, fingerprint.js, gate.js

```js
// devices.js
DEVICE_COOKIE = '__Host-dev'
readDevice(rc) → { id, row } | { id: null, row: null }   // HMAC verified BEFORE any query
ensureDevice(rc) → { id, row, setCookie|null }            // mints if absent; caps pending (≤ 2000 rows; prunes stale pending > 30 days)
trackDevice(rc, userId) → { id, setCookie|null }           // ensureDevice + device_users ledger + last_seen/ip/label
deviceCode(id) → 'K7F3-9QX2'                               // what the pending page shows and an admin types
findDeviceByCode(env, code) → row | null
setDeviceStatus(rc, deviceId, status, { label? }) → { prior, row }   // 'pending' | 'approved' | 'blocked'; blocking/revoking drops grace + sessions on that device
renameDevice(rc, deviceId, label) → { prior, row }
revokeDevice(rc, deviceId) → void                          // status back to 'pending', grace dropped, sessions revoked
listDevices(env, { status?, userId?, limit }) → rows (+ users who signed in on each)
deviceLabelFromUa(ua, hints) → 'Chrome on macOS'          // UA first; client hints are a bonus (A §14.7)

// grace.js
GRACE_MS = { 1: 7 * DAY, 2: DAY, 3: 2 * HOUR, 4: 0 }
recordGrace(env, userId, deviceId, tier, nowMs) → void
graceValid(env, userId, deviceId, currentTier, nowMs) → { valid, verifiedAt }   // min(stored expiry, verified_at + window(currentTier)); no tier → invalid
dropGrace(env, { userId?, deviceId? }) → void

// network.js
tierForIp(env, ip, nowMs) → { tier, entry } | null          // live entries only; most specific wins; tie → stricter
isIpBlocked(env, ip, nowMs) → bool
listAllowed(env, nowMs), listBlocked(env, nowMs) → rows with { active, covers_ip? }
addAllowed(rc, input) → row      // { cidr, tier 1–4, label?, owner?, user_id?, expires_at? | expires_in_hours? }
                                 // refuses private/reserved and whole-family (§A 4); tier 4 gets 24h if no expiry
editAllowed(rc, id, patch) → { prior, row }
removeAllowed(rc, id) → { row }  // the anti-lockout checks live in guards.js and are called by the API AND the reverter
addBlocked(rc, input) → row, removeBlocked(rc, id) → { row }

// fingerprint.js
edgeSignals(request, cf) → { ip, country, asn, as_org, colo, city, tls_version, tls_cipher, http_protocol,
                            bot_score, ja3, ja4, ua, accept_language, sec_ch_ua, sec_ch_ua_mobile,
                            sec_ch_ua_platform, sec_fetch_site, sec_fetch_mode, sec_fetch_dest, header_names }
sanitizeClientSignals(obj) → object | null                    // type + size caps; unknown keys dropped
scoreRisk(edge, client|null) → { score: 0–100, flags: [{ key, weight, reason }] }
    // every flag has a plain-English reason (B §6)
automationTells(edge, client|null) → string[]                 // named tells: 'webdriver', 'headless-ua', ...
isDatacenterAsn(asn) → bool
fingerprintHash(edge, client) → hex, visitorId(edge, client) → hex   // visitor id = stable subset
recordFingerprint(rc, { client }) → { hash, visitor_id, risk }  // upsert + trim (by last_seen AND count)
FP_COOKIE = '__Host-fp'; fpCookie(env, hash, risk, nowMs) → Set-Cookie; readFpCookie(rc) → { hash, risk } | null
recordVisit(rc, { decision, reason }) → void                  // + trim by count and age; never throws

// gate.js
evaluateGate(rc) → {
  allowed: 'all' | 'shell' | 'none',
  shell: null | 'setup' | 'request' | 'pending' | 'login' | 'invite',
  reason: string,               // machine reason, e.g. 'not_allowlisted', 'country', 'risk', 'tor'
  mode, trusted, ipTier, risk: { score, flags }
}
shellAllows(shell, method, path) → bool
denyResponse(policy) → Response   // empty 403, or a decoy 404 that looks like a stock server page
PASS_COOKIE = '__Host-pass'       // short-lived signed pass after a valid invitation link
```

`evaluateGate` order (each step fully decides before the next):

1. Blocked device → none. No usable IP → none. Blocklisted IP → none.
2. Unless the IP is allowlisted (B trap 8: an allowlisted IP legitimately
   bypasses country rules): country allow/deny (`T1` is Tor), Tor, datacenter
   ASN, automation tells, risk ≥ threshold → none.
3. No users exist yet → shell `setup`.
4. `trusted` = allowlisted IP **or** approved device. `open` = `gate_open`
   active (never in lockdown).
   - `lockdown`: allowlisted IP **and** approved device, else none.
   - `allowlist`, `invite_only`: trusted or open, else a valid pass cookie →
     shell `invite`, else none.
   - `request_access`: trusted or open → all; else pass → `invite`; else
     shell `request`.
   - `fingerprint_gate`: trusted or a valid fp cookie under the threshold →
     all; else shell `login` (the login page reports a fingerprint first).
   - `public`: all.
5. `device_gating` on and the device is not approved → shell `pending`
   (or `invite` when a pass cookie is present — accepting approves it).

Shell path sets (GET unless noted). Every shell also allows `/healthz`,
`/css/app.css`, `/js/common.js`, `/favicon.svg`.

| shell | pages | assets | API |
|---|---|---|---|
| setup | `/`, `/setup` | `/js/setup.js` | `GET /api/setup/status`, `POST /api/setup` |
| request | `/`, `/request-access` | `/js/request.js`, `/js/fp.js` | `POST /api/access-request`, `POST /api/fp` |
| login | `/`, `/login` | `/js/login.js`, `/js/fp.js`, `/js/webauthn.js` | `POST /api/fp`, `GET /api/auth/whoami` |
| invite | `/invite` | `/js/invite.js`, `/js/fp.js` | `GET /api/invite/:token`, `POST /api/invite/accept`, `POST /api/fp` |
| pending | any navigation shows `/pending` | `/js/pending.js` | `GET /api/device/status`, `GET /api/diag` |

### 7.9 signin.js

```js
completeSignIn(rc, user, how, { aal, mfaAt = null, factorVerified = false }) → Response
```

The single tail for password-only, grace, TOTP, backup code, emailed/texted
code, passkey and invitation sign-ins (A §7.2, §14.8). In order:
`trackDevice` → `recordGrace` (only when `factorVerified` and the IP has a
tier) → `nextPin` → `createSession` → `last_login_at` → clear per-account
counters (`login_id`, `mfa_user`, `failed_logins`; **not** `login_ip`) →
audit `login.success` "Signed in with {how}" → `touchStreak` (never blocks) →
200:

```js
{ ok: true, user: publicUser, pinned: null | 'password_change' | 'mfa_enroll',
  enroll_prompt: bool, next: '/' | '/account?pin=…', streak: status | null }
```

---

## 8. HTTP

### 8.1 Pipeline (worker.js)

1. `/healthz` → `200 ok` text, before anything (A §11 liveness).
2. Secrets present, else empty 503.
3. `ensureSchema`, `buildContext`, `evaluateGate`.
4. `recordVisit` via `ctx.waitUntil` for: every denial, every HTML navigation,
   every non-GET `/api/*`. Not for asset GETs.
5. `allowed === 'none'` → `denyResponse`.
6. Non-GET requests must carry `Origin` equal to `env.ORIGIN` (or
   `Sec-Fetch-Site: same-origin` with no Origin) → else empty 403.
7. `loadSession`.
8. Shell restriction (`shellAllows`); a navigation outside the shell gets the
   shell's page where §7.8 says so, otherwise the deny response.
9. Pages (§8.3) → assets (`/css/*`, `/js/*`, `/favicon.svg` via
   `env.ASSETS.fetch`) → API router → else 404 (JSON for `/api/*`).
10. Route checks: `auth` (`none` / `session` / `pinned-ok`), then `perm`, then
    step-up for non-GET routes whose perms include a danger key.
11. Append `rc.setCookies`; apply security headers to **every** response,
    including the empty ones.

### 8.2 Security headers

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

### 8.3 Pages (decided server-side — no flash of the wrong page, B §10)

| path | serves |
|---|---|
| `/` | dashboard (signed in, unpinned) · redirect `/account?pin=…` (pinned) · login (signed out) · shell page in a shell |
| `/login` | login, or redirect `/` if signed in |
| `/account` | account (signed in, pinned OK) else redirect `/login?next=/account` |
| `/admin` | admin console if the user holds any of `users.view team.view directory.view devices.view network.view audit.view settings.view roles.view visitors.view sessions.view streaks.view_all requests.manage users.invite`; otherwise redirect `/` |
| `/setup` | setup (setup shell only) |
| `/invite` | invite (sets the pass cookie when `?token=` is valid) |
| `/request-access` | request (request shell) |
| `/pending` | pending (pending shell) |

HTML files live in `public/*.html` and are fetched from `ASSETS` by name;
direct requests for `*.html` paths are 404.

### 8.4 API

`auth` column: **none** = no session needed (still behind the gate);
**session**; **pinned** = `pinned-ok`. Perm = required permission(s).

#### Public

| method path | auth | body → response |
|---|---|---|
| GET /api/setup/status | none | → `{ needed: bool, org_name }` (setup shell only) |
| POST /api/setup | none | `{ setup_key, email, full_name, password }` → completeSignIn response. Key compared in constant time; setup_ip limit; one-shot claim row in `meta` that **expires after 10 minutes** (B trap 3); creates the Super Admin, allowlists the caller's IP as tier 1 (`/32` or `/128`), approves the device, signs in pinned to `mfa_enroll`. Afterwards the route is unreachable. |
| GET /api/invite/:token | none | → `{ email, full_name, org_name, expires_at }` or 404; invite_ip limit |
| POST /api/invite/accept | none | `{ token, password, full_name? }` → completeSignIn response |
| POST /api/access-request | none | `{ email, full_name, reason }` → `{ ok: true }` (identical whether or not the email is known) |
| POST /api/fp | none | `{ signals }` → `{ ok: true }`; sets fp cookie |
| GET /api/diag | none | → `{ cookies: { names, count }, ua, client_hints, ip, country, asn, tls_version, http_protocol, device: { present, status, code }, session: { present, valid } }` — names only, never values (A §5) |
| GET /api/device/status | none | → `{ code, status, label }`; mints a pending device if none |

#### Auth

| method path | auth | body → response |
|---|---|---|
| POST /api/auth/login | none | `{ identifier, password }` → completeSignIn response, or `{ mfa_required: true, token, methods, destinations: [{ id, kind, hint }], sent: { kind, hint } \| null }`; failures are byte-identical `401 { error: 'Invalid credentials.' }`; lockdown non-super → `403`; fingerprint_gate without fp → `403 { fingerprint_required: true }` |
| POST /api/auth/mfa/code | none | `{ token, code }` (TOTP **or** backup code — one box, A §7.3) → completeSignIn |
| POST /api/auth/mfa/send | none | `{ token, destination_id }` → `{ token, sent: { kind, hint } }` (new token bound to the destination) |
| POST /api/auth/mfa/otp | none | `{ token, code }` → completeSignIn |
| POST /api/auth/mfa/passkey/options | none | `{ token }` → assertion options |
| POST /api/auth/mfa/passkey/verify | none | `{ token, credential }` → completeSignIn |
| POST /api/auth/logout | pinned | → `{ ok: true }`; clears the session cookie |
| GET /api/auth/whoami | none | → `{ authenticated: bool, user?, pinned?, enroll_prompt? }` |

Every factor endpoint re-checks `status === 'active'` and lockdown, and
charges `mfa_user` before verifying.

#### Me

| method path | auth | notes |
|---|---|---|
| GET /api/me | pinned | `{ user, permissions: [...], sources, pinned, enroll_prompt, step_up_fresh, factors: userFactors, org_name, timezone, privacy_notice }` |
| PATCH /api/me | session | `{ full_name }` |
| POST /api/me/password | pinned | `{ current, next }` |
| GET /api/me/streak | session | `{ enabled, status, history, upcoming, rules, leaderboard: [...] \| null }` |
| GET /api/me/sessions | session | list; DELETE /api/me/sessions/:ref; POST /api/me/sessions/revoke-others |
| GET /api/me/devices | session | devices this user signed in on; DELETE /api/me/devices/:id (forget: revoke grace + sessions there) |
| POST /api/me/devices/approve | session + step-up | `{ code }` — approve a pending device for yourself; only from an **approved** current device; device_code_user limit |
| GET /api/me/activity | session | own last 50 audit rows (no undo data) |
| GET /api/me/fingerprint | session | own latest fingerprint, risk score and reasons |
| GET /api/me/step-up | session | `{ methods, destinations }` |
| POST /api/me/step-up/code, /send, /otp, /passkey/options, /passkey/verify | session | as the login factor endpoints, but bound to the session; success → `markStepUp` |
| POST /api/me/mfa/totp/begin | pinned | → `{ secret_grouped, otpauth, qr }` |
| POST /api/me/mfa/totp/confirm | pinned | `{ code }` → `{ backup_codes: [...] \| null, pinned }`; marks step-up |
| DELETE /api/me/mfa/totp | session + step-up | canDropFactor |
| POST /api/me/mfa/passkey/options | pinned | registration options |
| POST /api/me/mfa/passkey/register | pinned | `{ credential, label }` → `{ passkey, backup_codes, pinned }` |
| PATCH /api/me/mfa/passkey/:id | session | `{ label }` |
| DELETE /api/me/mfa/passkey/:id | session + step-up | canDropFactor |
| POST /api/me/mfa/backup/regenerate | session + step-up | → `{ backup_codes }` (shown once) |

#### Admin (people, roles, devices, sessions, streaks, audit — `admin.js`)

| method path | perm |
|---|---|
| GET /api/admin/overview | any admin-console perm — counts the caller may see |
| GET /api/directory | directory.view |
| GET /api/admin/users · GET /api/admin/users/:id | users.view (or team.view for own reports) |
| POST /api/admin/users | users.invite — `{ email, full_name, role_id, ... }` → `{ user, invitation: { url, expires_at } }` |
| PATCH /api/admin/users/:id | users.edit |
| POST /api/admin/users/:id/status | users.suspend (`active`↔`suspended`) / users.disable (`disabled`↔`active`) |
| POST /api/admin/users/:id/role | users.roles — `{ role_id, perm_grants, perm_denies }` |
| POST /api/admin/users/:id/temp-role · DELETE /api/admin/users/:id/temp-role/:roleId | users.roles |
| POST /api/admin/users/:id/reset-password | users.reset_password (reserved) |
| POST /api/admin/users/:id/reset-mfa | users.reset_mfa |
| POST /api/admin/users/:id/logout | users.suspend |
| POST /api/admin/users/:id/revoke-devices | users.suspend |
| GET/POST /api/admin/users/:id/destinations · DELETE …/destinations/:did | destinations.manage (reserved) |
| POST /api/admin/users/:id/invitation | users.invite — reissue |
| POST /api/admin/users/:id/streak | streaks.manage — `{ current, longest, reason }` |
| GET /api/admin/invitations · POST /api/admin/invitations/:id/revoke | users.invite |
| GET /api/admin/requests · POST …/:id/approve `{ role_id }` · POST …/:id/deny | requests.manage |
| GET /api/admin/roles · GET /api/admin/permissions | roles.view |
| POST /api/admin/roles · PATCH /api/admin/roles/:id · DELETE /api/admin/roles/:id | roles.manage (reserved) |
| GET /api/admin/devices · POST …/:id/approve · …/:id/block · …/:id/unblock · …/:id/rename · DELETE …/:id | devices.view / devices.approve / devices.manage |
| GET /api/admin/sessions · DELETE /api/admin/sessions/:ref | sessions.view / sessions.revoke |
| GET /api/admin/streaks | streaks.view_all (all) or team.view (own reports) |
| GET /api/admin/audit | audit.view — `?action=&actor=&target_type=&target_id=&outcome=&severity=&q=&before_seq=&limit=` → `{ entries, next_before_seq }`; each entry has `revertible`, `reverted_by` — **never** `undo_payload` |
| POST /api/admin/audit/verify | audit.verify → `{ ok, checked, head_seq, broken_at }` |
| POST /api/admin/audit/:id/revert | audit.revert (reserved) |

#### Admin (security — `admin-security.js`)

| method path | perm |
|---|---|
| GET /api/admin/settings | settings.view → `{ settings: [{ key, value, raw, default, perm, type, options, min, max, description, can_edit }] }` |
| PUT /api/admin/settings | per key (§5) — `{ changes: { key: value } }` → `{ ok, applied: [...], warnings: [...], notices: [...] }`; blocking guards → 409 `{ code: 'self_lockout', error }` |
| GET /api/admin/gate · POST /api/admin/gate/open `{ hours }` or `{ forever: true }` · POST /api/admin/gate/close | gate.open (reserved) |
| GET /api/admin/network | network.view → `{ allow, block, you: { ip, country, asn, tier, covered_by } }` |
| POST /api/admin/network/allow · PATCH …/allow/:id · DELETE …/allow/:id | network.manage |
| POST /api/admin/network/block · DELETE …/block/:id | network.manage |
| GET /api/admin/visitors · GET /api/admin/visits | visitors.view |

`hours` for the gate: rejected unless an integer 1–168 **before** any coercion
of `null`, `''`, `undefined` or a boolean (A §14.1). "Open until I close it"
needs the explicit `{ forever: true }`.

### 8.5 Self-lockout guards (guards.js — B trap 8, A §4)

Called by the settings/network API **and** by the reverters.

Blocking (409 `self_lockout`):
- deleting the last live allowlist entry;
- deleting/editing/expiring an entry when no remaining live entry would cover
  the caller's address;
- a block range containing the caller's address;
- `country_allow` / `country_deny` that would refuse the caller's country,
  unless the caller's IP is allowlisted;
- `block_tor` / `block_datacenter` / `block_automation` that the caller
  currently trips, unless allowlisted;
- `risk_threshold` at or below the caller's current risk, unless allowlisted;
- `access_mode: lockdown` unless the caller is a Super Admin on an
  allowlisted IP.

Auto-approve instead of refusing (A §5 "turning gating on must auto-approve
the device doing the turning"): enabling `device_gating`, or switching to
`allowlist`/`invite_only`/`lockdown`, approves the caller's current device in
the same request and returns a notice.

Warnings (saved, with a sentence): enabling device gating or a restrictive
mode while N active users have no approved device and no allowlisted address;
`mfa_policy: required` while N active users have no factor.

---

## 9. The streak algorithm

Inputs: `lastAt` (ms of the most recent sign-in), `cfg` (§7.4).
`H` = 3,600,000 ms, `D` = 86,400,000 ms. Days are portal-local (`cfg.tz`).

```
lastDay  = localDay(lastAt)
base     = lastAt + baseHours·H
hardCap  = base + maxLeewayDays·D + graceHours·H      // a calendar bug can never exceed this
deadline = base
repeat at most 8 rounds:
    endDay  = localDay(deadline)
    count   = |{ d : lastDay < d ≤ endDay, isProtected(d) }|
    closed  = the latest d with lastDay < d < endDay, isProtected(d) and not isProtected(d+1)
              (a protected block that ENDS inside the window), or none
    next    = base + min(count, maxLeewayDays)·D
    if closed and graceHours > 0:
        next = max(next, zonedMidnightUtc(closed + 1) + graceHours·H)   // re-entry grace (B)
    next    = min(next, hardCap)
    if next == deadline: stop                // converged; next is monotone non-decreasing
    deadline = next
```

Worked values with the defaults (30h window, 12h re-entry grace, Shabbos +
diaspora Yom Tov): a regular day 30h; across Shabbos 54h; a two-day Yom Tov
78h; Yom Tov Thursday–Friday into Shabbos 102h (A's table). Re-entry grace
only ever lengthens a window: signing in at 11pm Friday gives until noon
Sunday, not 5am.

`touchStreak(env, userId, nowMs, cfg)` — called by `completeSignIn` only:

- No row → `current = longest = total_days = 1`, `started_day = last_day =
  today`, `last_at = now`.
- `last_at` unreadable → restart at 1 (longest kept) and audit `streak.error`.
- `last_at` more than 5 minutes in the future (a clock moved, a restore) →
  **hold**: change nothing (A §11).
- Same local day as `last_day` → `last_at = max(last_at, now)` only.
- Later day: `now ≤ computeDeadline(last_at).deadline` → `current + 1`, else
  restart at 1 (`started_day = today`). `longest = max`, `total_days + 1`,
  `last_day = today`, `last_at = now`, insert `streak_days(today)`, prune that
  user's `streak_days` older than 400 days in the same batch.
- Concurrency: the update is conditional on the `last_day` it read
  (`… WHERE user_id = ? AND last_day IS ?`); zero rows changed means another
  sign-in won — re-read and treat as same-day. First insert is
  `ON CONFLICT DO NOTHING` + re-read. No double counting (A §11).
- Wrapped whole in try/catch → `null`. The e2e suite drops the `streaks` table
  and asserts sign-in still succeeds (A §10).

`streakStatus` (read-only, never writes):
`none` (no row) · `held` (last_at in the future) · `lapsed` (now > deadline →
display `current` 0, longest intact) · `paused` (today is protected and not yet
counted) · `at_risk` (not counted today and < 6h left) · `active`.

---

## 10. Pages and browser code

- One HTML file per page in `public/`, each loading `/css/app.css` and one
  module script `/js/<page>.js`. No inline script or style. No `style=""`.
- `public/js/common.js` exports the shared kit: `h(tag, attrs, ...children)`
  (sets attributes and `textContent` only — `on*` attributes become
  `addEventListener`), `api(method, path, body)` (JSON, same-origin, throws
  `ApiError { status, body }`), `fmtDate`, `fmtRelative`, `safeNext(url)` (same
  host only: refuses off-site, `//host`, `javascript:`, `http:` downgrade,
  junk — A §7.5), `toast`, `stepUp()` (the modal that satisfies
  `step_up_required` and retries), `showError`.
- `public/js/webauthn.js`: `supportsPasskeys()`, `createPasskey(options)`,
  `getPasskey(options)` — base64url ⇄ ArrayBuffer both directions, with a loop
  (A §7.4); returns the wire shapes of §7.5. `NotAllowedError`/`AbortError`
  become `{ cancelled: true }` (A §7.6).
- `public/js/fp.js` (edge work): `collectSignals({ deadlineMs = 1500 })` and
  `reportFingerprint()` → never throws, every probe individually trapped,
  resolves `{ ok }`.
- Dark mode via `prefers-color-scheme` with tokens on `:root`; no toggle. The
  QR image always sits on its own white plate.
- Login state machine: A §7.6 exactly — auto-sent code, one method opens
  directly, a chooser for two or more, an explanation (not an empty list) for
  none the browser can offer; "use a different method" keyed off what the
  browser can offer; a cancelled passkey dialog returns to the chooser; a spent
  challenge turns Retry into "Start over"; after success ask `whoami` and say
  plainly when the cookie did not stick.
- The dashboard leads with the streak: the flame and count, longest, the
  state in words, the exact deadline in the portal's time zone, "paused for
  Shabbos" when today is protected, the 12-week history strip (counted /
  protected / missed / today), the next three weeks of protected days, the
  rules in one sentence, and the leaderboard when the setting allows.

---

## 11. Retention

| table | trimmed by | rule |
|---|---|---|
| auth_attempts | `ratelimit.charge` | older than 1 day |
| visits | `recordVisit` | older than 30 days; keep newest 50,000 |
| fingerprints | `recordFingerprint` | `last_seen` older than 90 days; keep newest 20,000 by `last_seen` |
| webauthn_challenges | issuing one | expired |
| otp_challenges | sending one | expired more than 1 day ago |
| sessions | `createSession` | absolute-expired or revoked more than 7 days ago |
| devices (pending) | `ensureDevice` | pending and unseen 30 days; cap 2,000 pending |
| streak_days | `touchStreak` | that user's rows older than 400 days |
| audit_log | never | paged in the UI; the chain verifies from genesis |
| allowed_ips | never | expired rows are kept and excluded by queries |

---

## 12. Tests

- `npm test` runs `tests/**/*.test.mjs`, each in its own process, via
  `tests/run.mjs` (passed / failed / DID NOT REPORT).
- Suites import `tests/helpers/t.js` and end with `await run()`.
- `tests/helpers/env.js` → `makeEnv()` / `makeEnvWithSchema()`; real SQLite.
- `tests/helpers/http.js` → `Client` drives `worker.fetch` with cookies, IP and
  `cf` (one Client = one browser).
- `tests/helpers/authenticator.js` → software passkeys (webauthn work).
- `tests/helpers/dom.js` → minimal DOM stub for page scripts (ui work, A §13.4).
- Assert on **absence** as well as presence (no text was sent; no key material
  in a payload; exactly one new audit row) — A §13.8.
- Every module reachable from unauthenticated input is tested against
  `[null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol()]`.
- Mutation-check the important suites (A §13.7): break the code on purpose,
  confirm a test fails, restore.
