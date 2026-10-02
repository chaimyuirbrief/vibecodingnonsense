# Staff portal

The staff side of a small company's web presence: one Cloudflare Worker, on its
own subdomain, that decides who works here, what they may reach, from which
devices, and what they did — and greets everyone who signs in with a 🔥
sign-in streak that never breaks for a day they could not have signed in.

Every request, stylesheets included, passes a gate before anything is served,
and a visitor the gate refuses sees an empty page. Signing in takes a password
and a real second factor. It runs on Workers, D1 and Workers Assets with no
framework, no build step and no runtime dependencies. The design and the
reasoning behind it are in [SPEC.md](SPEC.md); exact routes, settings and module
contracts are in [docs/CONTRACTS.md](docs/CONTRACTS.md).

**Features**

- **🔥 Sign-in streak.** Counts consecutive days signed in, with a 30-hour
  window that grows by exactly the days nobody can sign in: Shabbos and Yom Tov
  by default (computed arithmetically, diaspora or Israel), plus any weekly days
  and closure dates you configure. The dashboard shows the exact deadline, a
  12-week history, the protected days coming up, and an optional leaderboard;
  an administrator can restore a streak, and undo the restore.
- **An access gate with six modes**, from `public` to `lockdown`; an IP
  allowlist with trust tiers, a blocklist, country, Tor, datacenter and
  automation rules, a risk threshold, and a time-boxed "open to the internet"
  switch. Refusals are an empty 403 or a decoy 404.
- **Real second factors**: passkeys, authenticator apps, backup codes, and codes
  by email or text as a fallback only. Per-device grace windows on trusted
  networks; a fresh check before anything dangerous.
- **Device trust**: signed device cookies, an approval queue, and "approve my
  phone from my laptop".
- **People and authority**: six ranked roles, owner-only reserved capabilities,
  temporary roles, invitation links, access requests, employee numbers, and
  disable-not-delete.
- **Visibility**: edge and browser fingerprinting with risk scores that explain
  themselves, a privacy notice on by default, and a hash-chained audit log with
  revert.

## Requirements

- **Node.js 22.13 or newer.** The tests run against `node:sqlite`, which needs no
  flag from 22.13.
- **A Cloudflare account** with Workers and D1. Wrangler is a dev dependency, so
  use `npx wrangler` (or the npm scripts below); no global install is needed.
- Optional: a **Twilio** account for texted codes, a **Resend** account for
  emailed codes and invitation emails. Without them, invitations are links you
  copy, and people sign in with passkeys, authenticator apps and backup codes.

## Local development

```sh
cd staff-portal
npm install
cp .dev.vars.example .dev.vars
```

Fill `.dev.vars` with three **different** random values, each generated with:

```sh
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Then add two local overrides to the same file, because writes are accepted only
from `ORIGIN` and passkeys are bound to `RP_ID`:

```sh
ORIGIN=http://localhost:8787
RP_ID=localhost
```

`.dev.vars` is git-ignored. Never put these values in `wrangler.jsonc`.

**The database.** `wrangler dev` runs D1 locally, as a SQLite file under
`.wrangler/state`, so you can develop before creating the real database. Create
it whenever you like, and certainly before your first deploy:

```sh
npx wrangler d1 create staff-portal     # prints a database_id; paste it into wrangler.jsonc
```

There is no migration step: the worker creates its schema on the first request.

**Run it.**

```sh
npm run dev                             # wrangler dev → http://localhost:8787
```

Open <http://localhost:8787/setup>. While no account exists, that is the only
page the gate serves. Enter the `SETUP_KEY` from `.dev.vars`, your email, name
and a password of at least 12 characters. You become the Super Admin, your
browser is approved as a device, and you are asked to enrol a passkey or an
authenticator app before anything else. Locally your address is loopback, which
the allowlist will not accept; the device approval is what keeps you in.

Browse `http://localhost:8787` exactly, the address in `ORIGIN`. On
`http://127.0.0.1:8787` (what wrangler prints if you start it with
`--ip 127.0.0.1`) the pages load but every form gets an empty 403, because a
write must carry an `Origin` equal to `ORIGIN`.

Use Chrome or Firefox locally: the portal's cookies are `Secure` and
`__Host-` prefixed, which those browsers accept on `http://localhost`. If a
browser refuses them, the sign-in page says so rather than looping.

To make time pass — a streak lapse, a lock expiring — edit the local database
between requests:

```sh
npx wrangler d1 execute staff-portal --local \
  --command "UPDATE streaks SET last_at = '2026-01-01T00:00:00.000Z'"
```

Locally the client address is whatever the request claims, defaulting to
loopback, so you can test the gate as a public visitor. Give curl a browser's
user agent: its own is refused as an automation tool (the `block_automation`
setting) before the gate even looks at the address.

```sh
curl -si -A 'Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0.0.0 Safari/537.36' \
  -H 'CF-Connecting-IP: 81.2.69.142' http://localhost:8787/
```

In production the edge sets that header and a client cannot. `request.cf` is a
placeholder locally (wrangler falls back to a fixed one, a US address on
AS395747 in `America/Chicago`, when it cannot fetch the real one, for example
behind a proxy), and local requests arrive over HTTP/1.1, which adds 15 to
every visit's risk score. Local is more permissive than production in other
ways too (SPEC §14.6): PBKDF2 above 100,000 iterations works locally and
fails in production. A passing local run is evidence, not proof.

One thing goes the other way: local D1 enforces D1's real limits, which the
node test suite does not (it runs on `node:sqlite`). A LIKE or GLOB pattern
over 50 bytes fails with `LIKE or GLOB pattern too complex`, and a statement
with more than 100 bound parameters fails with `too many SQL variables`. After
changing SQL, walk the affected screens under `npm run dev`.

## Deploy

1. **Create the database** and paste its id into `wrangler.jsonc`
   (`d1_databases[0].database_id`):

   ```sh
   npx wrangler d1 create staff-portal
   ```

2. **Set the variables in `wrangler.jsonc`** — `ORG_NAME`, `ORG_CODE` (two to
   eight capital letters, the employee-number prefix), `RP_ID`, `ORIGIN`,
   `PBKDF2_ITERATIONS`, and `MAIL_FROM` if you use Resend. **These replace the
   deployed variables on every deploy**: anything set only in the Cloudflare
   dashboard is wiped by the next `wrangler deploy`, so keep every variable in
   the file.

3. **Set the secrets** (new values, not your local ones):

   ```sh
   npx wrangler secret put SESSION_SECRET
   npx wrangler secret put DATA_KEY          # must differ from SESSION_SECRET
   npx wrangler secret put SETUP_KEY
   # optional
   npx wrangler secret put TWILIO_ACCOUNT_SID
   npx wrangler secret put TWILIO_AUTH_TOKEN
   npx wrangler secret put TWILIO_FROM
   npx wrangler secret put RESEND_API_KEY
   ```

   Until `SESSION_SECRET` and `DATA_KEY` exist, every page is an empty 503 and
   only `/healthz` answers. Treat `DATA_KEY` as permanent: rotating it makes
   every enrolled authenticator app stop working (SPEC §13.3).

4. **Check, test and dry-run:**

   ```sh
   npm run check        # bundle the worker and every browser script
   npm test
   npm run dry-run      # validate config and bindings without shipping
   ```

5. **Deploy:**

   ```sh
   npm run deploy       # wrangler deploy
   ```

6. **Give it its own hostname.** Add a custom domain on its own subdomain and
   turn off the `workers.dev` address, so the portal answers on one origin
   only — in `wrangler.jsonc`:

   ```jsonc
   "routes": [{ "pattern": "staff.example.com", "custom_domain": true }],
   "workers_dev": false
   ```

   `ORIGIN` must be exactly `https://staff.example.com` and `RP_ID`
   `staff.example.com`. Choose the hostname before anyone enrols a passkey:
   changing `RP_ID` later orphans every passkey.

If you deploy from a CI integration, point it at this directory with a "root
directory" setting **or** pass `--config staff-portal/wrangler.jsonc` — never
both, or the path doubles. A dashboard "retry" rebuilds the same commit.

## First run

1. Visit the portal from the network you will administer from. With no
   accounts, the gate shows only the setup page.
2. Enter `SETUP_KEY`, your email, name and password. You become the Super
   Admin; your address is allowlisted as tier 1 and your browser is approved, so
   you cannot lock yourself out on the next request.
3. **Enrol a passkey or an authenticator app** — required for a Super Admin —
   and keep the ten backup codes, which are shown once.
4. Optionally delete the setup key; nothing needs it again:
   `npx wrangler secret delete SETUP_KEY`.
5. In the admin console (`/admin`), **add your networks** to the allowlist with
   a tier: 1 for a core admin network (a factor every 7 days), 2 trusted (24
   hours), 3 shared (2 hours), 4 temporary (every time; the entry expires).
6. **Add people**: invite each one, copy the invitation link and send it. They
   set their own password, their browser is approved, and they are asked to
   enrol a factor. Nobody ever knows anyone else's password.
7. Review the settings: time zone (default `America/New_York`), the streak
   calendar, device approval, and the access mode (default `allowlist`).

**If you get a blank page:** `/healthz` answers `ok` when the worker is up. An
empty 503 means a secret is missing; an empty 403 (or a 404, if you chose the
decoy) means the gate does not trust you from where you are. SPEC §13.5 has the
full checklist.

## Testing

```sh
npm test                          # every suite
npm test -- streak                # only suites whose path contains "streak"
TEST_ONLY=deadline npm test -- streak   # only tests whose name contains "deadline"
```

Suites live in `tests/unit`, `tests/e2e` and `tests/pages`. They run against
real SQLite behind D1's interface, drive the worker's real `fetch` handler
with a cookie jar and a fake clock, and test page scripts against a minimal
DOM. Each suite runs in its own process, and the runner reports one line per
suite:

```
✓ tests/unit/streak.test.mjs  33 passed  (1.4s)
✗ tests/e2e/login.test.mjs  41 passed, 1 failed (exit 1)              ← then the failures
✗ tests/e2e/admin.test.mjs  DID NOT REPORT — it failed to run (exit 1)  ← then its last output
✗ tests/unit/empty.test.mjs  REPORTED ZERO TESTS

15 suites: 480 tests passed, 1 failed, 2 suites broken
```

A suite that crashes before reporting counts as broken, never as passing, and
any failure or broken suite makes the command exit non-zero. (The lines above
are illustrative.)

## Project layout

```
staff-portal/
  wrangler.jsonc        the worker, its D1 database, its assets (run_worker_first)
  package.json          scripts; dev dependencies only (esbuild, wrangler, jsqr)
  worker.js             the request pipeline
  src/                  domain modules (gate, sessions, factors, audit, streak, …)
    api/                HTTP routes
    calendar/           Hebrew calendar and protected days
    mfa/  webauthn/     second factors and passkey verification
  public/               one HTML page each, /css/app.css, /js/<page>.js
  scripts/              bundle-check.mjs
  tests/                unit, e2e, pages, helpers, run.mjs
  docs/CONTRACTS.md     exact exports, routes, response shapes, settings
  SPEC.md               the design, the reasoning, the traps
```

## Configuration

Almost everything is a **setting** stored in the database and changed from the
admin console without a deploy: the access mode, network rules, the risk
threshold, second-factor policy, grace windows, device approval, session
lengths, the time zone, the privacy notice and the streak. The full list —
type, default, what an unreadable value falls back to (always the restrictive
choice), and which permission may change it — is the table in
[docs/CONTRACTS.md §5](docs/CONTRACTS.md#5-settings-policyjs). Environment
variables only identify the deployment (`ORG_NAME`, `ORG_CODE`, `RP_ID`,
`ORIGIN`, `PBKDF2_ITERATIONS`) and its providers.

**Streak calendar options**

| Setting | Default | |
|---|---|---|
| `streak_enabled` | on | show and count streaks |
| `timezone` | `America/New_York` | what "a day" means for everyone |
| `streak_window_hours` | 30 | hours after a sign-in to make the next one (24–72) |
| `streak_weekly_days` | `[6]` | weekdays that never break a streak (0 = Sunday) |
| `streak_hebrew_holidays` | on | protect Yom Tov |
| `streak_region` | `diaspora` | `diaspora` or `israel` Yom Tov schedule |
| `streak_extra_dates` | `[]` | closures: `{ "date": "YYYY-MM-DD", "label": "Office move" }`, up to 366 |
| `streak_reentry_grace_hours` | 12 | after a protected stretch, at least this long into the first day back (0–24) |
| `streak_max_leeway_days` | 4 | most protected days one window can absorb (0–7); keep it above your longest real stretch |
| `streak_leaderboard` | `all` | `all`, `managers` or `off` |

A Sunday-sabbath workplace sets `[0]` and turns Hebrew holidays off; one where
nobody works weekends sets `[0, 6]`. SPEC §10.14 has more examples, and §10 the
whole design.

## Further reading

- [SPEC.md](SPEC.md) — the merged design: decisions, the gate, authentication,
  passkeys, the streak, the audit log, operations, deployment traps, testing, and
  the fail-open catalogue.
- [docs/CONTRACTS.md](docs/CONTRACTS.md) — the binding reference for module
  exports, routes, response shapes and settings.
