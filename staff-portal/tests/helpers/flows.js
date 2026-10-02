// End-to-end building blocks over the real worker (A §13.2): every helper
// drives worker.fetch through tests/helpers/http.js Clients and the env
// clock, so a suite reads like what people do.
//
//   const env = await freshEnv();
//   const owner = await bootstrap(env);            // signed-in Super Admin, TOTP enrolled, step-up fresh
//   const amy = await makeUser(env, owner.client, { role: 'manager', totp: true });
//   await stepUp(env, owner.client);               // fresh step-up for a danger route
//   const r = await owner.client.post('/api/admin/...', {...});
//
// Clients returned here carry `.user` (the users row at creation) and
// `.totpSecret` (base32, or null). Every TOTP helper that PROVES a code first
// moves the clock forward one 30-second step: the replay floor refuses a
// counter that was already spent, exactly as it should.

import assert from 'node:assert/strict';
import worker from '../../worker.js';
import { makeEnv, makeEnvWithSchema } from './env.js';
import { Client, CHROME_UA } from './http.js';
import { base32Decode, totpCode, TOTP_STEP_MS } from '../../src/mfa/totp.js';
import { DAY, HOUR, MINUTE, iso } from '../../src/util.js';
import { getUser, createUser } from '../../src/users.js';
import { createInvitation } from '../../src/invitations.js';
import { effectivePermissions } from '../../src/rbac.js';
import { resolvePolicy } from '../../src/policy.js';
import { SESSION_COOKIE } from '../../src/sessions.js';
import { DEVICE_COOKIE } from '../../src/devices.js';

export { worker, Client, CHROME_UA, SESSION_COOKIE, DEVICE_COOKIE, DAY, HOUR, MINUTE };

export const OWNER_IP = '81.2.69.142'; // allowlisted tier 1 by setup
export const OWNER = Object.freeze({ email: 'owner@acme.com', full_name: 'Olive Owner', password: 'owner-password-0123' });
export const PASSWORD = 'staff-password-0123';
export const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];

// Distinct public addresses (CONTRACTS §12: documentation ranges are refused).
const PREFIXES = ['91.198.174', '185.15.56', '81.2.70'];
let ipSeq = 0;
export function nextIp() {
  const n = ipSeq++;
  return `${PREFIXES[Math.floor(n / 250) % PREFIXES.length]}.${(n % 250) + 2}`;
}

let userSeq = 0;

export function freshEnv(overrides) {
  return makeEnv(overrides);
}

export { makeEnvWithSchema };

export function client(env, opts = {}) {
  return new Client(worker, env, { ip: nextIp(), ...opts });
}

// ---------------------------------------------------------------- time

export function advance(env, ms) {
  env.__advance(ms);
}

export function advanceDays(env, n) {
  env.__advance(n * DAY);
}

export function setNow(env, isoOrMs) {
  env.__setNow(typeof isoOrMs === 'number' ? isoOrMs : Date.parse(isoOrMs));
}

export function nowIso(env) {
  return iso(env.__clock());
}

// ---------------------------------------------------------------- TOTP

export function secretFromOtpauth(uri) {
  return new URL(uri).searchParams.get('secret');
}

// The code for the env clock's current step (no clock movement).
export async function totpNow(secretB32, env, offsetSteps = 0) {
  const counter = Math.floor(env.__clock() / TOTP_STEP_MS) + offsetSteps;
  return totpCode(base32Decode(secretB32), counter);
}

// Moves the clock one step, then answers its code: a counter never spent.
export async function nextTotp(env, secretB32) {
  env.__advance(TOTP_STEP_MS);
  return totpNow(secretB32, env);
}

// begin + confirm on the client's session → the base32 secret.
export async function enrollTotp(env, c) {
  const begin = await c.post('/api/me/mfa/totp/begin', {});
  assert.equal(begin.status, 200, `totp begin: ${begin.text}`);
  const secret = secretFromOtpauth(begin.body.otpauth);
  const confirm = await c.post('/api/me/mfa/totp/confirm', { code: await totpNow(secret, env) });
  assert.equal(confirm.status, 200, `totp confirm: ${confirm.text}`);
  c.totpSecret = secret;
  c.backupCodes = confirm.body.backup_codes;
  return secret;
}

// A fresh step-up for the session (TOTP; the client must carry totpSecret).
export async function stepUp(env, c, secret = c.totpSecret) {
  assert.ok(secret, 'stepUp needs a TOTP secret');
  const r = await c.post('/api/me/step-up/code', { code: await nextTotp(env, secret) });
  assert.equal(r.status, 200, `step-up: ${r.text}`);
  return r;
}

// ---------------------------------------------------------------- people

// POST /api/setup from OWNER_IP, then TOTP enrolment (clears the pin and
// marks step-up). → { client, user, password, totpSecret, backupCodes, setup }
export async function bootstrap(env, { ip = OWNER_IP, email = OWNER.email, full_name = OWNER.full_name, password = OWNER.password } = {}) {
  const c = new Client(worker, env, { ip });
  const setup = await c.post('/api/setup', { setup_key: env.SETUP_KEY, email, full_name, password });
  assert.equal(setup.status, 200, `setup: ${setup.text}`);
  c.user = await getUser(env, setup.body.user.id);
  const totpSecret = await enrollTotp(env, c);
  c.user = await getUser(env, c.user.id);
  return { client: c, user: c.user, password, totpSecret, backupCodes: c.backupCodes, setup };
}

export function roleId(env, key) {
  const row = env.DB.q('SELECT id FROM roles WHERE key = ?', key)[0];
  assert.ok(row, `no role '${key}'`);
  return row.id;
}

// A request context acting as `userRow`, for calling domain functions directly.
export async function actorRc(env, userRow, extra = {}) {
  const nowMs = env.__clock();
  return {
    env,
    nowMs,
    user: userRow,
    authz: await effectivePermissions(env, userRow, nowMs),
    policy: await resolvePolicy(env),
    ip: null,
    setCookies: [],
    ...extra,
  };
}

// An invited account accepted through the real link flow: GET /invite?token=
// (pass cookie when the gate needs one), POST /api/invite/accept (device
// approved, signed in). By default the invitation is made by domain calls as
// the superClient's user, so suites do not depend on the admin API; pass
// viaApi: true to make it with POST /api/admin/users instead.
// → { client, user, password, totpSecret, token }
export async function makeUser(env, superClient, opts = {}) {
  const n = ++userSeq;
  const {
    role = 'employee',
    email = `user${n}@acme.com`,
    full_name = `User ${n}`,
    password = PASSWORD,
    ip = nextIp(),
    ua = CHROME_UA,
    totp = false,
    viaApi = false,
  } = opts;
  let token;
  if (viaApi) {
    const r = await superClient.post('/api/admin/users', { email, full_name, role_id: roleId(env, role) });
    assert.ok(r.status === 200 || r.status === 201, `POST /api/admin/users: ${r.status} ${r.text}`);
    token = new URL(r.body.invitation.url, env.ORIGIN).searchParams.get('token');
  } else {
    assert.ok(superClient && superClient.user, 'makeUser needs a client with .user (from bootstrap or makeUser)');
    const rc = await actorRc(env, superClient.user);
    const created = await createUser(rc, { email, full_name, role_id: roleId(env, role) });
    token = (await createInvitation(rc, created.id)).token;
  }
  const c = new Client(worker, env, { ip, ua });
  const link = await c.get(`/invite?token=${token}`);
  assert.equal(link.status, 200, `invite link: ${link.status}`);
  const accept = await c.post('/api/invite/accept', { token, password, full_name });
  assert.equal(accept.status, 200, `invite accept: ${accept.text}`);
  c.user = await getUser(env, accept.body.user.id);
  c.password = password;
  let totpSecret = null;
  if (totp) totpSecret = await enrollTotp(env, c);
  c.totpSecret = totpSecret;
  return { client: c, user: c.user, password, totpSecret, token };
}

// Password, then (if asked) the authenticator. → the final response.
export async function signIn(env, c, identifier, password, { totpSecret = c.totpSecret } = {}) {
  const r = await c.post('/api/auth/login', { identifier, password });
  if (r.status !== 200 || !r.body?.mfa_required || !totpSecret) return r;
  return c.post('/api/auth/mfa/code', { token: r.body.token, code: await nextTotp(env, totpSecret) });
}

export async function signOut(c) {
  return c.post('/api/auth/logout', {});
}

// ---------------------------------------------------------------- inspection

export function q(env, sql, ...params) {
  return env.DB.q(sql, ...params);
}

export function count(env, sql, ...params) {
  const row = env.DB.q(sql, ...params)[0];
  return row ? Object.values(row)[0] : 0;
}

export function auditRows(env, action) {
  return action === undefined
    ? env.DB.q('SELECT * FROM audit_log ORDER BY seq')
    : env.DB.q('SELECT * FROM audit_log WHERE action = ? ORDER BY seq', action);
}

export function lastAudit(env, action) {
  const rows = auditRows(env, action);
  return rows[rows.length - 1] || null;
}

// Tests only: writes a setting row directly, bypassing validation and the
// self-lockout guards (use the settings API to test those).
export function setSetting(env, key, value) {
  env.DB.q(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    key,
    value,
    nowIso(env),
  );
}

export function sessionToken(c) {
  return c.jar.get(SESSION_COOKIE) ?? null;
}

export function deviceCookie(c) {
  return c.jar.get(DEVICE_COOKIE) ?? null;
}

// A request built by hand — no automatic Origin, cookies only if given —
// for the CSRF and header suites.
export async function rawRequest(env, method, path, { headers = {}, body, ip = nextIp(), cf = {} } = {}) {
  const h = new Headers({ 'cf-connecting-ip': ip, 'user-agent': CHROME_UA, 'accept-language': 'en-US', ...headers });
  const req = new Request(new URL(path, env.ORIGIN), { method, headers: h, body });
  Object.defineProperty(req, 'cf', { value: { country: 'US', asn: 7922, tlsVersion: 'TLSv1.3', httpProtocol: 'HTTP/2', ...cf }, enumerable: true });
  const pending = [];
  const res = await worker.fetch(req, env, { waitUntil: (p) => pending.push(p), passThroughOnException() {} });
  await Promise.allSettled(pending);
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, res };
}

// A Twilio/Resend stand-in for env.__fetch: records every call, answers 201.
export function fakeProvider(status = 201) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init, body: typeof init.body === 'string' ? init.body : '' });
    return new Response('{}', { status });
  };
  return { fetch, calls };
}

export const TWILIO = Object.freeze({ TWILIO_ACCOUNT_SID: 'AC0123456789', TWILIO_AUTH_TOKEN: 'twilio-auth-token', TWILIO_FROM: '+15550000000' });

// The six digits in the last text or email the fake provider carried.
export function lastCodeSent(provider) {
  const call = provider.calls[provider.calls.length - 1];
  assert.ok(call, 'nothing was sent');
  const text = call.body.includes('Body=') ? new URLSearchParams(call.body).get('Body') : call.body;
  const m = /\b(\d{6})\b/.exec(text);
  assert.ok(m, 'no code in the message');
  return m[1];
}

// Reads a public/ page so a suite can tell which one was served.
export async function pageText(name) {
  const { readFile } = await import('node:fs/promises');
  const { PUBLIC_DIR } = await import('./env.js');
  return readFile(`${PUBLIC_DIR}/${name}`, 'utf8');
}
