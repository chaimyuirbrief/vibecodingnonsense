// Routes a visitor reaches before signing in, each still behind the gate
// (CONTRACTS §8.4 Public; A §5, §11; B §5, trap 3; SPEC §6.6–6.8, §8.6).

import { json, readJson, iso, normEmail, clearCookie, randomToken, MINUTE } from '../util.js';
import { HttpError, ValidationError, notFound, tooMany } from '../errors.js';
import { timingSafeEqual } from '../crypto.js';
import { charge } from '../ratelimit.js';
import { audit } from '../audit.js';
import { undoFor } from '../undo.js';
import { isPrivateOrReserved } from '../ip.js';
import { addAllowed } from '../network.js';
import { createOwner } from '../users.js';
import { lookupInvitation, acceptInvitation, createAccessRequest } from '../invitations.js';
import { ensureDevice, setDeviceStatus, deviceState, deviceCode, DEVICE_COOKIE } from '../devices.js';
import { recordFingerprint, CLIENT_MAX_BYTES } from '../fingerprint.js';
import { SESSION_COOKIE } from '../sessions.js';
import { PASS_COOKIE } from '../gate.js';
import { completeSignIn } from '../signin.js';
import { orgName, privacyNotice } from './auth.js';

const SETUP_CLAIM_KEY = 'setup_claim';
const SETUP_CLAIM_MS = 10 * MINUTE;
const CLAIM_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\|/;
const COOKIE_NAME_RE = /^[\x21-\x7e]{1,64}$/;
const HINT_HEADERS = Object.freeze([
  ['sec-ch-ua', 'sec_ch_ua'],
  ['sec-ch-ua-mobile', 'sec_ch_ua_mobile'],
  ['sec-ch-ua-platform', 'sec_ch_ua_platform'],
  ['sec-ch-ua-model', 'sec_ch_ua_model'],
]);

async function body(rc) {
  return (await readJson(rc.request)) || {};
}

async function chargeOr429(rc, kind) {
  const lim = await charge(rc.env, kind, rc.ip ?? '?', rc.nowMs);
  if (!lim.allowed) throw tooMany(lim.retryAfterSec);
}

// ---------------------------------------------------------------- setup

// Reachable only from the setup shell — i.e. while no account exists. Once
// one does, the route is gone (B §5 "then 404s forever").
function requireSetupShell(rc) {
  if (rc.gate?.allowed !== 'shell' || rc.gate.shell !== 'setup') throw notFound();
}

// The one-shot claim (B trap 3): `<expiry ISO>|<random>` in meta, held by
// one setup at a time, and EXPIRING, so a setup that died halfway can be
// retried rather than leaving a portal with no accounts that refuses to
// create one. A claim value that cannot be read is retakeable for the same
// reason; the conditional insert in users.createOwner, not this row, is what
// makes a second owner impossible.
//
// Whether a claim is still held is decided here, not in SQL: D1 refuses any
// LIKE/GLOB pattern over 50 bytes ("LIKE or GLOB pattern too complex"),
// which node:sqlite does not, so a shape check written as a GLOB passed every
// test and made every retry — a racing setup, or the retry after a crashed
// one — a 500 in the real runtime.
function claimHeld(value, nowMs) {
  const m = typeof value === 'string' ? CLAIM_RE.exec(value) : null;
  return m !== null && m[1] > iso(nowMs);
}

// Insert when there is no claim; otherwise replace a stale one by
// compare-and-swap on the exact value read, so of two setups that both saw
// the same stale claim only one takes it.
async function takeSetupClaim(env, nowMs) {
  const db = env.DB;
  const value = `${iso(nowMs + SETUP_CLAIM_MS)}|${randomToken(16)}`;
  for (let attempt = 0; attempt < 2; attempt++) {
    const ins = await db
      .prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING')
      .bind(SETUP_CLAIM_KEY, value)
      .run();
    if (ins.meta.changes === 1) return value;
    const row = await db.prepare('SELECT value FROM meta WHERE key = ?').bind(SETUP_CLAIM_KEY).first();
    if (!row) continue; // released between the two statements: insert again
    const seen = row.value ?? null;
    if (claimHeld(seen, nowMs)) return null;
    const cas = await db.prepare('UPDATE meta SET value = ? WHERE key = ? AND value IS ?').bind(value, SETUP_CLAIM_KEY, seen).run();
    return cas.meta.changes === 1 ? value : null;
  }
  return null;
}

async function releaseSetupClaim(env, value) {
  await env.DB.prepare('DELETE FROM meta WHERE key = ? AND value = ?').bind(SETUP_CLAIM_KEY, value).run();
}

async function setupStatus(rc) {
  requireSetupShell(rc);
  return json(200, { needed: true, org_name: orgName(rc.env) });
}

async function setup(rc) {
  requireSetupShell(rc);
  const env = rc.env;
  const t = rc.nowMs;
  await chargeOr429(rc, 'setup_ip');
  const b = await body(rc);
  const configured = typeof env.SETUP_KEY === 'string' && env.SETUP_KEY.length >= 32;
  const given = typeof b.setup_key === 'string' && b.setup_key.length <= 1024 ? b.setup_key : '';
  // Constant time, and a missing SETUP_KEY matches nothing (fail closed).
  const match = await timingSafeEqual(given, configured ? env.SETUP_KEY : '');
  if (!(match && configured && given !== '')) {
    await audit(rc, {
      action: 'setup.complete',
      outcome: 'denied',
      detail: configured ? 'Refused setup: wrong setup key' : 'Refused setup: SETUP_KEY is not configured (at least 32 characters)',
    });
    throw new HttpError(403, { error: 'That setup key isn’t right.', code: 'setup_key', field: 'setup_key' });
  }
  const claim = await takeSetupClaim(env, t);
  if (!claim) {
    throw new HttpError(409, {
      error: 'Setup is already running somewhere else. If it was interrupted, try again in ten minutes.',
      code: 'setup_in_progress',
    });
  }
  try {
    const owner = await createOwner(env, { email: b.email, full_name: b.full_name, password: b.password }, t);
    rc.user = owner;
    const notices = [];
    // Allowlist the address setup ran from, or the owner is locked out on
    // their very next request in the default mode (SPEC §6.6). A private
    // address (wrangler dev reports loopback) is skipped: it could never
    // match a visitor, and the approved device is the way back in.
    if (rc.ip && !isPrivateOrReserved(rc.ip)) {
      try {
        const row = await addAllowed(rc, { cidr: rc.ip, tier: 1, label: 'Added by setup', owner: owner.email, user_id: owner.id });
        await audit(rc, {
          action: 'network.allow.add',
          target: { type: 'allowed_ip', id: row.id },
          detail: `Setup allowlisted ${row.cidr} (tier 1), the address it ran from`,
          after: row,
          undo: undoFor('network.allow.add', { id: row.id }),
        });
      } catch (e) {
        if (!(e instanceof ValidationError)) throw e;
        notices.push(`Your address was not allowlisted: ${e.message}`);
      }
    } else {
      notices.push(`Your address (${rc.ip || 'unknown'}) is private or reserved, so it was not allowlisted; this approved device is your way back in.`);
    }
    const dev = await ensureDevice(rc);
    if (dev.setCookie) rc.setCookies.push(dev.setCookie);
    const { prior, row } = await setDeviceStatus(rc, dev.id, 'approved', {});
    rc.device = { id: dev.id, row };
    await audit(rc, {
      action: 'device.approve',
      target: { type: 'device', id: dev.id },
      detail: `Setup approved the device it ran from (${row.label || 'unnamed'})`,
      before: { status: prior.status },
      after: { status: row.status },
      undo: undoFor('device.status', { deviceId: dev.id, status: prior.status }),
    });
    await audit(rc, {
      action: 'setup.complete',
      target: { type: 'user', id: owner.id },
      detail: `Created the first Super Admin, ${owner.email}${notices.length ? `. ${notices.join(' ')}` : ''}`,
    });
    const res = await completeSignIn(rc, owner, 'setup', { aal: 1 });
    await releaseSetupClaim(env, claim);
    return res;
  } catch (e) {
    await releaseSetupClaim(env, claim);
    throw e;
  }
}

// ---------------------------------------------------------------- invitations

function invalidInvitation() {
  return new HttpError(404, { error: 'This invitation link is no longer valid. Ask for a new one.', code: 'invitation_invalid' });
}

async function invitationLookup(rc) {
  const b = await body(rc);
  return describeInvitation(rc, b.token);
}

async function describeInvitation(rc, token) {
  await chargeOr429(rc, 'invite_ip');
  const found = await lookupInvitation(rc.env, token, rc.nowMs);
  if (!found) throw invalidInvitation();
  return json(200, {
    email: found.user.email,
    full_name: found.user.full_name || '',
    org_name: orgName(rc.env),
    expires_at: found.invitation.expires_at,
    privacy_notice: privacyNotice(rc.policy),
  });
}

// Accepting approves the device it was accepted on: the invitation IS the
// administrator's approval (D11). acceptInvitation does that in the same
// batch that activates the account; a blocked device stays blocked.
async function acceptInvite(rc) {
  const env = rc.env;
  await chargeOr429(rc, 'invite_ip');
  const b = await body(rc);
  const dev = await ensureDevice(rc);
  if (dev.setCookie) rc.setCookies.push(dev.setCookie);
  const before = deviceState(dev.row);
  const user = await acceptInvitation(rc, b.token, { password: b.password, full_name: b.full_name });
  rc.user = user;
  let row = await env.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(dev.id).first();
  if (deviceState(row) === 'pending') row = (await setDeviceStatus(rc, dev.id, 'approved', {})).row;
  rc.device = { id: dev.id, row };
  if (before === 'pending' && deviceState(row) === 'approved') {
    await audit(rc, {
      action: 'device.approve',
      target: { type: 'device', id: dev.id },
      detail: `Approved ${row.label || 'a device'} by accepting an invitation`,
      before: { status: 'pending' },
      after: { status: 'approved' },
      undo: undoFor('device.status', { deviceId: dev.id, status: 'pending' }),
    });
  }
  await audit(rc, { action: 'invite.accept', target: { type: 'user', id: user.id }, detail: `${user.email} accepted their invitation` });
  rc.setCookies.push(clearCookie(PASS_COOKIE));
  return completeSignIn(rc, user, 'invitation', { aal: 1 });
}

// ---------------------------------------------------------------- requests and fingerprints

// { ok: true } whatever happened to the email: nothing here asks whether it
// belongs to someone (SPEC §6.8).
async function accessRequest(rc) {
  const b = await body(rc);
  await createAccessRequest(rc, b);
  await audit(rc, { action: 'request.create', detail: `Access request from ${normEmail(b.email) || 'an unreadable address'}` });
  return json(200, { ok: true });
}

async function fingerprint(rc) {
  await chargeOr429(rc, 'fp_ip');
  const b = await readJson(rc.request, CLIENT_MAX_BYTES);
  if (!b) throw new ValidationError('Send the browser’s signals as JSON, at most 16 KiB.', 'signals');
  const r = await recordFingerprint(rc, { client: b.signals });
  rc.setCookies.push(r.setCookie);
  // The one reply every shell that fingerprints can read, so the request
  // page can honour the privacy_notice setting (B §6 "Say so").
  return json(200, { ok: true, privacy_notice: privacyNotice(rc.policy) });
}

// ---------------------------------------------------------------- diagnostics

// "What did the browser actually send?" Cookie NAMES and a count — never a
// value, because this exists to be screenshotted (A §5, §11).
async function diag(rc) {
  const e = rc.edge || {};
  const all = Object.keys(rc.cookies || {});
  const hints = {};
  for (const [header, key] of HINT_HEADERS) if (typeof e[key] === 'string' && e[key]) hints[header] = e[key];
  const id = typeof rc.device?.id === 'string' ? rc.device.id : null;
  return json(200, {
    cookies: { names: all.filter((n) => COOKIE_NAME_RE.test(n)).slice(0, 50), count: all.length },
    ua: rc.ua || null,
    client_hints: hints,
    ip: rc.ip,
    country: e.country ?? null,
    asn: e.asn ?? null,
    tls_version: e.tls_version ?? null,
    http_protocol: e.http_protocol ?? null,
    device: {
      present: typeof rc.cookies?.[DEVICE_COOKIE] === 'string',
      valid: id !== null,
      status: id ? deviceState(rc.device.row) : null,
      code: id ? await deviceCode(id) : null,
    },
    session: { present: typeof rc.cookies?.[SESSION_COOKIE] === 'string', valid: !!rc.session },
  });
}

// What the pending page polls; mints a pending device if there is none.
async function deviceStatus(rc) {
  const d = await ensureDevice(rc);
  if (d.setCookie) rc.setCookies.push(d.setCookie);
  return json(200, { code: await deviceCode(d.id), status: deviceState(d.row), label: d.row?.label ?? null });
}

export function register(router) {
  router.add('GET', '/api/setup/status', setupStatus, { auth: 'none' });
  router.add('POST', '/api/setup', setup, { auth: 'none' });
  router.add('POST', '/api/invite/lookup', invitationLookup, { auth: 'none' });
  router.add('POST', '/api/invite/accept', acceptInvite, { auth: 'none' });
  router.add('POST', '/api/access-request', accessRequest, { auth: 'none' });
  router.add('POST', '/api/fp', fingerprint, { auth: 'none' });
  router.add('GET', '/api/diag', diag, { auth: 'none' });
  router.add('GET', '/api/device/status', deviceStatus, { auth: 'none' });
  return router;
}
