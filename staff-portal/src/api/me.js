// Self-service (CONTRACTS §8.4 Me; A §7.3–7.5; B §6; SPEC §7.8–7.9, §8.2).
//
// Every route acts on the caller's OWN account: no path carries a user id,
// so nobody can add a passkey to someone else's login (A §7.5). Routes that
// weaken an account — removing a factor, new backup codes, approving a
// device — demand a fresh step-up themselves, since no permission marks them
// as danger for the worker to catch.

import { json, readJson, iso, toInt, strStrict, safeJsonParse } from '../util.js';
import { HttpError, GuardError, ValidationError, notFound, tooMany } from '../errors.js';
import { charge, clear } from '../ratelimit.js';
import { audit, listAuditForUser } from '../audit.js';
import { undoFor } from '../undo.js';
import { requireStepUp, can } from '../rbac.js';
import { publicUser, getUser, updateProfile, changeOwnPassword } from '../users.js';
import {
  nextPin, setPin, markStepUp, hasFreshStepUp, revokeSession, revokeUserSessions, listUserSessions, findSessionByRef, clearSessionCookie,
} from '../sessions.js';
import { listDevices, findDeviceByCode, setDeviceStatus, deviceState } from '../devices.js';
import { streakConfig, getStreak, streakHistory, upcomingProtected, streakRules, leaderboard } from '../streak.js';
import { userFactors, availableMethods, hasStrongFactor, canDropFactor } from '../mfa/factors.js';
import { beginTotp, confirmTotp, checkTotp, removeTotp } from '../mfa/totp.js';
import { consumeBackupCode, generateBackupCodes, storeBackupCodes, countUnusedBackupCodes } from '../mfa/backup.js';
import { listDestinations, sendCode, verifyCode } from '../mfa/otp.js';
import { registrationOptions, verifyRegistration, assertionOptions, verifyAssertion } from '../webauthn/webauthn.js';
import { HOW, pinTarget } from '../signin.js';
import { orgName, privacyNotice } from './auth.js';

const CODE_INPUT_MAX = 64;
const LABEL_MAX = 60;

async function body(rc) {
  return (await readJson(rc.request)) || {};
}

function me(rc) {
  return { type: 'user', id: rc.user.id };
}

function codeInput(v) {
  return typeof v === 'string' && v.length <= CODE_INPUT_MAX ? v : null;
}

function lastFactor() {
  return new GuardError('last_factor', 'That’s your last way to confirm it’s you. Add another one first.', 409);
}

function passkeyView(r) {
  return { id: r.id, label: r.label ?? null, created_at: r.created_at ?? null, last_used_at: r.last_used_at ?? null };
}

async function ownPasskeys(env, uid) {
  const { results } = await env.DB.prepare(
    'SELECT id, label, created_at, last_used_at FROM user_passkeys WHERE user_id = ? ORDER BY created_at, id',
  )
    .bind(uid)
    .all();
  return results.map(passkeyView);
}

// After enrolling: re-derive the pin rather than clearing it — a session
// pinned to a password change stays pinned to it (B trap 3).
async function repin(rc) {
  if (!rc.session.pinned) return { pinned: null, next: '/' };
  const pin = await nextPin(rc.env, await getUser(rc.env, rc.user.id), rc.policy);
  if (pin !== rc.session.pinned) {
    await setPin(rc.env, rc.session.id, pin);
    rc.session.pinned = pin;
  }
  return { pinned: pin, next: pinTarget(pin) };
}

// New backup codes when the person has none left unused (A §7.3: issued
// once, shown once).
async function backupCodesIfNone(rc) {
  if ((await countUnusedBackupCodes(rc.env, rc.user.id)) > 0) return null;
  const codes = generateBackupCodes();
  await storeBackupCodes(rc.env, rc.user.id, codes, rc.nowMs);
  await audit(rc, { action: 'mfa.backup.generate', target: me(rc), detail: `Issued ${codes.length} backup codes` });
  return codes;
}

// ---------------------------------------------------------------- profile

async function getMe(rc) {
  const env = rc.env;
  const uid = rc.user.id;
  const [factors, strong, passkeys] = await Promise.all([userFactors(env, uid), hasStrongFactor(env, uid), ownPasskeys(env, uid)]);
  return json(200, {
    user: publicUser(rc.user, rc.authz),
    permissions: [...rc.authz.perms].sort(),
    sources: rc.authz.sources,
    rank: rc.authz.rank,
    is_super: rc.authz.isSuper === true,
    pinned: rc.session.pinned ?? null,
    enroll_prompt: !strong,
    step_up_fresh: hasFreshStepUp(rc),
    factors,
    passkeys,
    org_name: orgName(env),
    timezone: rc.policy.timezone,
    privacy_notice: privacyNotice(rc.policy),
  });
}

async function patchMe(rc) {
  const b = await body(rc);
  if (b.full_name === undefined) throw new ValidationError('Enter your name.', 'full_name');
  const { prior, row } = await updateProfile(rc, rc.user.id, { full_name: b.full_name });
  if (Object.keys(prior).length) {
    await audit(rc, {
      action: 'user.edit',
      target: me(rc),
      detail: 'Changed their own name',
      before: prior,
      after: { full_name: row.full_name },
      undo: undoFor('user.profile', { userId: rc.user.id, fields: prior }),
    });
  }
  return json(200, { ok: true, user: publicUser(row, rc.authz) });
}

async function changePassword(rc) {
  const b = await body(rc);
  const r = await changeOwnPassword(rc, b.current, b.next);
  await audit(rc, { action: 'password.change', target: me(rc), detail: 'Changed their own password; their other sessions were ended' });
  return json(200, { ok: true, pinned: r.pinned, next: pinTarget(r.pinned) });
}

// ---------------------------------------------------------------- streak

async function myStreak(rc) {
  const env = rc.env;
  const t = rc.nowMs;
  const cfg = streakConfig(rc.policy);
  const rules = streakRules(cfg);
  if (!cfg.enabled) return json(200, { enabled: false, status: null, history: [], upcoming: [], rules, leaderboard: null });
  // Read-only: a lapsed streak shows 0 here and the stored row is untouched
  // until the next sign-in (A §10 "read without rewriting").
  const [status, history] = await Promise.all([getStreak(env, rc.user.id, t, cfg), streakHistory(env, rc.user.id, t, cfg, 84)]);
  const showBoard =
    cfg.leaderboard === 'all' || (cfg.leaderboard === 'managers' && (can(rc.authz, 'team.view') || can(rc.authz, 'streaks.view_all')));
  return json(200, {
    enabled: true,
    status,
    history,
    upcoming: upcomingProtected(cfg, t, 21),
    rules,
    leaderboard: showBoard ? await leaderboard(env, t, cfg, 10) : null,
  });
}

// ---------------------------------------------------------------- sessions

async function mySessions(rc) {
  return json(200, { sessions: await listUserSessions(rc.env, rc.user.id, rc.session.id) });
}

async function endSession(rc, params) {
  const row = await findSessionByRef(rc.env, params.ref, { userId: rc.user.id });
  if (!row || row.revoked_at) throw notFound('No such session.');
  await revokeSession(rc.env, row.id, 'user_revoked');
  const current = row.id === rc.session.id;
  if (current) rc.setCookies.push(clearSessionCookie());
  await audit(rc, { action: 'session.revoke', target: me(rc), detail: current ? 'Signed out of this session' : 'Signed out one of their other sessions' });
  return json(200, { ok: true, signed_out: current });
}

async function endOtherSessions(rc) {
  const n = await revokeUserSessions(rc.env, rc.user.id, 'revoke_others', { exceptId: rc.session.id });
  await audit(rc, { action: 'session.revoke', target: me(rc), detail: `Signed out of ${n} other session${n === 1 ? '' : 's'}` });
  return json(200, { ok: true, revoked: n });
}

// ---------------------------------------------------------------- devices

async function myDevices(rc) {
  const uid = rc.user.id;
  const rows = await listDevices(rc.env, { userId: uid, limit: 100 });
  return json(200, {
    devices: rows.map((d) => {
      const mine = d.users.find((u) => u.user_id === uid);
      return {
        id: d.id,
        label: d.label ?? null,
        status: deviceState(d),
        last_seen_at: mine?.last_seen ?? d.last_seen ?? null,
        first_seen_at: mine?.first_seen ?? d.first_seen ?? null,
        sign_ins: mine?.sign_ins ?? 0,
        ip: d.last_ip ?? null,
        current: d.id === rc.device?.id,
      };
    }),
  });
}

// "Forget": this account's trust in the device goes — its grace window, the
// sessions there and the ledger row that lets it ride past an account lock.
// The device itself may be someone else's too, so its status is untouched.
async function forgetDevice(rc, params) {
  const env = rc.env;
  const uid = rc.user.id;
  const id = typeof params.id === 'string' && params.id.length <= 128 ? params.id : null;
  const known = id && (await env.DB.prepare('SELECT 1 AS x FROM device_users WHERE user_id = ? AND device_id = ?').bind(uid, id).first());
  if (!known) throw notFound('No such device on your account.');
  const db = env.DB;
  const at = iso(rc.nowMs);
  await db.batch([
    db.prepare('DELETE FROM mfa_grace WHERE user_id = ? AND device_id = ?').bind(uid, id),
    db
      .prepare("UPDATE sessions SET revoked_at = ?, revoke_reason = 'device_forgotten' WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL")
      .bind(at, uid, id),
    db.prepare('DELETE FROM device_users WHERE user_id = ? AND device_id = ?').bind(uid, id),
  ]);
  const current = id === rc.device?.id;
  if (current) rc.setCookies.push(clearSessionCookie());
  await audit(rc, { action: 'device.revoke', target: { type: 'device', id }, detail: 'Forgot a device from their own account' });
  return json(200, { ok: true, signed_out: current });
}

// "Approve my phone from my laptop" (B §6): only from a device that is
// itself approved, after a step-up, with guesses rate-limited.
async function approveDevice(rc) {
  requireStepUp(rc);
  if (deviceState(rc.device?.row) !== 'approved') {
    throw new GuardError('device_not_approved', 'Approve other devices from a device that is itself approved.', 403);
  }
  const lim = await charge(rc.env, 'device_code_user', String(rc.user.id), rc.nowMs);
  if (!lim.allowed) throw tooMany(lim.retryAfterSec);
  const b = await body(rc);
  const target = await findDeviceByCode(rc.env, b.code);
  if (!target) throw notFound('No device is waiting with that code. Check it and try again.');
  const { prior, row } = await setDeviceStatus(rc, target.id, 'approved', {});
  await audit(rc, {
    action: 'device.self_approve',
    target: { type: 'device', id: row.id },
    detail: `Approved ${row.label || 'a device'} for themselves`,
    before: { status: prior.status },
    after: { status: row.status },
    undo: undoFor('device.status', { deviceId: row.id, status: prior.status }),
  });
  return json(200, { ok: true, device: { id: row.id, label: row.label ?? null, status: deviceState(row) } });
}

// ---------------------------------------------------------------- activity and fingerprint

async function myActivity(rc) {
  return json(200, { entries: await listAuditForUser(rc.env, rc.user.id, 50) });
}

// This browser's fingerprint (its signed cookie names it), else the latest
// one recorded while this person was signed in.
async function myFingerprint(rc) {
  const db = rc.env.DB;
  let row = null;
  if (typeof rc.fp?.hash === 'string') row = await db.prepare('SELECT * FROM fingerprints WHERE hash = ?').bind(rc.fp.hash).first();
  if (!row) row = await db.prepare('SELECT * FROM fingerprints WHERE last_user_id = ? ORDER BY last_seen DESC LIMIT 1').bind(rc.user.id).first();
  const threshold = toInt(rc.policy.risk_threshold, 1, 100);
  const base = { threshold: Number.isFinite(threshold) ? threshold : null };
  if (!row) return json(200, { fingerprint: null, risk: null, ...base });
  const edge = safeJsonParse(row.edge, null) || {};
  const client = safeJsonParse(row.client, null);
  const flags = safeJsonParse(row.flags, []);
  const score = toInt(row.risk, 0, 100);
  return json(200, {
    fingerprint: {
      visitor_id: row.visitor_id ?? null,
      first_seen: row.first_seen ?? null,
      last_seen: row.last_seen ?? null,
      hits: row.hits ?? null,
      ip: row.last_ip ?? null,
      country: edge.country ?? null,
      asn: edge.asn ?? null,
      as_org: edge.as_org ?? null,
      ua: edge.ua ?? null,
      tz: client && typeof client.tz === 'string' ? client.tz : null,
    },
    risk: {
      score: Number.isFinite(score) ? score : null,
      flags: Array.isArray(flags) ? flags.filter((f) => f && typeof f === 'object' && typeof f.reason === 'string') : [],
    },
    ...base,
  });
}

// ---------------------------------------------------------------- step-up

async function chargeFactor(rc) {
  const lim = await charge(rc.env, 'mfa_user', String(rc.user.id), rc.nowMs);
  if (!lim.allowed) throw tooMany(lim.retryAfterSec);
}

// A factor proved clears the per-account factor counter, as at sign-in.
async function stepUpDone(rc, method) {
  await markStepUp(rc.env, rc.session.id, method, rc.nowMs);
  await clear(rc.env, 'mfa_user', String(rc.user.id));
  rc.session.aal = 2;
  rc.session.mfa_at = iso(rc.nowMs);
  await audit(rc, { action: 'stepup.success', target: me(rc), detail: `Confirmed it was them with ${HOW[method]}` });
  return json(200, { ok: true, step_up_fresh: true });
}

async function stepUpFailed(rc, detail) {
  await audit(rc, { action: 'stepup.fail', outcome: 'failure', target: me(rc), detail });
  return new HttpError(400, { error: 'That didn’t work. Try again.', code: 'stepup_invalid' });
}

async function stepUpInfo(rc) {
  const env = rc.env;
  const [methods, dests] = await Promise.all([availableMethods(env, rc.user.id), listDestinations(env, rc.user.id, { usableOnly: true })]);
  return json(200, { methods, destinations: dests.map((d) => ({ id: d.id, kind: d.kind, hint: d.hint, label: d.label })) });
}

async function stepUpCode(rc) {
  const b = await body(rc);
  await chargeFactor(rc);
  const code = codeInput(b.code);
  if (code !== null) {
    if (await checkTotp(rc, rc.user.id, code)) return stepUpDone(rc, 'totp');
    if (await consumeBackupCode(rc, rc.user.id, code)) return stepUpDone(rc, 'backup');
  }
  throw await stepUpFailed(rc, 'Wrong authenticator or backup code at step-up');
}

async function stepUpSend(rc) {
  const b = await body(rc);
  const did = toInt(b.destination_id, 1);
  if (!Number.isFinite(did)) throw new ValidationError('Choose where to send the code.', 'destination_id');
  const r = await sendCode(rc, rc.user.id, did);
  if (!r.sent) throw new HttpError(503, { error: 'We couldn’t send a code there just now. Try again, or choose another way.', code: 'send_failed' });
  await audit(rc, { action: 'mfa.code_sent', target: me(rc), detail: `Sent a step-up code to ${r.hint}` });
  return json(200, { sent: { kind: r.kind, hint: r.hint } });
}

async function stepUpOtp(rc) {
  const b = await body(rc);
  await chargeFactor(rc);
  const did = toInt(b.destination_id, 1);
  const code = codeInput(b.code);
  const dest = Number.isFinite(did)
    ? await rc.env.DB.prepare('SELECT kind FROM code_destinations WHERE id = ? AND user_id = ?').bind(did, rc.user.id).first()
    : null;
  if (dest && code !== null && (await verifyCode(rc, rc.user.id, did, code))) return stepUpDone(rc, dest.kind === 'sms' ? 'sms' : 'email');
  throw await stepUpFailed(rc, 'Wrong or expired step-up code');
}

async function stepUpPasskeyOptions(rc) {
  return json(200, await assertionOptions(rc, rc.user, 'stepup'));
}

async function stepUpPasskeyVerify(rc) {
  const b = await body(rc);
  await chargeFactor(rc);
  try {
    await verifyAssertion(rc, rc.user, b.credential, 'stepup');
  } catch (e) {
    if (e instanceof HttpError) await audit(rc, { action: 'stepup.fail', outcome: 'failure', target: me(rc), detail: `Passkey refused at step-up (${typeof e.reason === 'string' ? e.reason : e.message})` });
    throw e;
  }
  return stepUpDone(rc, 'passkey');
}

// ---------------------------------------------------------------- second factors

// Adding a factor to an account that can already prove who it is needs that
// proof first (SPEC §7.9): otherwise whoever sits at a session whose step-up
// has gone stale registers a key of their own, steps up with it, and then
// removes the owner's factors. An account with nothing to prove itself with
// — a first factor, or a session pinned to enrolment, which cannot reach the
// step-up routes — enrols on the session alone. → the methods it had.
async function requireStepUpToEnrol(rc) {
  const had = await availableMethods(rc.env, rc.user.id);
  if (had.length > 0 && rc.session.pinned !== 'mfa_enroll') requireStepUp(rc);
  return had;
}

async function totpBegin(rc) {
  await requireStepUpToEnrol(rc);
  const r = await beginTotp(rc, rc.user.id);
  return json(200, { secret_grouped: r.secret_grouped, otpauth: r.otpauth, qr: r.qr });
}

// Proving a code from the new authenticator marks step-up only for an
// account that had no other way to prove itself (CONTRACTS §8.4): a factor
// the session just added must never stand in for one the account already had.
async function totpConfirm(rc) {
  const had = await requireStepUpToEnrol(rc);
  const b = await body(rc);
  const r = await confirmTotp(rc, rc.user.id, codeInput(b.code) ?? '');
  if (had.length === 0) {
    await markStepUp(rc.env, rc.session.id, 'totp', rc.nowMs);
    rc.session.aal = 2;
    rc.session.mfa_at = iso(rc.nowMs);
  }
  // A new way in is worth noticing in the log, whoever added it.
  await audit(rc, { action: 'mfa.totp.enroll', target: me(rc), severity: 'notice', detail: 'Set up an authenticator app' });
  if (r.backup_codes) await audit(rc, { action: 'mfa.backup.generate', target: me(rc), detail: `Issued ${r.backup_codes.length} backup codes` });
  return json(200, { backup_codes: r.backup_codes, ...(await repin(rc)) });
}

async function totpRemove(rc) {
  requireStepUp(rc);
  const uid = rc.user.id;
  if (!(await rc.env.DB.prepare('SELECT 1 AS x FROM user_totp WHERE user_id = ?').bind(uid).first())) throw notFound('No authenticator app is set up.');
  if (!(await canDropFactor(rc.env, uid, 'totp'))) throw lastFactor();
  await removeTotp(rc, uid);
  await audit(rc, { action: 'mfa.totp.remove', target: me(rc), detail: 'Removed their authenticator app' });
  return json(200, { ok: true });
}

async function passkeyRegOptions(rc) {
  await requireStepUpToEnrol(rc);
  return json(200, await registrationOptions(rc, rc.user));
}

// Registration verifies no signature under attestation 'none', so it is NOT
// a factor proved and does not mark step-up (A §7.4).
async function passkeyRegister(rc) {
  await requireStepUpToEnrol(rc);
  const b = await body(rc);
  const row = await verifyRegistration(rc, rc.user, b.credential, b.label);
  await audit(rc, { action: 'mfa.passkey.add', target: me(rc), severity: 'notice', detail: `Added passkey “${row.label || 'unnamed'}”` });
  const backup_codes = await backupCodesIfNone(rc);
  return json(200, { passkey: passkeyView(row), backup_codes, ...(await repin(rc)) });
}

async function passkeyRename(rc, params) {
  const b = await body(rc);
  const label = strStrict(b.label, 1, LABEL_MAX);
  if (label === null) throw new ValidationError(`A passkey name must be 1 to ${LABEL_MAX} characters.`, 'label');
  const res = await rc.env.DB.prepare('UPDATE user_passkeys SET label = ? WHERE id = ? AND user_id = ?').bind(label, params.id, rc.user.id).run();
  if (res.meta.changes !== 1) throw notFound('No such passkey.');
  await audit(rc, { action: 'mfa.passkey.rename', target: me(rc), detail: `Renamed a passkey to “${label}”` });
  return json(200, { ok: true });
}

async function passkeyRemove(rc, params) {
  requireStepUp(rc);
  const uid = rc.user.id;
  const row = await rc.env.DB.prepare('SELECT id, label FROM user_passkeys WHERE id = ? AND user_id = ?').bind(params.id, uid).first();
  if (!row) throw notFound('No such passkey.');
  if (!(await canDropFactor(rc.env, uid, 'passkey'))) throw lastFactor();
  await rc.env.DB.prepare('DELETE FROM user_passkeys WHERE id = ? AND user_id = ?').bind(row.id, uid).run();
  await audit(rc, { action: 'mfa.passkey.remove', target: me(rc), detail: `Removed passkey “${row.label || 'unnamed'}”` });
  return json(200, { ok: true });
}

async function backupRegenerate(rc) {
  requireStepUp(rc);
  const codes = generateBackupCodes();
  await storeBackupCodes(rc.env, rc.user.id, codes, rc.nowMs);
  await audit(rc, { action: 'mfa.backup.generate', target: me(rc), detail: `Replaced their backup codes with ${codes.length} new ones` });
  return json(200, { backup_codes: codes });
}

export function register(router) {
  router.add('GET', '/api/me', getMe, { auth: 'pinned-ok' });
  router.add('PATCH', '/api/me', patchMe, { auth: 'session' });
  router.add('POST', '/api/me/password', changePassword, { auth: 'pinned-ok' });
  router.add('GET', '/api/me/streak', myStreak, { auth: 'session' });
  router.add('GET', '/api/me/sessions', mySessions, { auth: 'session' });
  router.add('POST', '/api/me/sessions/revoke-others', endOtherSessions, { auth: 'session' });
  router.add('DELETE', '/api/me/sessions/:ref', endSession, { auth: 'session' });
  router.add('GET', '/api/me/devices', myDevices, { auth: 'session' });
  router.add('POST', '/api/me/devices/approve', approveDevice, { auth: 'session' });
  router.add('DELETE', '/api/me/devices/:id', forgetDevice, { auth: 'session' });
  router.add('GET', '/api/me/activity', myActivity, { auth: 'session' });
  router.add('GET', '/api/me/fingerprint', myFingerprint, { auth: 'session' });
  router.add('GET', '/api/me/step-up', stepUpInfo, { auth: 'session' });
  router.add('POST', '/api/me/step-up/code', stepUpCode, { auth: 'session' });
  router.add('POST', '/api/me/step-up/send', stepUpSend, { auth: 'session' });
  router.add('POST', '/api/me/step-up/otp', stepUpOtp, { auth: 'session' });
  router.add('POST', '/api/me/step-up/passkey/options', stepUpPasskeyOptions, { auth: 'session' });
  router.add('POST', '/api/me/step-up/passkey/verify', stepUpPasskeyVerify, { auth: 'session' });
  router.add('POST', '/api/me/mfa/totp/begin', totpBegin, { auth: 'pinned-ok' });
  router.add('POST', '/api/me/mfa/totp/confirm', totpConfirm, { auth: 'pinned-ok' });
  router.add('DELETE', '/api/me/mfa/totp', totpRemove, { auth: 'session' });
  router.add('POST', '/api/me/mfa/passkey/options', passkeyRegOptions, { auth: 'pinned-ok' });
  router.add('POST', '/api/me/mfa/passkey/register', passkeyRegister, { auth: 'pinned-ok' });
  router.add('PATCH', '/api/me/mfa/passkey/:id', passkeyRename, { auth: 'session' });
  router.add('DELETE', '/api/me/mfa/passkey/:id', passkeyRemove, { auth: 'session' });
  router.add('POST', '/api/me/mfa/backup/regenerate', backupRegenerate, { auth: 'session' });
  return router;
}
