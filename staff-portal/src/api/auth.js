// Sign-in: password, then a second factor or a live grace window, then the
// one tail (CONTRACTS §8.4 Auth; A §6, §7.1–7.2, §8; B §5, trap 4; SPEC §6.3).
//
// Every failure a stranger can provoke is the same 401 bytes — no such
// account, wrong password, suspended, disabled, locked — and the audit log
// says which it was, because an administrator has to work out why someone
// cannot get in (A §6). Every limit is charged BEFORE the check it protects.

import { json, readJson, toInt, str } from '../util.js';
import { HttpError, ValidationError, tooMany } from '../errors.js';
import { verifyPassword, burnPasswordCost, PASSWORD_ALGO } from '../crypto.js';
import { charge } from '../ratelimit.js';
import { audit } from '../audit.js';
import { DEFAULT_PRIVACY_NOTICE } from '../policy.js';
import { canonicalIdentifier, findUserByIdentifier, getUser, publicUser, isLocked, knownDeviceFor, recordLoginFailure, LOCK_AFTER } from '../users.js';
import { effectivePermissions } from '../rbac.js';
import { graceValid } from '../grace.js';
import { revokeSession, clearSessionCookie } from '../sessions.js';
import { issueMfaToken, readMfaToken } from '../mfa/token.js';
import { availableMethods, userFactors, hasStrongFactor } from '../mfa/factors.js';
import { checkTotp } from '../mfa/totp.js';
import { consumeBackupCode } from '../mfa/backup.js';
import { listDestinations, primaryDestination, sendCode, verifyCode } from '../mfa/otp.js';
import { assertionOptions, verifyAssertion } from '../webauthn/webauthn.js';
import { completeSignIn, knownDeviceLoginSubject, INVALID_CREDENTIALS } from '../signin.js';

const PASSWORD_INPUT_MAX = 4096;
const CODE_INPUT_MAX = 64;
const ALLOWLISTED_LOGIN_IP_MAX = 200; // a whole office shares one address (SPEC §6.4)

// One body, built once: the reply to every credential failure is byte-identical.
const INVALID_BODY = JSON.stringify({ error: INVALID_CREDENTIALS });

export function invalidCredentials() {
  return new Response(INVALID_BODY, { status: 401, headers: { 'content-type': 'application/json; charset=utf-8' } });
}

export function orgName(env) {
  return str(env?.ORG_NAME, 100) || 'Staff portal';
}

export function privacyNotice(policy) {
  if (!policy || policy.privacy_notice === false) return null;
  return typeof policy.privacy_notice_text === 'string' && policy.privacy_notice_text.trim() ? policy.privacy_notice_text : DEFAULT_PRIVACY_NOTICE;
}

async function body(rc) {
  return (await readJson(rc.request)) || {};
}

function lockdownRefusal() {
  return new HttpError(403, { error: 'The portal is in lockdown. Only a Super Admin can sign in.', code: 'lockdown' });
}

function codeInput(v) {
  return typeof v === 'string' && v.length <= CODE_INPUT_MAX ? v : null;
}

// ---------------------------------------------------------------- password

async function login(rc) {
  const env = rc.env;
  const t = rc.nowMs;
  // fingerprint_gate: the login shell lasts only until a fingerprint is on
  // file, so no MFA token can be had without one (CONTRACTS §7.8).
  if (rc.gate?.shell === 'login') {
    return json(403, { error: 'This browser has to report its fingerprint before signing in.', fingerprint_required: true });
  }
  // Never cleared, not even on success (B trap 4).
  const ipLim = await charge(env, 'login_ip', rc.ip ?? '?', t, rc.ipTier ? { max: ALLOWLISTED_LOGIN_IP_MAX } : {});
  if (!ipLim.allowed) throw tooMany(ipLim.retryAfterSec);
  const b = await body(rc);
  const ident = typeof b.identifier === 'string' ? b.identifier.trim().toLowerCase().slice(0, 254) : '';
  // The log names what was typed (§16.26); the bucket and the lookup use the
  // one normal form, so spellings the lookup treats as one account cannot
  // each have a fresh bucket. Anything that names no possible account shares
  // one bucket.
  const canon = canonicalIdentifier(ident);
  const user = canon ? await findUserByIdentifier(env, ident) : null;
  // D6: a stranger can spend the bucket for an account, never the one of a
  // device that has signed in to it before — that device has a bucket of its
  // own (per account and device), so junk sign-ins from elsewhere cannot keep
  // the owner out of their own laptop. The lookup is not a credential check;
  // the bucket is still charged before the password is.
  const known = !!user && typeof rc.device?.id === 'string' && (await knownDeviceFor(env, user.id, rc.device.id));
  const idSubject = known ? knownDeviceLoginSubject(user.id, rc.device.id) : canon ? canon.value : '?';
  const idLim = await charge(env, 'login_id', idSubject, t);
  if (!idLim.allowed) throw tooMany(idLim.retryAfterSec);
  const password = typeof b.password === 'string' && b.password.length <= PASSWORD_INPUT_MAX ? b.password : null;
  const who = ident ? `'${ident.slice(0, 100)}'` : 'a blank name';

  if (!user) {
    // Same work as a real check, so the clock does not tell them either.
    await burnPasswordCost(env, password ?? '');
    await audit(rc, { action: 'login.fail', outcome: 'failure', detail: `No account called ${who}` });
    return invalidCredentials();
  }
  const target = { type: 'user', id: user.id };
  // The password BEFORE the account's state (A §2): a suspended account must
  // look exactly like a wrong password to someone without the password. A
  // password we will not check (not a string, or an invited account with
  // none yet) still costs a full derivation, so timing says nothing either.
  let ok = false;
  if (password !== null && user.password_algo === PASSWORD_ALGO) ok = await verifyPassword(password, user);
  else await burnPasswordCost(env, password ?? '');
  if (!ok) {
    await recordLoginFailure(env, user, t);
    const failures = (toInt(user.failed_logins, 0) || 0) + 1;
    const lockNote = failures === LOCK_AFTER ? '; the account is now locked for 15 minutes except on devices that have signed in to it before' : '';
    await audit(rc, { action: 'login.fail', outcome: 'failure', target, detail: `Wrong password for ${who}${lockNote}` });
    return invalidCredentials();
  }
  if (user.status !== 'active') {
    await audit(rc, { action: 'login.fail', outcome: 'denied', target, detail: `Refused the correct password for ${who}: the account is ${user.status}` });
    return invalidCredentials();
  }
  // D6: a stranger can lock an account against strangers, never against a
  // device that has signed in to it before.
  if (isLocked(user, t)) {
    if (!known) {
      await audit(rc, {
        action: 'login.fail',
        outcome: 'denied',
        target,
        detail: `Refused the correct password for ${who}: the account is locked after repeated failures and this device has not signed in to it before`,
      });
      return invalidCredentials();
    }
  }
  const authz = await effectivePermissions(env, user, t);
  if (rc.policy?.access_mode === 'lockdown' && authz.isSuper !== true) {
    await audit(rc, { action: 'login.denied', outcome: 'denied', target, detail: `Refused ${who}: lockdown admits only Super Admins` });
    throw lockdownRefusal();
  }
  return afterPassword(rc, user);
}

async function afterPassword(rc, user) {
  const env = rc.env;
  const uid = user.id;
  const [methods, f] = await Promise.all([availableMethods(env, uid), userFactors(env, uid)]);
  // An authenticator that will not decrypt is a factor nobody can satisfy —
  // never "no factor", which would quietly fall back to the password (A §7.3).
  if (methods.length === 0 && !f.totpUnreadable) return completeSignIn(rc, user, 'password', { aal: 1 });

  const tier = toInt(rc.ipTier, 1, 4);
  if (rc.policy?.mfa_grace === true && Number.isFinite(tier) && typeof rc.device?.id === 'string') {
    const g = await graceValid(env, uid, rc.device.id, tier, rc.nowMs);
    if (g.valid) return completeSignIn(rc, user, 'grace', { aal: 2, mfaAt: g.verifiedAt });
  }

  const destinations = (await listDestinations(env, uid, { usableOnly: true })).map((d) => ({ id: d.id, kind: d.kind, hint: d.hint, label: d.label }));
  let destinationId = null;
  let sent = null;
  // A code goes out unasked only when a code is the ONLY way in (A §7.1):
  // nobody with a passkey or an authenticator is ever texted.
  if (!f.totpUnreadable && methods.every((m) => m === 'email' || m === 'sms')) {
    const dest = await primaryDestination(env, uid);
    if (dest) {
      try {
        const r = await sendCode(rc, uid, dest.id);
        if (r.sent) {
          destinationId = dest.id;
          sent = { kind: r.kind, hint: r.hint };
          await audit(rc, { action: 'mfa.code_sent', target: { type: 'user', id: uid }, detail: `Sent a sign-in code to ${r.hint}` });
        }
      } catch (e) {
        // Over the send limit: the page offers the destinations to try later.
        if (!(e instanceof HttpError)) throw e;
      }
    }
  }
  const token = await issueMfaToken(env, uid, destinationId, rc.nowMs);
  return json(200, { mfa_required: true, token, methods, destinations, sent });
}

// ---------------------------------------------------------------- factors

// Every factor step re-reads the account: a suspension or lockdown landing
// between the password and the factor must not be completable with a code
// already in hand (A §7.2).
async function pendingSignIn(rc, b) {
  const tok = await readMfaToken(rc.env, b.token, rc.nowMs);
  if (!tok) throw new HttpError(401, { error: 'This sign-in has expired. Start again.', code: 'mfa_expired' });
  const user = await getUser(rc.env, tok.userId);
  if (!user || user.status !== 'active') {
    await audit(rc, {
      action: 'mfa.fail',
      outcome: 'denied',
      target: user ? { type: 'user', id: user.id } : null,
      detail: user ? `Refused a second factor: the account is ${user.status}` : 'Refused a second factor for an account that no longer exists',
    });
    throw new HttpError(401, { error: INVALID_CREDENTIALS });
  }
  if (rc.policy?.access_mode === 'lockdown' && (await effectivePermissions(rc.env, user, rc.nowMs)).isSuper !== true) throw lockdownRefusal();
  return { user, destinationId: tok.destinationId };
}

async function chargeFactor(rc, uid) {
  const lim = await charge(rc.env, 'mfa_user', String(uid), rc.nowMs);
  if (!lim.allowed) throw tooMany(lim.retryAfterSec);
}

async function factorFailed(rc, uid, detail) {
  await audit(rc, { action: 'mfa.fail', outcome: 'failure', target: { type: 'user', id: uid }, detail });
}

// TOTP or a backup code in ONE box (A §7.3): the authenticator first, then
// the backup code, then fail.
async function mfaCode(rc) {
  const b = await body(rc);
  const { user } = await pendingSignIn(rc, b);
  await chargeFactor(rc, user.id);
  const code = codeInput(b.code);
  let how = null;
  if (code !== null) {
    if (await checkTotp(rc, user.id, code)) how = 'totp';
    else if (await consumeBackupCode(rc, user.id, code)) how = 'backup';
  }
  if (!how) {
    await factorFailed(rc, user.id, 'Wrong authenticator or backup code');
    throw new HttpError(401, { error: 'That code didn’t work. Use the newest code from your app, or a backup code.', code: 'mfa_invalid' });
  }
  return completeSignIn(rc, user, how, { aal: 2, mfaAt: rc.nowMs, factorVerified: true });
}

// A new token bound to the destination the code went to: verification is
// keyed on it, so removing that destination stops the code being a way in.
async function mfaSend(rc) {
  const b = await body(rc);
  const { user } = await pendingSignIn(rc, b);
  const did = toInt(b.destination_id, 1);
  if (!Number.isFinite(did)) throw new ValidationError('Choose where to send the code.', 'destination_id');
  const r = await sendCode(rc, user.id, did);
  if (!r.sent) throw new HttpError(503, { error: 'We couldn’t send a code there just now. Try again, or choose another way.', code: 'send_failed' });
  await audit(rc, { action: 'mfa.code_sent', target: { type: 'user', id: user.id }, detail: `Sent a sign-in code to ${r.hint}` });
  return json(200, { token: await issueMfaToken(rc.env, user.id, did, rc.nowMs), sent: { kind: r.kind, hint: r.hint } });
}

async function mfaOtp(rc) {
  const b = await body(rc);
  const { user, destinationId } = await pendingSignIn(rc, b);
  await chargeFactor(rc, user.id);
  const code = codeInput(b.code);
  const dest =
    destinationId === null
      ? null
      : await rc.env.DB.prepare('SELECT kind FROM code_destinations WHERE id = ? AND user_id = ?').bind(destinationId, user.id).first();
  if (!dest || code === null || !(await verifyCode(rc, user.id, destinationId, code))) {
    await factorFailed(rc, user.id, 'Wrong or expired sign-in code');
    throw new HttpError(401, { error: 'That code didn’t work, or it has expired. Send a new one.', code: 'mfa_invalid' });
  }
  return completeSignIn(rc, user, dest.kind === 'sms' ? 'sms' : 'email', { aal: 2, mfaAt: rc.nowMs, factorVerified: true });
}

async function passkeyOptions(rc) {
  const { user } = await pendingSignIn(rc, await body(rc));
  return json(200, await assertionOptions(rc, user, 'auth'));
}

async function passkeyVerify(rc) {
  const b = await body(rc);
  const { user } = await pendingSignIn(rc, b);
  await chargeFactor(rc, user.id);
  try {
    await verifyAssertion(rc, user, b.credential, 'auth');
  } catch (e) {
    if (e instanceof HttpError) await factorFailed(rc, user.id, `Passkey refused (${typeof e.reason === 'string' ? e.reason : e.message})`);
    throw e;
  }
  return completeSignIn(rc, user, 'passkey', { aal: 2, mfaAt: rc.nowMs, factorVerified: true });
}

// ---------------------------------------------------------------- session

async function logout(rc) {
  await revokeSession(rc.env, rc.session.id, 'logout');
  rc.setCookies.push(clearSessionCookie());
  await audit(rc, { action: 'logout', target: { type: 'user', id: rc.user.id }, detail: 'Signed out' });
  return json(200, { ok: true });
}

// The login page's source for the org name and the fingerprinting notice,
// and how every page checks that the session cookie came home (A §5).
async function whoami(rc) {
  const base = { org_name: orgName(rc.env), privacy_notice: privacyNotice(rc.policy) };
  if (!rc.session || !rc.user) return json(200, { authenticated: false, ...base });
  return json(200, {
    authenticated: true,
    user: publicUser(rc.user, rc.authz),
    pinned: rc.session.pinned ?? null,
    enroll_prompt: !(await hasStrongFactor(rc.env, rc.user.id)),
    ...base,
  });
}

export function register(router) {
  router.add('POST', '/api/auth/login', login, { auth: 'none' });
  router.add('POST', '/api/auth/mfa/code', mfaCode, { auth: 'none' });
  router.add('POST', '/api/auth/mfa/send', mfaSend, { auth: 'none' });
  router.add('POST', '/api/auth/mfa/otp', mfaOtp, { auth: 'none' });
  router.add('POST', '/api/auth/mfa/passkey/options', passkeyOptions, { auth: 'none' });
  router.add('POST', '/api/auth/mfa/passkey/verify', passkeyVerify, { auth: 'none' });
  router.add('POST', '/api/auth/logout', logout, { auth: 'pinned-ok' });
  router.add('GET', '/api/auth/whoami', whoami, { auth: 'none' });
  return router;
}
