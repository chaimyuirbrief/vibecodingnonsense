// completeSignIn — THE one tail for every way in (CONTRACTS §7.9; A §7.2
// "One completion path for every factor", §14.8; SPEC §7.3). Password only, a
// grace window, an authenticator, a backup code, a sent code, a passkey, an
// accepted invitation and the setup page all end here, so the session, the
// device ledger, the grace window, the counters, the audit line and the
// streak are established identically. Four near-copies is how one factor
// ends up not starting a grace window and nobody notices for months.

import { json, iso, toInt, now } from './util.js';
import { HttpError } from './errors.js';
import { trackDevice } from './devices.js';
import { recordGrace } from './grace.js';
import { nextPin, createSession } from './sessions.js';
import { getUser, publicUser, clearLoginFailures } from './users.js';
import { effectivePermissions } from './rbac.js';
import { clear } from './ratelimit.js';
import { audit, auditError } from './audit.js';
import { hasStrongFactor } from './mfa/factors.js';
import { streakConfig, touchStreak } from './streak.js';

export const INVALID_CREDENTIALS = 'Invalid credentials.';

// How each method reads in the audit log; the key itself is stored as the
// session's mfa_method, so the log and the session agree (A §7.2).
export const HOW = Object.freeze({
  password: 'a password',
  grace: 'a password inside a second-factor grace window',
  totp: 'an authenticator app',
  backup: 'a backup code',
  email: 'an emailed code',
  sms: 'a texted code',
  passkey: 'a passkey',
  invitation: 'an invitation',
  setup: 'the setup page',
});

// The login_id subject for a device that has signed in to the account
// before (D6): its own bucket, so a stranger spending the account's bucket
// cannot keep the owner out of their own laptop. Cleared on success with the
// other per-account counters.
export function knownDeviceLoginSubject(userId, deviceId) {
  return `user:${userId}|device:${deviceId}`;
}

export function pinTarget(pin) {
  return pin ? `/account?pin=${encodeURIComponent(pin)}` : '/';
}

function nowOf(rc) {
  return typeof rc.nowMs === 'number' && Number.isFinite(rc.nowMs) ? rc.nowMs : now(rc.env);
}

// → Response 200 { ok, user, pinned, enroll_prompt, next, streak }.
// Callers have verified everything about HOW; this re-reads the account so a
// suspension or a lockdown that landed a moment ago still refuses (A §7.2).
export async function completeSignIn(rc, user, how, opts = {}) {
  const env = rc.env;
  const t = nowOf(rc);
  if (!Object.hasOwn(HOW, how)) throw new Error(`completeSignIn: unknown method '${String(how)}'`);
  const o = opts && typeof opts === 'object' ? opts : {};
  const fresh = await getUser(env, user?.id);
  if (!fresh || fresh.status !== 'active') throw new HttpError(401, { error: INVALID_CREDENTIALS });
  const authz = await effectivePermissions(env, fresh, t);
  if (rc.policy?.access_mode === 'lockdown' && authz.isSuper !== true) {
    throw new HttpError(403, { error: 'The portal is in lockdown. Only a Super Admin can sign in.', code: 'lockdown' });
  }
  const uid = fresh.id;

  // 1. The device: minted if absent, ledger updated.
  const dev = await trackDevice(rc, uid);
  if (dev.setCookie) rc.setCookies.push(dev.setCookie);

  // 2. A grace window only for a factor PROVED now, on a network with a tier
  // (A §8: riding a window must not extend it; no tier, no grace).
  const tier = toInt(rc.ipTier && typeof rc.ipTier === 'object' ? rc.ipTier.tier : rc.ipTier, 1, 4);
  if (o.factorVerified === true && Number.isFinite(tier) && rc.policy?.mfa_grace === true) {
    await recordGrace(env, uid, dev.id, tier, t);
  }

  // 3–4. Pin, never refuse (B trap 3).
  const pinned = await nextPin(env, fresh, rc.policy);
  const aal = toInt(o.aal, 1, 2) === 2 ? 2 : 1;
  const session = await createSession(rc, fresh, { aal, mfaAt: o.mfaAt ?? null, mfaMethod: how, pinned, deviceId: dev.id });
  rc.setCookies.push(session.cookie);

  // 5–6. Per-account counters are cleared; the per-IP bucket never is (B trap 4).
  await env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').bind(iso(t), uid).run();
  for (const subject of [fresh.email, fresh.username]) {
    if (typeof subject === 'string' && subject) await clear(env, 'login_id', subject.toLowerCase());
  }
  await clear(env, 'login_id', knownDeviceLoginSubject(uid, dev.id));
  await clear(env, 'mfa_user', String(uid));
  await clearLoginFailures(env, uid);

  // 7. One audit row per sign-in, whatever the method.
  const actx = { ...rc, session: { id: session.id }, user: fresh };
  await audit(actx, {
    action: 'login.success',
    target: { type: 'user', id: uid },
    detail: `Signed in with ${HOW[how]}`,
    after: { method: how, aal, pinned },
  });

  // 8. Decoration: never blocks a sign-in (A §10). touchStreak never throws;
  // it hands its failure to onError so the real exception reaches the audit
  // log (CONTRACTS §0.4). The guard is for streakConfig and the audit calls.
  let streak = null;
  const streakTarget = { type: 'user', id: uid };
  try {
    streak = await touchStreak(env, uid, t, streakConfig(rc.policy), {
      onError: (e) => auditError(actx, 'streak.error', e, { target: streakTarget, detail: 'Could not count today’s sign-in toward the streak.' }),
    });
    if (streak && streak.repaired) {
      await audit(actx, {
        action: 'streak.error',
        outcome: 'failure',
        severity: 'warning',
        target: { type: 'user', id: uid },
        detail: `The stored streak could not be read (${streak.repaired}); it restarted at 1.`,
      });
    }
  } catch (e) {
    await auditError(actx, 'streak.error', e, { target: { type: 'user', id: uid }, detail: 'Could not count today’s sign-in toward the streak.' });
    streak = null;
  }

  rc.user = await getUser(env, uid);
  return json(200, {
    ok: true,
    user: publicUser(rc.user, authz),
    pinned,
    enroll_prompt: !(await hasStrongFactor(env, uid)),
    next: pinTarget(pinned),
    streak,
  });
}
