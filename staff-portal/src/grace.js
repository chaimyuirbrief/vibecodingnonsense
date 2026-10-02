// Second-factor grace windows (CONTRACTS §7.8, A §8, D9).
//
// Remembered per account AND per device: a browser that never completed a
// factor check gets nothing however trusted the network. The window in force
// is the SHORTER of the stored expiry and the current network's window
// measured from the proof — arriving from a lower tier shortens it; a higher
// one never lengthens it. No tier (not allowlisted) → no grace; tier 4 → none.
//
// Whether grace applies at all (`mfa_grace`) is the caller's policy check.

import { iso, now, toInt, parseIsoStrict, HOUR, DAY } from './util.js';

export const GRACE_MS = Object.freeze({ 1: 7 * DAY, 2: DAY, 3: 2 * HOUR, 4: 0 });

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function windowFor(tier) {
  const t = toInt(tier, 1, 4);
  return Number.isFinite(t) ? GRACE_MS[t] : 0;
}

// Device ids are printable tokens; whitespace or an over-long string is not one.
function deviceKey(v) {
  return typeof v === 'string' && /^[\x21-\x7e]{1,128}$/.test(v) ? v : null;
}

// Called by completeSignIn only when a factor was ACTUALLY proved on this
// sign-in (riding a window must not extend it). The latest proof replaces the
// row, so a window is never longer than the most recent proof allows. A tier
// with no window (4) records nothing; an unreadable argument records nothing.
export async function recordGrace(env, userId, deviceId, tier, nowMs) {
  const uid = toInt(userId, 1);
  const dev = deviceKey(deviceId);
  const t = toInt(tier, 1, 4);
  const w = windowFor(t);
  if (!Number.isFinite(uid) || !dev || !(w > 0)) return;
  const at = finite(nowMs) ? nowMs : now(env);
  await env.DB.prepare(
    `INSERT INTO mfa_grace (user_id, device_id, tier, verified_at, expires_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(user_id, device_id) DO UPDATE SET tier = excluded.tier, verified_at = excluded.verified_at, expires_at = excluded.expires_at`,
  )
    .bind(uid, dev, t, iso(at), iso(at + w))
    .run();
}

// → { valid, verifiedAt: ms | null }. Every unreadable value — the tier
// passed in, the stored tier, either stored time — is invalid, and so is a
// proof dated in the future (a clock moved or a backup was restored: A §11).
// The stored tier's own window caps the stored expiry too, so a corrupted
// expires_at cannot buy more than the tier it was granted on.
export async function graceValid(env, userId, deviceId, currentTier, nowMs) {
  const no = { valid: false, verifiedAt: null };
  const w = windowFor(currentTier);
  const uid = toInt(userId, 1);
  const dev = deviceKey(deviceId);
  if (!(w > 0) || !Number.isFinite(uid) || !dev) return no;
  const t = finite(nowMs) ? nowMs : now(env);
  const row = await env.DB.prepare('SELECT tier, verified_at, expires_at FROM mfa_grace WHERE user_id = ? AND device_id = ?')
    .bind(uid, dev)
    .first();
  if (!row) return no;
  const verified = parseIsoStrict(row.verified_at);
  const expires = parseIsoStrict(row.expires_at);
  const stored = windowFor(row.tier);
  if (!Number.isFinite(verified) || !Number.isFinite(expires) || !(stored > 0) || verified > t) return no;
  const until = Math.min(expires, verified + w, verified + stored);
  return t < until ? { valid: true, verifiedAt: verified } : no;
}

// Trust withdrawn → the window goes (A §8): device revoked or blocked, a
// user's devices revoked, password reset, suspended, factors cleared. A key
// that is present but unreadable THROWS rather than silently dropping
// nothing — a no-op here would leave a revoked device coasting.
export async function dropGrace(env, opts = {}) {
  const o = opts && typeof opts === 'object' ? opts : {};
  const hasUser = o.userId !== undefined && o.userId !== null;
  const hasDevice = o.deviceId !== undefined && o.deviceId !== null;
  const uid = hasUser ? toInt(o.userId, 1) : null;
  const dev = hasDevice ? deviceKey(o.deviceId) : null;
  if ((!hasUser && !hasDevice) || (hasUser && !Number.isFinite(uid)) || (hasDevice && !dev)) {
    throw new Error('grace: dropGrace needs a readable userId and/or deviceId');
  }
  await env.DB.prepare('DELETE FROM mfa_grace WHERE (? IS NULL OR user_id = ?) AND (? IS NULL OR device_id = ?)')
    .bind(uid, uid, dev, dev)
    .run();
}
