// The half-finished sign-in (CONTRACTS §7.6; A §7.2; SPEC §7.2).
//
//   payload = `${userId}.${destinationId}.${expiresAtMs}`   (destinationId 0 = none)
//   token   = signToken(env, 'mfa', payload)
//
// Five minutes. It binds WHICH destination a code was sent to: verification
// is keyed on where the code went, so removing that destination stops the
// code being a way in. The 'mfa' purpose stops a device or fingerprint
// cookie being replayed as one of these.

import { signToken, verifyToken } from '../crypto.js';
import { now, toInt, MINUTE } from '../util.js';

export const MFA_TOKEN_TTL_MS = 5 * MINUTE;
// A clock that stepped back a little must not strand a token just issued; one
// that claims to expire further out than we ever issue was not minted here.
const FUTURE_SKEW_MS = MINUTE;
// Strict shape BEFORE any numeric coercion (A §14.2): no signs, no leading
// zeros, no exponents, nothing toInt might be generous about.
const PAYLOAD_RE = /^([1-9]\d{0,15})\.(0|[1-9]\d{0,15})\.([1-9]\d{0,15})$/;

function clockOf(env, nowMs) {
  return typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : now(env);
}

export async function issueMfaToken(env, userId, destinationId, nowMs) {
  const uid = toInt(userId, 1, Number.MAX_SAFE_INTEGER);
  if (!Number.isFinite(uid)) throw new RangeError('issueMfaToken: bad user id');
  let did = 0;
  if (destinationId !== null && destinationId !== undefined) {
    did = toInt(destinationId, 1, Number.MAX_SAFE_INTEGER);
    if (!Number.isFinite(did)) throw new RangeError('issueMfaToken: bad destination id');
  }
  const exp = clockOf(env, nowMs) + MFA_TOKEN_TTL_MS;
  return signToken(env, 'mfa', `${uid}.${did}.${Math.floor(exp)}`);
}

// → { userId, destinationId: number | null } or null for anything forged,
// malformed, expired or implausibly far in the future.
export async function readMfaToken(env, token, nowMs) {
  const payload = await verifyToken(env, 'mfa', token);
  if (payload === null) return null;
  const m = PAYLOAD_RE.exec(payload);
  if (!m) return null;
  const uid = toInt(m[1], 1, Number.MAX_SAFE_INTEGER);
  const did = toInt(m[2], 0, Number.MAX_SAFE_INTEGER);
  const exp = toInt(m[3], 1, Number.MAX_SAFE_INTEGER);
  if (!Number.isFinite(uid) || !Number.isFinite(did) || !Number.isFinite(exp)) return null;
  const t = clockOf(env, nowMs);
  if (exp <= t || exp > t + MFA_TOKEN_TTL_MS + FUTURE_SKEW_MS) return null;
  return { userId: uid, destinationId: did === 0 ? null : did };
}
