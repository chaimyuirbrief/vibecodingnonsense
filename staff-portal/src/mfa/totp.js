// Authenticator apps: RFC 6238 TOTP — HMAC-SHA1, 6 digits, 30 s step, one
// step of drift either way (CONTRACTS §7.6; A §7.3, §14.3; B §5).
//
// Stored as crypto.encrypt(env, base32, 'totp:' + userId): the AAD binds the
// blob to its row so a ciphertext cannot be moved to another account. A row
// that will not decrypt is REFUSED and audited, never read as "no
// authenticator" — that would quietly fall back to something weaker.

import { audit } from '../audit.js';
import { encrypt, decrypt, timingSafeEqual } from '../crypto.js';
import { HttpError, notFound } from '../errors.js';
import { qrDataUri } from '../qr.js';
import { now, iso, toInt, str, randomBytes } from '../util.js';
import { countUnusedBackupCodes, generateBackupCodes, storeBackupCodes } from './backup.js';

export const TOTP_STEP_MS = 30_000;
export const TOTP_DIGITS = 6;
export const TOTP_SECRET_BYTES = 20; // 160 bits, as generated
// RFC 4226 §4 R6. Enforced at VERIFICATION, not only at generation: with a
// one-byte secret one observed code narrows it to a single candidate (A §7.3).
export const TOTP_MIN_SECRET_BYTES = 16;

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CODE_INPUT_MAX = 32;
const ISSUER_MAX = 60;

function userIdOf(v) {
  const n = toInt(v, 1, Number.MAX_SAFE_INTEGER);
  return Number.isFinite(n) ? n : null;
}

function clockOf(rc) {
  return Number.isFinite(rc.nowMs) ? rc.nowMs : now(rc.env);
}

function aadFor(uid) {
  return `totp:${uid}`;
}

// ---------------------------------------------------------------- base32

export function base32Encode(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < b.length; i++) {
    acc = (acc << 8) | b[i];
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

// Strict: unpadded or padded RFC 4648, case-insensitive, whitespace allowed
// (the grouped form). Impossible lengths and non-zero trailing bits are
// refused — a value we did not write is not one we guess at. '' is null, not
// an empty secret.
export function base32Decode(s) {
  if (typeof s !== 'string' || s.length > 1024) return null;
  const clean = s.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (!clean || !/^[A-Z2-7]+$/.test(clean)) return null;
  const rem = clean.length % 8;
  if (rem === 1 || rem === 3 || rem === 6) return null;
  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of clean) {
    acc = (acc << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out[o++] = (acc >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) return null;
  return out;
}

export function groupSecret(b32) {
  if (typeof b32 !== 'string') return '';
  return b32.replace(/\s+/g, '').match(/.{1,4}/g)?.join(' ') ?? '';
}

// ---------------------------------------------------------------- RFC 6238

export function generateTotpSecret() {
  return randomBytes(TOTP_SECRET_BYTES);
}

function hmacKey(secretBytes) {
  return crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
}

async function hotp(key, counter) {
  const msg = new Uint8Array(8);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, Math.floor(counter / 2 ** 32));
  dv.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

function isCounter(v) {
  return Number.isSafeInteger(v) && v >= 0;
}

export async function totpCode(secretBytes, counter) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length === 0) throw new TypeError('totpCode: secret must be non-empty bytes');
  if (!isCounter(counter)) throw new RangeError('totpCode: bad counter');
  return hotp(await hmacKey(secretBytes), counter);
}

// Spaces forgiven ("123 456"); anything else must be exactly six digits.
function codeDigits(code) {
  if (typeof code !== 'string' || code.length > CODE_INPUT_MAX) return null;
  const s = code.replace(/\s+/g, '');
  return /^\d{6}$/.test(s) ? s : null;
}

// → the matched counter, or null. lastCounter has THREE readings, not two
// (A §14.3): null/undefined = no floor; a safe non-negative integer = the
// floor (refuse ≤ it); anything else — 'garbage', NaN, {}, Infinity, '5' — is
// a floor we cannot read, and the presence of one means a counter WAS spent,
// so every code is refused.
export async function verifyTotp(secretBytes, code, nowMs, lastCounter) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length < TOTP_MIN_SECRET_BYTES) return null;
  const digits = codeDigits(code);
  if (digits === null) return null;
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs) || nowMs < 0) return null;
  let floor = -1;
  if (lastCounter !== null && lastCounter !== undefined) {
    if (!isCounter(lastCounter)) return null;
    floor = lastCounter;
  }
  const t = Math.floor(nowMs / TOTP_STEP_MS);
  const key = await hmacKey(secretBytes);
  let hit = null;
  for (const c of [t - 1, t, t + 1]) {
    if (c < 0 || c <= floor) continue;
    if ((await timingSafeEqual(await hotp(key, c), digits)) && hit === null) hit = c;
  }
  return hit;
}

// Only the parameters every app assumes anyway (SHA1/6/30 are the defaults),
// so the URI — and the QR carrying it — stays as short as it can.
export function otpauthUri({ issuer, account, secretB32 }) {
  const iss = str(issuer, ISSUER_MAX) || 'Staff portal';
  const acct = str(account, 254) || 'account';
  const label = `${encodeURIComponent(iss)}:${encodeURIComponent(acct)}`;
  return `otpauth://totp/${label}?secret=${encodeURIComponent(String(secretB32))}&issuer=${encodeURIComponent(iss)}`;
}

function qrOrNull(uri) {
  try {
    return qrDataUri(uri);
  } catch (e) {
    if (e instanceof RangeError) return null;
    throw e;
  }
}

// ---------------------------------------------------------------- storage

// The confirmed row, decoded and checked. One reader for checkTotp and
// factors.userFactors, so "usable" cannot mean two things.
//   null                                     no confirmed authenticator
//   { problem: 'decrypt' }                   will not decrypt / not a ≥16-byte secret
//   { problem: 'floor', secret }             replay floor present but unreadable
//   { problem: null, secret, floor, row }    usable (floor: number | null)
export async function loadConfirmedTotp(env, userId) {
  const uid = userIdOf(userId);
  if (uid === null) return null;
  const row = await env.DB.prepare(
    'SELECT secret_enc, confirmed_at, last_counter FROM user_totp WHERE user_id = ? AND confirmed_at IS NOT NULL',
  )
    .bind(uid)
    .first();
  if (!row) return null;
  const plain = await decrypt(env, row.secret_enc, aadFor(uid));
  const secret = plain === null ? null : base32Decode(plain);
  if (!secret || secret.length < TOTP_MIN_SECRET_BYTES) return { problem: 'decrypt', row };
  const floor = row.last_counter;
  if (floor !== null && !isCounter(floor)) return { problem: 'floor', secret, row };
  return { problem: null, secret, floor, row };
}

export async function beginTotp(rc, userId) {
  const env = rc.env;
  const uid = userIdOf(userId);
  if (uid === null) throw notFound('No such account.');
  const user = await env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(uid).first();
  if (!user) throw notFound('No such account.');
  const existing = await env.DB.prepare('SELECT confirmed_at FROM user_totp WHERE user_id = ?').bind(uid).first();
  if (existing && existing.confirmed_at !== null) throw alreadySetUp();
  const b32 = base32Encode(generateTotpSecret());
  const enc = await encrypt(env, b32, aadFor(uid));
  // Replaces an unconfirmed row only; the WHERE makes a confirmation that
  // lands between our read and this write win, rather than be overwritten.
  const res = await env.DB.prepare(
    `INSERT INTO user_totp (user_id, secret_enc, confirmed_at, last_counter, created_at) VALUES (?, ?, NULL, NULL, ?)
     ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, confirmed_at = NULL, last_counter = NULL,
       created_at = excluded.created_at
     WHERE user_totp.confirmed_at IS NULL`,
  )
    .bind(uid, enc, iso(clockOf(rc)))
    .run();
  if (res.meta.changes !== 1) throw alreadySetUp();
  const issuer = str(env.ORG_NAME, ISSUER_MAX) || 'Staff portal';
  let otpauth = otpauthUri({ issuer, account: user.email, secretB32: b32 });
  let qr = qrOrNull(otpauth);
  if (!qr) {
    // A very long address will not fit a version-10 symbol: shorten the
    // label (cosmetic in the app) rather than lose the QR.
    otpauth = otpauthUri({ issuer, account: String(user.email).slice(0, 40), secretB32: b32 });
    qr = qrOrNull(otpauth);
  }
  return { secret_b32: b32, secret_grouped: groupSecret(b32), otpauth, qr };
}

function alreadySetUp() {
  return new HttpError(409, { error: 'An authenticator app is already set up. Remove it first to set up another.', code: 'totp_exists' });
}

function notPending() {
  return new HttpError(409, { error: 'Start setting up the authenticator app again.', code: 'totp_not_pending' });
}

export async function confirmTotp(rc, userId, code) {
  const env = rc.env;
  const uid = userIdOf(userId);
  if (uid === null) throw notFound('No such account.');
  const t = clockOf(rc);
  const row = await env.DB.prepare('SELECT secret_enc, last_counter FROM user_totp WHERE user_id = ? AND confirmed_at IS NULL')
    .bind(uid)
    .first();
  if (!row) throw notPending();
  const plain = await decrypt(env, row.secret_enc, aadFor(uid));
  const secret = plain === null ? null : base32Decode(plain);
  if (!secret) {
    await auditDecryptFailed(rc, uid, 'while confirming setup');
    throw notPending();
  }
  const counter = await verifyTotp(secret, code, t, row.last_counter);
  if (counter === null) {
    throw new HttpError(400, { error: 'That code didn’t work. Check the time on your phone and try the newest code.', code: 'totp_invalid' });
  }
  // Conditional on the very secret we verified against: a second "begin" in
  // another tab must not let this code confirm a secret it was not made from.
  const upd = await env.DB.prepare(
    'UPDATE user_totp SET confirmed_at = ?, last_counter = ? WHERE user_id = ? AND confirmed_at IS NULL AND secret_enc = ?',
  )
    .bind(iso(t), counter, uid, row.secret_enc)
    .run();
  if (upd.meta.changes !== 1) throw notPending();
  if ((await countUnusedBackupCodes(env, uid)) > 0) return { backup_codes: null };
  const codes = generateBackupCodes();
  await storeBackupCodes(env, uid, codes, t);
  return { backup_codes: codes };
}

function auditDecryptFailed(rc, uid, when) {
  return audit(rc, {
    action: 'mfa.decrypt_failed',
    outcome: 'failure',
    severity: 'critical',
    target: { type: 'user', id: uid },
    detail: `Refused an authenticator code ${when}: the stored secret will not decrypt to a usable key (was DATA_KEY rotated?). They need another method or an admin reset.`,
  });
}

// Sign-in and step-up. Confirmed rows only (an abandoned setup is nobody's
// factor). Success advances last_counter with a conditional UPDATE on the
// floor we read, so two simultaneous uses of one code cannot both win.
export async function checkTotp(rc, userId, code) {
  if (codeDigits(code) === null) return false;
  const uid = userIdOf(userId);
  if (uid === null) return false;
  const env = rc.env;
  const st = await loadConfirmedTotp(env, uid);
  if (!st) return false;
  if (st.problem === 'decrypt') {
    await auditDecryptFailed(rc, uid, 'at sign-in');
    return false;
  }
  if (st.problem === 'floor') {
    await audit(rc, {
      action: 'mfa.replay_floor_unreadable',
      outcome: 'failure',
      severity: 'critical',
      target: { type: 'user', id: uid },
      detail: 'Refused an authenticator code: the stored replay counter is unreadable, so every code is refused until the authenticator is reset.',
    });
    return false;
  }
  const counter = await verifyTotp(st.secret, code, clockOf(rc), st.floor);
  if (counter === null) return false;
  const upd = await env.DB.prepare(
    'UPDATE user_totp SET last_counter = ? WHERE user_id = ? AND confirmed_at IS NOT NULL AND last_counter IS ?',
  )
    .bind(counter, uid, st.floor)
    .run();
  return upd.meta.changes === 1;
}

export async function removeTotp(rc, userId) {
  const uid = userIdOf(userId);
  if (uid === null) throw notFound('No such account.');
  await rc.env.DB.prepare('DELETE FROM user_totp WHERE user_id = ?').bind(uid).run();
}
