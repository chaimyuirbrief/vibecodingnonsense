// Codes by text or email (CONTRACTS §7.6; A §1.3, §7.1; SPEC §7.6).
//
// The weakest factor, kept because it is the one that works for someone who
// has just lost their phone. Codes go only to code destinations an
// administrator added (adding one is handing out a factor), and only to a
// destination whose provider is configured. Six digits, ten minutes, stored
// as an HMAC, five attempts per code, single use; five sends per person per
// fifteen minutes, charged BEFORE anything is sent (A §6).

import { hmacHex, requireSecret, timingSafeEqual } from '../crypto.js';
import { GuardError, ValidationError, notFound, tooMany } from '../errors.js';
import { charge } from '../ratelimit.js';
import { now, iso, toInt, str, normEmail, randomInt, randomToken, parseIsoStrict, DAY, MINUTE } from '../util.js';
import { E164_RE, maskEmail, maskPhone, sendEmail, sendSms, usableKinds } from '../notify.js';
import { canDropFactor } from './factors.js';

export const OTP_TTL_MS = 10 * MINUTE;
export const OTP_MAX_ATTEMPTS = 5;
export const MAX_DESTINATIONS = 5;
const KINDS = ['sms', 'email'];
const LABEL_MAX = 60;
const CODE_INPUT_MAX = 32;
const MAX_ID = Number.MAX_SAFE_INTEGER;

function idOf(v) {
  const n = toInt(v, 1, MAX_ID);
  return Number.isFinite(n) ? n : null;
}

function clockOf(rc) {
  return Number.isFinite(rc.nowMs) ? rc.nowMs : now(rc.env);
}

function usableSet(env) {
  return new Set(usableKinds(env));
}

export function destinationHint(row) {
  if (row?.kind === 'sms') return maskPhone(row.address);
  if (row?.kind === 'email') return maskEmail(row.address);
  return '••••';
}

// Separators people type around a phone number; then it must be E.164. We do
// not guess a country for a number without '+'.
function normPhone(v) {
  if (typeof v !== 'string' || v.length > 40) return null;
  const s = v.trim().replace(/[\s().-]/g, '');
  return E164_RE.test(s) ? s : null;
}

// ---------------------------------------------------------------- destinations

// Masked for display; the address itself never leaves through this function.
export async function listDestinations(env, userId, { usableOnly = false } = {}) {
  const uid = idOf(userId);
  if (uid === null) return [];
  const usable = usableSet(env);
  const { results } = await env.DB.prepare(
    'SELECT id, kind, address, label, is_primary FROM code_destinations WHERE user_id = ? ORDER BY is_primary DESC, id',
  )
    .bind(uid)
    .all();
  const out = [];
  for (const r of results) {
    const ok = typeof r.kind === 'string' && usable.has(r.kind);
    if (usableOnly && !ok) continue;
    out.push({ id: r.id, kind: r.kind, hint: destinationHint(r), label: r.label ?? null, is_primary: r.is_primary === 1, usable: ok });
  }
  return out;
}

// The primary if it is usable, else the oldest usable one.
export async function primaryDestination(env, userId) {
  const uid = idOf(userId);
  if (uid === null) return null;
  const kinds = usableKinds(env);
  if (!kinds.length) return null;
  return (
    (await env.DB.prepare(
      `SELECT * FROM code_destinations WHERE user_id = ? AND kind IN (${kinds.map(() => '?').join(', ')})
       ORDER BY is_primary DESC, id LIMIT 1`,
    )
      .bind(uid, ...kinds)
      .first()) ?? null
  );
}

// The caller enforces destinations.manage and audits. One statement decides
// the cap, the duplicate check and primary-ness, so two concurrent adds
// cannot both become primary or both squeeze under the cap.
export async function addDestination(rc, userId, input) {
  const env = rc.env;
  const uid = idOf(userId);
  if (uid === null) throw notFound('No such account.');
  const i = input && typeof input === 'object' ? input : {};
  if (typeof i.kind !== 'string' || !KINDS.includes(i.kind)) throw new ValidationError('Choose text message or email.', 'kind');
  const address = i.kind === 'sms' ? normPhone(i.address) : normEmail(i.address);
  if (!address) {
    throw new ValidationError(
      i.kind === 'sms' ? 'Enter the number in international form, starting with + and the country code.' : 'Enter a valid email address.',
      'address',
    );
  }
  const label = str(i.label, LABEL_MAX) || null;
  if (!(await env.DB.prepare('SELECT 1 AS ok FROM users WHERE id = ?').bind(uid).first())) throw notFound('No such account.');
  const res = await env.DB.prepare(
    `INSERT INTO code_destinations (user_id, kind, address, label, is_primary, created_by, created_at)
     SELECT ?, ?, ?, ?, CASE WHEN EXISTS (SELECT 1 FROM code_destinations WHERE user_id = ? AND is_primary = 1) THEN 0 ELSE 1 END, ?, ?
     WHERE (SELECT COUNT(*) FROM code_destinations WHERE user_id = ?) < ?
       AND NOT EXISTS (SELECT 1 FROM code_destinations WHERE user_id = ? AND kind = ? AND address = ?)`,
  )
    .bind(uid, i.kind, address, label, uid, idOf(rc.user?.id), iso(clockOf(rc)), uid, MAX_DESTINATIONS, uid, i.kind, address)
    .run();
  if (res.meta.changes !== 1) {
    const dup = await env.DB.prepare('SELECT 1 AS ok FROM code_destinations WHERE user_id = ? AND kind = ? AND address = ?')
      .bind(uid, i.kind, address)
      .first();
    if (dup) throw new GuardError('duplicate', 'That destination is already on this account.', 409);
    throw new GuardError('too_many', `A person can have at most ${MAX_DESTINATIONS} code destinations.`, 409);
  }
  return env.DB.prepare('SELECT * FROM code_destinations WHERE id = ?').bind(res.meta.last_row_id).first();
}

// → { row } (the removed row as stored: the 'destination.remove' undo
// payload needs the address to re-add it). Never the last usable factor
// (canDropFactor — the one guard, A §14.8). Outstanding codes sent there die
// with it, and the oldest remaining destination is promoted if no primary is
// left — all in one batch.
export async function removeDestination(rc, userId, destinationId) {
  const env = rc.env;
  const db = env.DB;
  const uid = idOf(userId);
  const did = idOf(destinationId);
  if (uid === null || did === null) throw notFound('No such destination.');
  const row = await db.prepare('SELECT * FROM code_destinations WHERE id = ? AND user_id = ?').bind(did, uid).first();
  if (!row) throw notFound('No such destination.');
  if (!(await canDropFactor(env, uid, { destinationId: did }))) {
    throw new GuardError('last_factor', 'That is the last way this person can prove it’s them. Add another method first.', 409);
  }
  await db.batch([
    db.prepare('DELETE FROM code_destinations WHERE id = ? AND user_id = ?').bind(did, uid),
    db.prepare('DELETE FROM otp_challenges WHERE destination_id = ? AND user_id = ?').bind(did, uid),
    db
      .prepare(
        `UPDATE code_destinations SET is_primary = 1
          WHERE id = (SELECT id FROM code_destinations WHERE user_id = ? ORDER BY id LIMIT 1)
            AND NOT EXISTS (SELECT 1 FROM code_destinations WHERE user_id = ? AND is_primary = 1)`,
      )
      .bind(uid, uid),
  ]);
  return { row };
}

// ---------------------------------------------------------------- codes

function codeHash(env, id, code) {
  return hmacHex(requireSecret(env, 'SESSION_SECRET'), `otp.${id}.${code}`);
}

function codeDigits(code) {
  if (typeof code !== 'string' || code.length > CODE_INPUT_MAX) return null;
  const s = code.replace(/\s+/g, '');
  return /^\d{6}$/.test(s) ? s : null;
}

// → { sent, kind, hint, challengeId }. Throws 429 when over otp_send, 404 for
// a destination that is not theirs, 409 when its provider is not configured.
// A provider failure is { sent: false }, not an exception, and its challenge
// is withdrawn — nobody holds that code.
export async function sendCode(rc, userId, destinationId) {
  const env = rc.env;
  const db = env.DB;
  const uid = idOf(userId);
  if (uid === null) throw notFound('No such account.');
  const t = clockOf(rc);
  // Charged first — texts cost money, and a refused or junk request still
  // counts (A §6).
  const rl = await charge(env, 'otp_send', String(uid), t);
  if (!rl.allowed) throw tooMany(rl.retryAfterSec);
  const did = idOf(destinationId);
  const dest = did === null ? null : await db.prepare('SELECT * FROM code_destinations WHERE id = ? AND user_id = ?').bind(did, uid).first();
  if (!dest) throw notFound('No such destination.');
  if (!usableSet(env).has(dest.kind)) {
    throw new GuardError('destination_unusable', 'Codes can’t be sent there right now. Choose another way to sign in.', 409);
  }
  const id = randomToken(16);
  const code = String(randomInt(1_000_000)).padStart(6, '0');
  await db.batch([
    db.prepare('DELETE FROM otp_challenges WHERE expires_at < ?').bind(iso(t - DAY)),
    db
      .prepare(
        `INSERT INTO otp_challenges (id, user_id, destination_id, code_hash, attempts, expires_at, used_at, created_at)
         VALUES (?, ?, ?, ?, 0, ?, NULL, ?)`,
      )
      .bind(id, uid, dest.id, await codeHash(env, id, code), iso(t + OTP_TTL_MS), iso(t)),
  ]);
  const org = str(env.ORG_NAME, 60) || 'Staff portal';
  const result =
    dest.kind === 'sms'
      ? await sendSms(env, dest.address, `${org} sign-in code: ${code}. It expires in 10 minutes. Never share it.`)
      : await sendEmail(
          env,
          dest.address,
          `${org} sign-in code`,
          `Your sign-in code is ${code}.\n\nIt expires in 10 minutes. If you did not just try to sign in, tell your administrator.`,
        );
  if (!result.sent) await db.prepare('DELETE FROM otp_challenges WHERE id = ?').bind(id).run();
  return { sent: result.sent === true, kind: dest.kind, hint: destinationHint(dest), challengeId: result.sent ? id : null };
}

// The latest unused, unexpired challenge for this user AT THIS destination —
// which must still exist and be usable: removing a destination (or switching
// off its provider) stops a code already sent there being a way in (A §7.2).
// The attempt is spent before the comparison, conditionally, so parallel
// guesses cannot exceed five between them.
export async function verifyCode(rc, userId, destinationId, code) {
  const digits = codeDigits(code);
  if (digits === null) return false;
  const uid = idOf(userId);
  const did = idOf(destinationId);
  if (uid === null || did === null) return false;
  const env = rc.env;
  const db = env.DB;
  const t = clockOf(rc);
  const dest = await db.prepare('SELECT kind FROM code_destinations WHERE id = ? AND user_id = ?').bind(did, uid).first();
  if (!dest || !usableSet(env).has(dest.kind)) return false;
  const ch = await db.prepare(
    `SELECT id, code_hash, expires_at FROM otp_challenges
      WHERE user_id = ? AND destination_id = ? AND used_at IS NULL AND expires_at > ?
      ORDER BY created_at DESC, rowid DESC LIMIT 1`,
  )
    .bind(uid, did, iso(t))
    .first();
  if (!ch) return false;
  // The SQL comparison is between strings; 'garbage' sorts after every ISO
  // date, so re-check with a strict parse (A §14.2).
  const exp = parseIsoStrict(ch.expires_at);
  if (!Number.isFinite(exp) || exp <= t) return false;
  const spent = await db.prepare(`UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ? AND used_at IS NULL AND attempts < ?`)
    .bind(ch.id, OTP_MAX_ATTEMPTS)
    .run();
  if (spent.meta.changes !== 1) return false;
  if (typeof ch.code_hash !== 'string' || !(await timingSafeEqual(await codeHash(env, ch.id, digits), ch.code_hash))) return false;
  const used = await db.prepare('UPDATE otp_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(iso(t), ch.id).run();
  return used.meta.changes === 1;
}
