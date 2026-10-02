// Attempt counting (CONTRACTS §7.1). One row per attempt in auth_attempts;
// the count is the rows inside the window. Charged BEFORE the check it
// protects (A §6), so a guess that is about to be refused still costs.
//
// The per-IP login bucket is never cleared, on success or otherwise (B trap
// 4): it is the only brake on spraying one guess across many accounts.

import { iso, now, toInt, parseIsoStrict, DAY } from './util.js';

export const LIMITS = Object.freeze({
  login_ip: Object.freeze({ max: 20, windowSec: 600 }),
  login_id: Object.freeze({ max: 10, windowSec: 900 }),
  mfa_user: Object.freeze({ max: 5, windowSec: 900 }),
  otp_send: Object.freeze({ max: 5, windowSec: 900 }),
  setup_ip: Object.freeze({ max: 5, windowSec: 3600 }),
  curpw_user: Object.freeze({ max: 10, windowSec: 900 }),
  request_ip: Object.freeze({ max: 5, windowSec: 3600 }),
  fp_ip: Object.freeze({ max: 30, windowSec: 600 }),
  invite_ip: Object.freeze({ max: 20, windowSec: 3600 }),
  device_code_user: Object.freeze({ max: 10, windowSec: 3600 }),
});

const SUBJECT_MAX = 200;

function limitFor(kind) {
  if (typeof kind !== 'string' || !Object.hasOwn(LIMITS, kind)) throw new Error(`ratelimit: unknown kind '${String(kind)}'`);
  return LIMITS[kind];
}

// Callers pass an address, a normalised identifier or a user id. Anything
// else shares one bucket — over-counting is the safe direction.
function subjectKey(subject) {
  if (typeof subject === 'string') return subject.slice(0, SUBJECT_MAX);
  if (typeof subject === 'number' && Number.isFinite(subject)) return String(subject);
  return '?';
}

function clockOf(env, nowMs) {
  return typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : now(env);
}

// → { allowed, count, retryAfterSec }. A database failure throws: the request
// fails closed and the worker audits the real error.
export async function charge(env, kind, subject, nowMs, opts = {}) {
  const lim = limitFor(kind);
  const sub = subjectKey(subject);
  const t = clockOf(env, nowMs);
  // An unreadable override falls back to the default, which is never looser.
  const override = toInt(opts?.max, 1, 100000);
  const max = Number.isFinite(override) ? override : lim.max;
  const windowMs = lim.windowSec * 1000;
  const db = env.DB;
  const [, , counted] = await db.batch([
    db.prepare('INSERT INTO auth_attempts (kind, subject, at) VALUES (?, ?, ?)').bind(kind, sub, iso(t)),
    db.prepare('DELETE FROM auth_attempts WHERE at < ?').bind(iso(t - DAY)),
    db
      .prepare('SELECT COUNT(*) AS n, MIN(at) AS oldest FROM auth_attempts WHERE kind = ? AND subject = ? AND at > ?')
      .bind(kind, sub, iso(t - windowMs)),
  ]);
  const row = counted?.results?.[0] || {};
  const count = toInt(row.n, 0);
  const oldest = parseIsoStrict(row.oldest);
  const ageOut = Number.isFinite(oldest) ? oldest + windowMs - t : windowMs;
  return {
    // An unreadable count is treated as over the limit.
    allowed: Number.isFinite(count) && count <= max,
    count: Number.isFinite(count) ? count : max + 1,
    retryAfterSec: Math.max(1, Math.ceil(ageOut / 1000)),
  };
}

export async function peek(env, kind, subject, nowMs) {
  const lim = limitFor(kind);
  const t = clockOf(env, nowMs);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_attempts WHERE kind = ? AND subject = ? AND at > ?')
    .bind(kind, subjectKey(subject), iso(t - lim.windowSec * 1000))
    .first('n');
  const c = toInt(n, 0);
  return Number.isFinite(c) ? c : Number.MAX_SAFE_INTEGER;
}

// Refuses login_ip by construction (B trap 4) rather than trusting every
// caller to remember.
export async function clear(env, kind, subject) {
  limitFor(kind);
  if (kind === 'login_ip') throw new Error('ratelimit: the per-IP login bucket is never cleared');
  await env.DB.prepare('DELETE FROM auth_attempts WHERE kind = ? AND subject = ?').bind(kind, subjectKey(subject)).run();
}
