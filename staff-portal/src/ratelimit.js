// Attempt counting (CONTRACTS §7.1). One row per attempt in auth_attempts;
// the count is the rows inside the window. Charged BEFORE the check it
// protects (A §6): an attempt that is let through is recorded before the
// caller checks anything, so a correct password costs the same as a wrong one.
// An attempt refused because the bucket is ALREADY full is not recorded:
// otherwise one stranger hammering a refused route grows auth_attempts
// without bound (SPEC §16.34).
//
// The per-IP login bucket is never cleared, on success or otherwise (B trap
// 4): it is the only brake on spraying one guess across many accounts.
//
// Every per-address kind (the ones named *_ip) is keyed on the caller's
// network, not the full address: an IPv6 /64 is one bucket (ip.rateLimitNetwork).

import { iso, now, toInt, parseIsoStrict, DAY } from './util.js';
import { rateLimitNetwork } from './ip.js';

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
// else shares one bucket — over-counting is the safe direction. An address
// for a per-address kind becomes its network; one that does not parse joins
// the shared '?' bucket.
function subjectKey(kind, subject) {
  if (kind.endsWith('_ip')) return rateLimitNetwork(subject) ?? '?';
  if (typeof subject === 'string') return subject.slice(0, SUBJECT_MAX);
  if (typeof subject === 'number' && Number.isFinite(subject)) return String(subject);
  return '?';
}

function clockOf(env, nowMs) {
  return typeof nowMs === 'number' && Number.isFinite(nowMs) ? nowMs : now(env);
}

function verdict(row, max, windowMs, t, pending) {
  const n = toInt(row?.n, 0);
  // An unreadable count is treated as over the limit.
  const count = Number.isFinite(n) ? n + pending : max + 1;
  const oldest = parseIsoStrict(row?.oldest);
  const ageOut = Number.isFinite(oldest) ? oldest + windowMs - t : windowMs;
  return { allowed: Number.isFinite(n) && count <= max, count, retryAfterSec: Math.max(1, Math.ceil(ageOut / 1000)) };
}

// → { allowed, count, retryAfterSec }. A database failure throws: the request
// fails closed and the worker audits the real error.
//
// Peek, then charge: a bucket that is already full refuses without writing.
// Otherwise the attempt is inserted, rows older than a day are pruned and the
// window is counted in ONE batch, and that count decides — so concurrent
// attempts that all peeked under the limit are still refused past it.
export async function charge(env, kind, subject, nowMs, opts = {}) {
  const lim = limitFor(kind);
  const sub = subjectKey(kind, subject);
  const t = clockOf(env, nowMs);
  // An unreadable override falls back to the default, which is never looser.
  const override = toInt(opts?.max, 1, 100000);
  const max = Number.isFinite(override) ? override : lim.max;
  const windowMs = lim.windowSec * 1000;
  const db = env.DB;
  const window = () =>
    db
      .prepare('SELECT COUNT(*) AS n, MIN(at) AS oldest FROM auth_attempts WHERE kind = ? AND subject = ? AND at > ?')
      .bind(kind, sub, iso(t - windowMs));
  const before = verdict(await window().first(), max, windowMs, t, 1);
  if (!before.allowed) return before;
  const [, , counted] = await db.batch([
    db.prepare('INSERT INTO auth_attempts (kind, subject, at) VALUES (?, ?, ?)').bind(kind, sub, iso(t)),
    db.prepare('DELETE FROM auth_attempts WHERE at < ?').bind(iso(t - DAY)),
    window(),
  ]);
  return verdict(counted?.results?.[0], max, windowMs, t, 0);
}

export async function peek(env, kind, subject, nowMs) {
  const lim = limitFor(kind);
  const t = clockOf(env, nowMs);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_attempts WHERE kind = ? AND subject = ? AND at > ?')
    .bind(kind, subjectKey(kind, subject), iso(t - lim.windowSec * 1000))
    .first('n');
  const c = toInt(n, 0);
  return Number.isFinite(c) ? c : Number.MAX_SAFE_INTEGER;
}

// Refuses login_ip by construction (B trap 4) rather than trusting every
// caller to remember.
export async function clear(env, kind, subject) {
  limitFor(kind);
  if (kind === 'login_ip') throw new Error('ratelimit: the per-IP login bucket is never cleared');
  await env.DB.prepare('DELETE FROM auth_attempts WHERE kind = ? AND subject = ?').bind(kind, subjectKey(kind, subject)).run();
}
