// The allowlist and the blocklist (CONTRACTS §7.8, A §4, SPEC §8.7).
//
// Addresses are compared as bytes by ip.js, never as strings. "Live" always
// means not expired: an expired entry is kept so an administrator can see
// what lapsed, and grants nothing (A §4 — counting one as cover waves through
// the exact delete the guard exists to stop). Expiry is re-checked with
// parseIsoStrict after the SQL prefilter, so an unreadable expiry never makes
// an allow entry live and never lets a block lapse.
//
// No anti-lockout logic lives here: guards.js (called by the API and the
// reverters) uses coveringEntries and liveCount.

import { iso, now, toInt, strStrict, parseIsoStrict, HOUR, isoShapeSql } from './util.js';
import { parseIp, normalizeCidr, isPrivateOrReserved, isWholeFamily, cidrContains, bestMatch } from './ip.js';
import { ValidationError, notFound } from './errors.js';

export const TIERS = Object.freeze([1, 2, 3, 4]);
export const TIER4_DEFAULT_MS = 24 * HOUR;
const MAX_HOURS = 8760;
const TEXT_MAX = 100;
const ROW_LIMIT = 10000;

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function clockOf(env, nowMs) {
  return finite(nowMs) ? nowMs : now(env);
}

function nowOf(rc) {
  return clockOf(rc?.env, rc?.nowMs);
}

// An allow entry is live only with no expiry or a READABLE one in the future.
export function allowLive(row, nowMs) {
  if (!row || row.expires_at === null || row.expires_at === undefined) return !!row;
  const exp = parseIsoStrict(row.expires_at);
  return Number.isFinite(exp) && exp > nowMs;
}

// A block stays in force unless its expiry is readable and past.
export function blockLive(row, nowMs) {
  if (!row || row.expires_at === null || row.expires_at === undefined) return !!row;
  const exp = parseIsoStrict(row.expires_at);
  return !(Number.isFinite(exp) && exp <= nowMs);
}

// A stored tier that is not 1–4 reads as 4: allowlisted, but no grace window
// (the restrictive reading of the one unreadable field).
export function entryTier(row) {
  const t = toInt(row?.tier, 1, 4);
  return Number.isFinite(t) ? t : 4;
}

async function liveAllowRows(env, nowMs) {
  const { results } = await env.DB.prepare('SELECT * FROM allowed_ips WHERE expires_at IS NULL OR expires_at > ? ORDER BY id LIMIT ?')
    .bind(iso(nowMs), ROW_LIMIT)
    .all();
  return (results || []).filter((r) => allowLive(r, nowMs));
}

// Rows written here always hold iso() strings; anything not shaped like one
// is fetched too and judged by blockLive (unreadable → still blocking).
async function liveBlockRows(env, nowMs) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM blocked_ips WHERE expires_at IS NULL OR expires_at > ? OR NOT ${isoShapeSql('expires_at')}
     ORDER BY id LIMIT ?`,
  )
    .bind(iso(nowMs), ROW_LIMIT)
    .all();
  return (results || []).filter((r) => blockLive(r, nowMs));
}

// ---------------------------------------------------------------- reading

// → { tier, entry } | null. Most specific wins; on an exact tie the stricter
// tier (ip.bestMatch, A §4).
export async function tierForIp(env, ip, nowMs) {
  if (!parseIp(ip)) return null;
  const t = clockOf(env, nowMs);
  const entry = bestMatch(await liveAllowRows(env, t), ip);
  return entry ? { tier: entryTier(entry), entry } : null;
}

// An address that does not parse counts as blocked (fail closed); the gate
// refuses it anyway as "no usable address".
export async function isIpBlocked(env, ip, nowMs) {
  if (!parseIp(ip)) return true;
  const rows = await liveBlockRows(env, clockOf(env, nowMs));
  return rows.some((r) => cidrContains(r.cidr, ip));
}

// Live allow entries covering `ip`, optionally pretending one is gone.
export async function coveringEntries(env, ip, nowMs, opts = {}) {
  if (!parseIp(ip)) return [];
  const ex = toInt(opts?.excludeId, 1);
  const rows = await liveAllowRows(env, clockOf(env, nowMs));
  return rows.filter((r) => r.id !== ex && cidrContains(r.cidr, ip));
}

export async function liveCount(env, nowMs, opts = {}) {
  const ex = toInt(opts?.excludeId, 1);
  const rows = await liveAllowRows(env, clockOf(env, nowMs));
  return rows.filter((r) => r.id !== ex).length;
}

function annotate(rows, live, nowMs, ip) {
  const addr = parseIp(ip);
  return rows.map((r) => {
    const out = { ...r, active: live(r, nowMs) };
    if (addr) out.covers_ip = cidrContains(r.cidr, addr);
    return out;
  });
}

// Every row, expired ones included (the newest 10,000 — the tables are never
// trimmed), oldest first, each with `active` and — when the caller's address
// is passed — `covers_ip`.
export async function listAllowed(env, nowMs, ip) {
  const { results } = await env.DB.prepare('SELECT * FROM (SELECT * FROM allowed_ips ORDER BY id DESC LIMIT ?) ORDER BY id').bind(ROW_LIMIT).all();
  return annotate(results || [], allowLive, clockOf(env, nowMs), ip);
}

export async function listBlocked(env, nowMs, ip) {
  const { results } = await env.DB.prepare('SELECT * FROM (SELECT * FROM blocked_ips ORDER BY id DESC LIMIT ?) ORDER BY id').bind(ROW_LIMIT).all();
  return annotate(results || [], blockLive, clockOf(env, nowMs), ip);
}

// ---------------------------------------------------------------- validation

function given(v) {
  return v !== undefined && v !== null;
}

// '81.2.69.7/24' is refused by ip.parseCidr (host bits set); say which range
// was probably meant rather than just "invalid".
function hostBitsHint(s) {
  const slash = s.indexOf('/');
  if (slash === -1 || s.includes(':')) return null;
  const a = parseIp(s.slice(0, slash));
  const p = toInt(s.slice(slash + 1), 0, 32);
  if (!a || a.v !== 4 || !Number.isFinite(p)) return null;
  const bytes = a.bytes.map((b, i) => b & (0xff << (8 - Math.max(0, Math.min(8, p - i * 8)))) & 0xff);
  return normalizeCidr(`${Array.from(bytes).join('.')}/${p}`);
}

export function validateCidr(input, { what = 'allowlist' } = {}) {
  const s = strStrict(input, 1, 64);
  if (s === null) throw new ValidationError('Enter an address such as 81.2.69.142 or a range such as 81.2.69.0/24.', 'cidr');
  const c = normalizeCidr(s);
  if (!c) {
    const hint = hostBitsHint(s);
    throw new ValidationError(
      hint ? `${s} has address bits set below its prefix; the range it sits in is ${hint}.` : `${s} is not an IPv4 or IPv6 address or range.`,
      'cidr',
    );
  }
  // A §4: the whole address family is the gate turned off, not an entry.
  if (isWholeFamily(c)) {
    throw new ValidationError(
      what === 'allowlist'
        ? `${c} is the entire internet. That is not an allowlist entry; use “Open to the internet” for a bounded time instead.`
        : `${c} is the entire internet. To refuse everyone, use lockdown mode instead.`,
      'cidr',
    );
  }
  // A §4: callers always arrive on a public address.
  if (isPrivateOrReserved(c)) {
    throw new ValidationError(
      `${c} is a private or reserved range (a home or office LAN, loopback, documentation or similar). Visitors always arrive from a public address, so it could never match anyone — use your public address instead.`,
      'cidr',
    );
  }
  return c;
}

export function validateTier(v) {
  const t = typeof v === 'number' || typeof v === 'string' ? toInt(v, 1, 4) : NaN;
  if (!Number.isFinite(t)) {
    throw new ValidationError('Tier must be 1 (core admin), 2 (trusted), 3 (shared) or 4 (temporary).', 'tier');
  }
  return t;
}

// Optional text: absent, null or blank → null; anything else must be a string.
function optText(v, field, max = TEXT_MAX) {
  if (!given(v) || (typeof v === 'string' && v.trim() === '')) return null;
  const s = strStrict(v, 1, max);
  if (s === null) throw new ValidationError(`${field === 'owner' ? 'Owner' : field === 'reason' ? 'Reason' : 'Label'} must be text of at most ${max} characters.`, field);
  return s;
}

// → ms | null. `expires_at` must be a strict ISO instant in the future;
// `expires_in_hours` an integer 1–8760. A blank never means "no expiry"
// (A §14.1, §14.11); null does.
export function validateExpiry(input, nowMs) {
  const hasAt = given(input.expires_at);
  const hasHours = given(input.expires_in_hours);
  if (hasAt && hasHours) throw new ValidationError('Give an expiry time or a number of hours, not both.', 'expires_at');
  if (hasHours) {
    const v = input.expires_in_hours;
    const h = typeof v === 'number' || typeof v === 'string' ? toInt(v, 1, MAX_HOURS) : NaN;
    if (!Number.isFinite(h)) throw new ValidationError(`Hours until expiry must be a whole number from 1 to ${MAX_HOURS}.`, 'expires_in_hours');
    return nowMs + h * HOUR;
  }
  if (hasAt) {
    const ms = parseIsoStrict(input.expires_at);
    if (!Number.isFinite(ms)) throw new ValidationError('Expiry must be a date and time such as 2026-02-01T09:00:00Z.', 'expires_at');
    if (ms <= nowMs) throw new ValidationError('Expiry must be in the future. To end an entry now, remove it.', 'expires_at');
    return ms;
  }
  return null;
}

async function validUserId(env, v) {
  if (!given(v)) return null;
  const id = toInt(v, 1);
  const row = Number.isFinite(id) ? await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first() : null;
  if (!row) throw new ValidationError('No such person.', 'user_id');
  return id;
}

function plain(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ValidationError('Expected an object.');
  return input;
}

function actorId(rc) {
  const n = toInt(rc?.user?.id, 1);
  return Number.isFinite(n) ? n : null;
}

// ---------------------------------------------------------------- allowlist

// → the inserted row. Refuses private/reserved and whole-family ranges; a
// tier-4 entry with no expiry gets 24 hours (A §8 — a temporary entry that
// never ends is what the tier exists to prevent); a duplicate of a live
// entry is refused rather than silently creating a tie.
export async function addAllowed(rc, input) {
  const env = rc.env;
  const t = nowOf(rc);
  const i = plain(input);
  const cidr = validateCidr(i.cidr);
  const tier = validateTier(i.tier);
  const label = optText(i.label, 'label');
  const owner = optText(i.owner, 'owner');
  const userId = await validUserId(env, i.user_id);
  let exp = validateExpiry(i, t);
  if (tier === 4 && exp === null) exp = t + TIER4_DEFAULT_MS;
  const dup = (await liveAllowRows(env, t)).find((r) => r.cidr === cidr);
  if (dup) throw new ValidationError(`${cidr} is already on the allowlist (entry ${dup.id}). Edit that entry instead.`, 'cidr');
  return env.DB.prepare(
    `INSERT INTO allowed_ips (cidr, tier, label, owner, user_id, expires_at, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`,
  )
    .bind(cidr, tier, label, owner, userId, exp === null ? null : iso(exp), actorId(rc), iso(t), iso(t))
    .first();
}

async function loadAllowed(env, id) {
  const n = toInt(id, 1);
  const row = Number.isFinite(n) ? await env.DB.prepare('SELECT * FROM allowed_ips WHERE id = ?').bind(n).first() : null;
  if (!row) throw notFound('No such allowlist entry.');
  return row;
}

const EDITABLE = ['tier', 'label', 'owner', 'user_id', 'expires_at', 'expires_in_hours'];

// → { prior, row }. The range itself is not editable (add the new one, then
// remove the old one, so the guards see both steps). `expires_at: null`
// removes an expiry — except on tier 4, which gets 24 hours from now.
export async function editAllowed(rc, id, patch) {
  const env = rc.env;
  const t = nowOf(rc);
  const p = plain(patch);
  if (p.cidr !== undefined) throw new ValidationError('The range of an entry cannot be changed. Add the new range, then remove this one.', 'cidr');
  if (!EDITABLE.some((k) => p[k] !== undefined)) throw new ValidationError('Nothing to change.');
  const prior = await loadAllowed(env, id);
  const next = {
    tier: p.tier !== undefined ? validateTier(p.tier) : entryTier(prior),
    label: p.label !== undefined ? optText(p.label, 'label') : prior.label,
    owner: p.owner !== undefined ? optText(p.owner, 'owner') : prior.owner,
    user_id: p.user_id !== undefined ? await validUserId(env, p.user_id) : prior.user_id,
    expires_at: prior.expires_at,
  };
  if (p.expires_at !== undefined || p.expires_in_hours !== undefined) {
    const exp = validateExpiry(p, t);
    next.expires_at = exp === null ? null : iso(exp);
  }
  // An already-expired entry stays expired: only a new expiry revives it.
  if (next.tier === 4 && next.expires_at === null) next.expires_at = iso(t + TIER4_DEFAULT_MS);
  const row = await env.DB.prepare(
    'UPDATE allowed_ips SET tier = ?, label = ?, owner = ?, user_id = ?, expires_at = ?, updated_at = ? WHERE id = ? RETURNING *',
  )
    .bind(next.tier, next.label, next.owner, next.user_id, next.expires_at, iso(t), prior.id)
    .first();
  return { prior, row };
}

// → { row }. The anti-lockout checks are guards.js's, run before this.
export async function removeAllowed(rc, id) {
  const row = await loadAllowed(rc.env, id);
  await rc.env.DB.prepare('DELETE FROM allowed_ips WHERE id = ?').bind(row.id).run();
  return { row };
}

// ---------------------------------------------------------------- blocklist

// → the inserted row. The self-block guard is guards.js's.
export async function addBlocked(rc, input) {
  const env = rc.env;
  const t = nowOf(rc);
  const i = plain(input);
  const cidr = validateCidr(i.cidr, { what: 'blocklist' });
  const reason = optText(i.reason, 'reason', 200);
  const exp = validateExpiry(i, t);
  return env.DB.prepare('INSERT INTO blocked_ips (cidr, reason, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?) RETURNING *')
    .bind(cidr, reason, exp === null ? null : iso(exp), actorId(rc), iso(t))
    .first();
}

export async function removeBlocked(rc, id) {
  const n = toInt(id, 1);
  const row = Number.isFinite(n) ? await rc.env.DB.prepare('SELECT * FROM blocked_ips WHERE id = ?').bind(n).first() : null;
  if (!row) throw notFound('No such blocklist entry.');
  await rc.env.DB.prepare('DELETE FROM blocked_ips WHERE id = ?').bind(row.id).run();
  return { row };
}
