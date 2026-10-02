// Sessions (CONTRACTS §7.7, SPEC §6.9, D16). The cookie carries a 256-bit
// random token; the database stores only its SHA-256, so a leaked backup, an
// export or a read-only query exposes no usable session. Lists show id_ref —
// the first 12 hex of the stored hash — enough to act on, useless to replay.

import { cookie, clearCookie, iso, now, toInt, str, parseIsoStrict, randomToken, MINUTE, HOUR, DAY } from './util.js';
import { sha256Hex } from './crypto.js';
import { effectivePermissions, requireStepUp } from './rbac.js';
import { getUser, mfaEnrolmentPending } from './users.js';
import { auditError } from './audit.js';

export const SESSION_COOKIE = '__Host-sid';
export const PINS = Object.freeze(['password_change', 'mfa_enroll']);

// randomToken(32) is exactly 43 base64url characters. Anything else is
// refused before it is hashed or reaches a query.
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const ID_RE = /^[0-9a-f]{64}$/;
const REF_RE = /^[0-9a-f]{12}$/;
const TOUCH_MS = MINUTE;
const RETAIN_MS = 7 * DAY;

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

// rc.policy comes from resolvePolicy, which already maps unrecognised values
// to the restrictive ones. A missing policy means the §5 defaults; a present
// value that still does not read gets the §5 "unrecognised" value.
function policyInt(policy, key, min, max, def, unrecognised) {
  if (!policy || typeof policy !== 'object' || policy[key] === undefined) return def;
  const n = toInt(policy[key], min, max);
  return Number.isFinite(n) ? n : unrecognised;
}

function idleMs(policy) {
  return policyInt(policy, 'session_idle_minutes', 5, 1440, 120, 30) * MINUTE;
}

function absoluteMs(policy) {
  return policyInt(policy, 'session_absolute_hours', 1, 72, 8, 8) * HOUR;
}

function checkPin(pin) {
  if (pin !== null && !PINS.includes(pin)) throw new Error(`sessions: unknown pin '${String(pin)}'`);
  return pin;
}

// Prunes in the same batch (CONTRACTS §11): sessions absolute-expired or
// revoked more than 7 days ago. Rows are written by this module only, so the
// ISO strings compare correctly as text.
export async function createSession(rc, user, opts = {}) {
  const env = rc.env;
  const t = nowOf(rc);
  const userId = toInt(user?.id, 1);
  if (!Number.isFinite(userId)) throw new Error('sessions: createSession needs a user');
  const o = opts && typeof opts === 'object' ? opts : {};
  const aal = toInt(o.aal, 1, 2) === 2 ? 2 : 1;
  const mfaAtMs = finite(o.mfaAt) ? o.mfaAt : parseIsoStrict(o.mfaAt);
  const mfaAt = Number.isFinite(mfaAtMs) ? iso(mfaAtMs) : aal === 2 ? iso(t) : null;
  const pinned = checkPin(o.pinned === undefined ? null : o.pinned);
  const deviceId = typeof o.deviceId === 'string' && o.deviceId ? o.deviceId.slice(0, 128) : null;
  const absolute = t + absoluteMs(rc.policy);
  const idle = Math.min(absolute, t + idleMs(rc.policy));
  const token = randomToken(32);
  const id = await sha256Hex(token);
  const db = env.DB;
  await db.batch([
    db
      .prepare(
        `INSERT INTO sessions (id, user_id, device_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at,
           ip, ua, aal, mfa_at, mfa_method, pinned) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        id,
        userId,
        deviceId,
        iso(t),
        iso(t),
        iso(idle),
        iso(absolute),
        typeof rc.ip === 'string' ? rc.ip.slice(0, 64) : null,
        str(rc.ua, 512) || null,
        aal,
        mfaAt,
        str(o.mfaMethod, 32) || null,
        pinned,
      ),
    db
      .prepare('DELETE FROM sessions WHERE absolute_expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)')
      .bind(iso(t - RETAIN_MS), iso(t - RETAIN_MS)),
  ]);
  return { id, cookie: cookie(SESSION_COOKIE, token, { maxAge: (absolute - t) / 1000 }) };
}

// Refuses (CONTRACTS §7.7): a malformed cookie (before hashing or any query),
// an unknown or revoked session, idle or absolute expiry — by the stored
// times AND by the current policy, so shortening a setting takes effect —
// unreadable times, an account that is not 'active', and in lockdown anyone
// who is not a Super Admin. Extends the idle expiry at most once a minute.
export async function loadSession(rc) {
  rc.session = null;
  rc.user = null;
  rc.authz = null;
  const raw = rc.cookies ? rc.cookies[SESSION_COOKIE] : undefined;
  if (typeof raw !== 'string' || !TOKEN_RE.test(raw)) return null;
  const env = rc.env;
  const t = nowOf(rc);
  const policy = rc.policy;
  const db = env.DB;
  const s = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(await sha256Hex(raw)).first();
  if (!s || (s.revoked_at !== null && s.revoked_at !== undefined)) return null;
  const created = parseIsoStrict(s.created_at);
  const lastSeen = parseIsoStrict(s.last_seen_at);
  const idleAt = parseIsoStrict(s.idle_expires_at);
  const absAt = parseIsoStrict(s.absolute_expires_at);
  if (![created, lastSeen, idleAt, absAt].every(Number.isFinite)) return null;
  const absolute = Math.min(absAt, created + absoluteMs(policy));
  if (t >= absolute || t >= Math.min(idleAt, lastSeen + idleMs(policy))) return null;

  const user = await getUser(env, s.user_id);
  if (!user || user.status !== 'active') return null;
  const authz = await effectivePermissions(env, user, t);
  if (policy?.access_mode === 'lockdown' && authz.isSuper !== true) return null;

  if (Math.abs(t - lastSeen) >= TOUCH_MS) {
    const nextIdle = Math.min(absolute, t + idleMs(policy));
    try {
      await db.batch([
        db.prepare('UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ? AND revoked_at IS NULL').bind(iso(t), iso(nextIdle), s.id),
        db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').bind(iso(t), user.id),
      ]);
      s.last_seen_at = iso(t);
      s.idle_expires_at = iso(nextIdle);
    } catch (e) {
      // Failing to EXTEND a valid session is not a reason to refuse it — but
      // the real error is recorded, not swallowed (B trap 2).
      await auditError(rc, 'error', e, { detail: 'Could not extend a session’s idle expiry.' });
    }
  }
  rc.session = s;
  rc.user = user;
  rc.authz = authz;
  return { session: s, user, authz };
}

// What the person must do before anything else: change a temporary password,
// then — when policy requires a factor and they have none usable — enrol one.
// Pin, never refuse (B trap 3).
export async function nextPin(env, user, policy) {
  const mc = user?.must_change_password;
  if (mc !== undefined && mc !== 0 && mc !== '0') return 'password_change';
  return (await mfaEnrolmentPending(env, user, policy)) ? 'mfa_enroll' : null;
}

export async function setPin(env, sessionId, pin) {
  checkPin(pin === undefined ? null : pin);
  if (typeof sessionId !== 'string' || !ID_RE.test(sessionId)) return;
  await env.DB.prepare('UPDATE sessions SET pinned = ? WHERE id = ?').bind(pin ?? null, sessionId).run();
}

export async function markStepUp(env, sessionId, method, nowMs) {
  if (typeof sessionId !== 'string' || !ID_RE.test(sessionId)) return;
  const t = finite(nowMs) ? nowMs : now(env);
  await env.DB.prepare('UPDATE sessions SET aal = 2, mfa_at = ?, mfa_method = ? WHERE id = ? AND revoked_at IS NULL')
    .bind(iso(t), str(method, 32) || null, sessionId)
    .run();
}

// The one freshness rule lives in rbac.requireStepUp.
export function hasFreshStepUp(rc) {
  try {
    requireStepUp(rc);
    return true;
  } catch {
    return false;
  }
}

export async function revokeSession(env, id, reason) {
  if (typeof id !== 'string' || !ID_RE.test(id)) return 0;
  const res = await env.DB.prepare('UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL')
    .bind(iso(now(env)), str(reason, 64) || 'revoked', id)
    .run();
  return res.meta.changes;
}

export async function revokeUserSessions(env, userId, reason, opts = {}) {
  const uid = toInt(userId, 1);
  if (!Number.isFinite(uid)) return 0;
  const except = typeof opts?.exceptId === 'string' && ID_RE.test(opts.exceptId) ? opts.exceptId : null;
  const res = await env.DB.prepare('UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL AND id IS NOT ?')
    .bind(iso(now(env)), str(reason, 64) || 'revoked', uid, except)
    .run();
  return res.meta.changes;
}

// Live sessions only. Never the stored id: id_ref is what the UI acts on.
export async function listUserSessions(env, userId, currentId) {
  const uid = toInt(userId, 1);
  if (!Number.isFinite(uid)) return [];
  const t = now(env);
  const { results } = await env.DB.prepare(
    `SELECT id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, ip, ua, aal FROM sessions
     WHERE user_id = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC LIMIT 200`,
  )
    .bind(uid)
    .all();
  return results
    .filter((s) => parseIsoStrict(s.idle_expires_at) > t && parseIsoStrict(s.absolute_expires_at) > t)
    .map((s) => ({
      id_ref: String(s.id).slice(0, 12),
      created_at: s.created_at,
      last_seen_at: s.last_seen_at,
      ip: s.ip ?? null,
      ua: s.ua ?? null,
      aal: toInt(s.aal, 1, 2) === 2 ? 2 : 1,
      current: typeof currentId === 'string' && s.id === currentId,
    }));
}

// id_ref → the session row, for DELETE …/sessions/:ref. 48 bits make a
// collision unlikely, not impossible: an ambiguous ref matches nothing.
export async function findSessionByRef(env, ref, opts = {}) {
  if (typeof ref !== 'string' || !REF_RE.test(ref)) return null;
  const userId = opts?.userId;
  const uid = userId === undefined || userId === null ? null : toInt(userId, 1);
  if (Number.isNaN(uid)) return null;
  const { results } = await env.DB.prepare('SELECT * FROM sessions WHERE id GLOB ? AND (? IS NULL OR user_id = ?) LIMIT 2')
    .bind(ref + '*', uid, uid)
    .all();
  return results.length === 1 ? results[0] : null;
}

export function clearSessionCookie() {
  return clearCookie(SESSION_COOKIE);
}
