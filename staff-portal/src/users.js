// Accounts: lookup, lifecycle, roles, employee numbers, passwords and the
// account lock (CONTRACTS §7.7, SPEC §5.5–5.6, §6.2–6.5).
//
// Every guard lives inside the function that writes, so the API handler and
// the audit reverter run the same checks (B trap 5). Writers return
// { prior, row }; the API writes the audit row (CONTRACTS §4.2). Side effects
// on other tables (sessions, grace, invitations) are direct SQL in the same
// batch, so a suspension can never land without its sign-out.

import { now, iso, toInt, str, strStrict, normEmail, normUsername, parseIsoStrict, randomInt, MINUTE, DAY } from './util.js';
import { hashPassword, verifyPassword } from './crypto.js';
import { HttpError, GuardError, ValidationError, forbidden, notFound, tooMany } from './errors.js';
import { PERMISSION_KEYS, PERMISSION_BY_KEY } from './catalog.js';
import {
  SUPER_ROLE_KEY,
  effectivePermissions,
  can,
  isSuperRole,
  assertCanActOn,
  assertCanAssignRole,
  assertCanGrantPerms,
  assertNotLastSuper,
} from './rbac.js';
import { charge } from './ratelimit.js';

export const STATUSES = Object.freeze(['invited', 'active', 'suspended', 'disabled']);
export const MFA_POLICIES = Object.freeze(['inherit', 'prompt', 'required']);
export const LOCK_AFTER = 10;
export const LOCK_MS = 15 * MINUTE;
export const TEMP_ROLE_MAX_MS = 90 * DAY;
export const EMPLOYEE_NO_MAX = 999999;
export const EMPLOYEE_NO_RE = /^[A-Z]{2,8}\d{6}$/;
// No 0/O, 1/I/L: the temporary password is read aloud or copied by hand.
export const TEMP_PASSWORD_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

const ORG_CODE_RE = /^[A-Z]{2,8}$/;
const HIGH_KEY = 'employee_no_high';
const NAME_MAX = 200;
const TEXT_MAX = 200;
const PHONE_RE = /^\+?[0-9][0-9 ()-]{3,30}$/;
const PW_MIN = 12;
const PW_MAX = 1024;
const PROFILE_FIELDS = Object.freeze(['full_name', 'username', 'job_title', 'department', 'manager_id', 'employee_no', 'phone']);

// Who may move whom between which states, and with which permission
// (CONTRACTS §8.4). 'invited' is a target only from 'disabled', for someone
// who never set a password — so disabling an invitee is revertible.
const TRANSITIONS = Object.freeze({
  active: Object.freeze({ suspended: 'users.suspend', disabled: 'users.disable' }),
  suspended: Object.freeze({ active: 'users.suspend', disabled: 'users.disable' }),
  disabled: Object.freeze({ active: 'users.disable', invited: 'users.disable' }),
  invited: Object.freeze({ disabled: 'users.disable' }),
});

// ---------------------------------------------------------------- helpers

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function blank(v) {
  return v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
}

function duplicate(field) {
  const error = {
    email: 'Someone already has that email address.',
    username: 'That username is taken.',
    employee_no: 'That employee number is taken.',
  }[field];
  return new HttpError(409, { error, code: 'duplicate', field });
}

// SQLite and D1 both say "UNIQUE constraint failed: users.email".
function uniqueField(err) {
  const m = /UNIQUE constraint failed: users\.(email|username|employee_no)\b/.exec(String(err?.message || ''));
  return m ? m[1] : null;
}

function conflict() {
  return new HttpError(409, { error: 'Someone changed this account at the same moment, so nothing was changed. Reload and try again.', code: 'conflict' });
}

function readJsonList(raw) {
  if (typeof raw !== 'string') return null;
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

// The actor: rc.authz from loadSession, or (no request, e.g. a script) the
// signed-in user re-read. An actor we cannot identify, or who is no longer
// active, holds nothing.
export async function actorAuthz(rc) {
  if (rc?.authz && rc.authz.perms instanceof Set && finite(rc.authz.userId)) return rc.authz;
  const id = toInt(rc?.user?.id, 1);
  if (!rc?.env || !Number.isFinite(id)) throw forbidden();
  const row = await rc.env.DB.prepare('SELECT id, role_id, perm_grants, perm_denies, status FROM users WHERE id = ?').bind(id).first();
  if (!row || row.status !== 'active') throw forbidden();
  return effectivePermissions(rc.env, row, nowOf(rc));
}

async function loadTarget(env, userId, nowMs) {
  const row = await getUser(env, userId);
  if (!row) throw notFound('No such person.');
  return { row, authz: await effectivePermissions(env, row, nowMs) };
}

function refuseSelf(actor, targetId, what) {
  if (actor.userId === targetId) throw new GuardError('self', `You can’t ${what} your own account.`);
}

function requirePerm(actor, perm) {
  if (!can(actor, perm)) throw forbidden();
}

async function roleById(env, roleId) {
  const id = toInt(roleId, 1);
  if (!Number.isFinite(id)) return null;
  return env.DB.prepare('SELECT * FROM roles WHERE id = ?').bind(id).first();
}

function revokeSessionsStmt(db, userId, reason, at, onlyIfStatus) {
  // Conditional on the status having landed in the same batch: a refused
  // change must not sign anyone out.
  return db
    .prepare(
      `UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL
       AND (SELECT status FROM users WHERE id = ?) = ?`,
    )
    .bind(at, reason, userId, userId, onlyIfStatus);
}

// Same-statement re-check of the last-superuser rule (A §11): two Super
// Admins removing each other at once both pass assertNotLastSuper, so the
// write itself also requires ANOTHER active Super Admin to exist when it
// lands. assertNotLastSuper stays the primary guard (it fails closed when the
// count is unreadable); this only closes the race. Like that guard it counts
// PERMANENT owners only — a timed grant lapses on its own — so no expiry has
// to be compared at all.
const SUPER_ROLE_SQL = `r.key = '${SUPER_ROLE_KEY}' AND r.is_system = 1 AND r.permissions LIKE '%"*"%'`;
const OTHER_SUPER_SQL = `EXISTS (
  SELECT 1 FROM users o JOIN roles r ON r.id = o.role_id
   WHERE o.id != ? AND o.status = 'active' AND ${SUPER_ROLE_SQL}
  UNION ALL
  SELECT 1 FROM user_roles ur JOIN users o ON o.id = ur.user_id JOIN roles r ON r.id = ur.role_id
   WHERE o.id != ? AND o.status = 'active' AND ${SUPER_ROLE_SQL}
     AND ur.expires_at IS NULL)`;

function superGuard(needed, userId, nowMs) {
  return needed ? { sql: ` AND ${OTHER_SUPER_SQL}`, args: [userId, userId] } : { sql: '', args: [] };
}

// A guarded write that changed nothing: either the last-superuser rule
// refused at the last moment, or someone else got there first.
async function explainNoChange(env, userId, guarded, nowMs) {
  if (guarded) await assertNotLastSuper(env, userId, nowMs);
  throw conflict();
}

// ---------------------------------------------------------------- reading

export async function getUser(env, id) {
  const uid = toInt(id, 1);
  if (!Number.isFinite(uid)) return null;
  return env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(uid).first();
}

// The one normal form of a sign-in name: the email or username exactly as
// the lookup matches it, or null. The login_id bucket keys on this too, so
// two spellings the lookup treats as one account (case, surrounding space, a
// username typed past its 32 characters) are one bucket (SPEC §6.4).
export function canonicalIdentifier(identifier) {
  if (typeof identifier !== 'string') return null;
  if (identifier.includes('@')) {
    const email = normEmail(identifier);
    return email ? { kind: 'email', value: email } : null;
  }
  const username = normUsername(identifier);
  return username ? { kind: 'username', value: username } : null;
}

// Emails and usernames are stored lowercased, so lowercasing the identifier
// is the whole of "case-insensitive".
export async function findUserByIdentifier(env, identifier) {
  const id = canonicalIdentifier(identifier);
  if (!id) return null;
  const sql = id.kind === 'email' ? 'SELECT * FROM users WHERE email = ?' : 'SELECT * FROM users WHERE username = ?';
  return env.DB.prepare(sql).bind(id.value).first();
}

function roleShape(r, fallbackId) {
  const rank = toInt(r?.rank);
  return {
    id: r?.id ?? fallbackId ?? null,
    key: typeof r?.key === 'string' ? r.key : null,
    name: typeof r?.name === 'string' ? r.name : null,
    rank: Number.isFinite(rank) ? rank : null,
  };
}

// The only way a user row leaves the server (CONTRACTS §4.5). `role` may be a
// roles row, authz.role, or a whole authz; a row joined with role_key /
// role_name / role_rank supplies its own. Admin views pass withLocked and see
// `locked`, never the counters.
export function publicUser(row, role = null, { withLocked = false, nowMs } = {}) {
  if (!row || typeof row !== 'object') return null;
  let r = null;
  if (role && typeof role === 'object') r = role.perms instanceof Set ? role.role : role;
  else if (row.role_key !== undefined) r = { id: row.role_id, key: row.role_key, name: row.role_name, rank: row.role_rank };
  const out = {
    id: row.id,
    email: row.email,
    username: row.username ?? null,
    full_name: row.full_name ?? '',
    employee_no: row.employee_no ?? null,
    job_title: row.job_title ?? null,
    department: row.department ?? null,
    manager_id: row.manager_id ?? null,
    status: row.status,
    role: roleShape(r, row.role_id),
    mfa_policy: MFA_POLICIES.includes(row.mfa_policy) ? row.mfa_policy : 'required',
    last_login_at: row.last_login_at ?? null,
    created_at: row.created_at ?? null,
  };
  if (withLocked === true) out.locked = isLocked(row, nowMs);
  return out;
}

export async function listUsers(env, opts = {}) {
  const o = isPlainObject(opts) ? opts : {};
  const where = [];
  const args = [];
  if (STATUSES.includes(o.status)) {
    where.push('u.status = ?');
    args.push(o.status);
  }
  const q = str(o.q, 100);
  if (q) {
    // instr, not LIKE: D1 refuses LIKE patterns over 50 bytes, and a
    // 49-character search (or 29 Hebrew letters) would be a 500.
    const p = q.toLowerCase();
    where.push(`(instr(lower(u.email), ?) > 0 OR instr(lower(coalesce(u.username, '')), ?) > 0 OR instr(lower(u.full_name), ?) > 0 OR instr(lower(coalesce(u.employee_no, '')), ?) > 0)`);
    args.push(p, p, p, p);
  }
  const roleId = toInt(o.role, 1);
  if (Number.isFinite(roleId)) {
    where.push('u.role_id = ?');
    args.push(roleId);
  } else if (typeof o.role === 'string' && o.role.trim()) {
    where.push('r.key = ?');
    args.push(str(o.role, 64));
  }
  const managerId = toInt(o.managerId, 1);
  if (Number.isFinite(managerId)) {
    where.push('u.manager_id = ?');
    args.push(managerId);
  }
  const limit = toInt(o.limit, 1, 500);
  const offset = toInt(o.offset, 0, 1_000_000);
  const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const from = 'FROM users u LEFT JOIN roles r ON r.id = u.role_id';
  const [rows, total] = await Promise.all([
    env.DB.prepare(
      `SELECT u.*, r.key AS role_key, r.name AS role_name, r.rank AS role_rank ${from} ${w}
       ORDER BY u.full_name COLLATE NOCASE, u.id LIMIT ? OFFSET ?`,
    )
      .bind(...args, Number.isFinite(limit) ? limit : 50, Number.isFinite(offset) ? offset : 0)
      .all(),
    env.DB.prepare(`SELECT COUNT(*) AS n ${from} ${w}`).bind(...args).first('n'),
  ]);
  const nowMs = finite(o.nowMs) ? o.nowMs : now(env);
  return {
    users: rows.results.map((row) => publicUser(row, null, { withLocked: o.withLocked === true, nowMs })),
    total: toInt(total, 0) || 0,
  };
}

export async function countActiveUsers(env) {
  const n = toInt(await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'active'").first('n'), 0);
  return Number.isFinite(n) ? n : 0;
}

export async function anyUsers(env) {
  return !!(await env.DB.prepare('SELECT 1 AS x FROM users LIMIT 1').first());
}

// ---------------------------------------------------------------- passwords

// SPEC §6.2: 12–1,024 characters, not the email or username, not one
// character repeated. Nothing else. Never trimmed: spaces are characters.
export function validatePassword(pw, { email, username, field = 'password' } = {}) {
  if (typeof pw !== 'string' || pw.length === 0) throw new ValidationError('Choose a password.', field);
  if (pw.length > PW_MAX * 2) throw new ValidationError('Use at most 1,024 characters.', field);
  const chars = Array.from(pw);
  if (chars.length < PW_MIN) throw new ValidationError('Use at least 12 characters.', field);
  if (chars.length > PW_MAX) throw new ValidationError('Use at most 1,024 characters.', field);
  if (new Set(chars).size === 1 || pw.trim() === '') throw new ValidationError('A password can’t be one character repeated.', field);
  const lower = pw.trim().toLowerCase();
  for (const v of [email, username]) {
    if (typeof v === 'string' && v && lower === v.trim().toLowerCase()) {
      throw new ValidationError('A password can’t be your email address or username.', field);
    }
  }
}

export async function setPassword(env, userId, password, opts = {}) {
  const row = await getUser(env, userId);
  if (!row) throw notFound('No such person.');
  validatePassword(password, { email: row.email, username: row.username });
  const h = await hashPassword(env, password);
  await env.DB.prepare(
    `UPDATE users SET password_hash = ?, password_salt = ?, password_algo = ?, password_iters = ?,
       must_change_password = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(h.hash, h.salt, h.algo, h.iters, opts?.mustChange === true ? 1 : 0, iso(now(env)), row.id)
    .run();
}

// Charged to curpw_user BEFORE the check (A §6). Ends every OTHER session
// (SPEC §6.5) and moves this session's password_change pin on to whatever is
// next — dropping it to null would let a required-MFA account skip enrolment.
export async function changeOwnPassword(rc, current, next) {
  const env = rc.env;
  const t = nowOf(rc);
  const uid = toInt(rc?.user?.id, 1);
  if (!Number.isFinite(uid)) throw new HttpError(401, { error: 'Sign in first.' });
  const row = await getUser(env, uid);
  if (!row || row.status !== 'active') throw new HttpError(401, { error: 'Sign in first.' });
  const lim = await charge(env, 'curpw_user', String(uid), t);
  if (!lim.allowed) throw tooMany(lim.retryAfterSec);
  if (typeof current !== 'string' || current.length > PW_MAX * 4 || !(await verifyPassword(current, row))) {
    throw new ValidationError('That isn’t your current password.', 'current');
  }
  validatePassword(next, { email: row.email, username: row.username, field: 'next' });
  if (next === current) throw new ValidationError('Choose a password different from your current one.', 'next');
  const h = await hashPassword(env, next);
  const pendingEnrol = await mfaEnrolmentPending(env, { ...row, must_change_password: 0 }, rc.policy, rc.authz);
  const pin = pendingEnrol ? 'mfa_enroll' : null;
  const sid = typeof rc.session?.id === 'string' ? rc.session.id : null;
  const at = iso(t);
  const db = env.DB;
  await db.batch([
    db
      .prepare(
        `UPDATE users SET password_hash = ?, password_salt = ?, password_algo = ?, password_iters = ?,
           must_change_password = 0, updated_at = ? WHERE id = ?`,
      )
      .bind(h.hash, h.salt, h.algo, h.iters, at, uid),
    db
      .prepare("UPDATE sessions SET revoked_at = ?, revoke_reason = 'password.change' WHERE user_id = ? AND revoked_at IS NULL AND id IS NOT ?")
      .bind(at, uid, sid),
    db.prepare("UPDATE sessions SET pinned = ? WHERE id = ? AND pinned = 'password_change'").bind(pin, sid),
  ]);
  if (rc.session && rc.session.pinned === 'password_change') rc.session.pinned = pin;
  return { pinned: rc.session ? rc.session.pinned ?? null : pin };
}

function temporaryPassword() {
  let s = '';
  for (let i = 0; i < 20; i++) {
    if (i && i % 5 === 0) s += '-';
    s += TEMP_PASSWORD_ALPHABET[randomInt(TEMP_PASSWORD_ALPHABET.length)];
  }
  return s;
}

// Reserved to Super Admins (SPEC §6.5). Shown once; the next session is
// pinned to the change form. Ends their sessions and drops grace windows so
// no already-verified browser coasts on; clears the lock, since the old
// password it protected no longer works.
export async function adminResetPassword(rc, userId) {
  const env = rc.env;
  const t = nowOf(rc);
  const actor = await actorAuthz(rc);
  const { row, authz: target } = await loadTarget(env, userId, t);
  refuseSelf(actor, row.id, 'reset the password of');
  requirePerm(actor, 'users.reset_password');
  assertCanActOn(actor, target);
  if (row.status === 'invited') {
    throw new GuardError('invited', 'They haven’t accepted their invitation yet. Reissue it instead.', 409);
  }
  const temporary_password = temporaryPassword();
  const h = await hashPassword(env, temporary_password);
  const at = iso(t);
  const db = env.DB;
  await db.batch([
    db
      .prepare(
        `UPDATE users SET password_hash = ?, password_salt = ?, password_algo = ?, password_iters = ?,
           must_change_password = 1, failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?`,
      )
      .bind(h.hash, h.salt, h.algo, h.iters, at, row.id),
    db.prepare("UPDATE sessions SET revoked_at = ?, revoke_reason = 'password.reset' WHERE user_id = ? AND revoked_at IS NULL").bind(at, row.id),
    db.prepare('DELETE FROM mfa_grace WHERE user_id = ?').bind(row.id),
  ]);
  return { temporary_password };
}

// ---------------------------------------------------------------- employee numbers

export function employeePrefix(env) {
  const c = env?.ORG_CODE;
  return typeof c === 'string' && ORG_CODE_RE.test(c) ? c : 'EMP';
}

// Raise-only: a value in meta that is not a canonical integer is never
// overwritten (it stays unreadable, so issuing keeps refusing until repaired).
function raiseHighWaterStmt(db, n) {
  return db
    .prepare(
      `INSERT INTO meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value
         WHERE CAST(CAST(meta.value AS INTEGER) AS TEXT) = meta.value
           AND CAST(meta.value AS INTEGER) < CAST(excluded.value AS INTEGER)`,
    )
    .bind(HIGH_KEY, String(n));
}

function prefixedNumber(env, employeeNo) {
  const prefix = employeePrefix(env);
  if (typeof employeeNo !== 'string' || !employeeNo.startsWith(prefix)) return NaN;
  const rest = employeeNo.slice(prefix.length);
  return /^\d{6}$/.test(rest) ? toInt(rest, 1, EMPLOYEE_NO_MAX) : NaN;
}

// From the highest number ever issued — the meta high-water mark and the
// largest existing number, whichever is higher — never a row count (B trap
// 10): disabling employee 12 must not hand 12 to the next hire. The upsert
// is one statement, so two concurrent hires get different numbers.
export async function nextEmployeeNo(env) {
  const db = env.DB;
  const prefix = employeePrefix(env);
  const top = await db
    .prepare('SELECT MAX(CAST(substr(employee_no, ?) AS INTEGER)) AS n FROM users WHERE employee_no GLOB ?')
    .bind(prefix.length + 1, prefix + '[0-9]'.repeat(6))
    .first('n');
  const existing = toInt(top, 0, EMPLOYEE_NO_MAX);
  const maxExisting = Number.isFinite(existing) ? existing : 0;
  const exhausted = () =>
    new HttpError(409, { error: `Employee numbers have run out (${EMPLOYEE_NO_MAX} is the highest). Enter one by hand.`, code: 'employee_no_exhausted' });
  if (maxExisting >= EMPLOYEE_NO_MAX) throw exhausted();
  // A bound JS number arrives as REAL, and MAX(…, 900.0) + 1 would store
  // '901.0' — which the next call rightly reads as unreadable. Cast it.
  const issued = await db
    .prepare(
      `INSERT INTO meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = CAST(MAX(CAST(meta.value AS INTEGER), CAST(? AS INTEGER)) + 1 AS TEXT)
         WHERE CAST(CAST(meta.value AS INTEGER) AS TEXT) = meta.value
           AND MAX(CAST(meta.value AS INTEGER), CAST(? AS INTEGER)) < CAST(? AS INTEGER)
       RETURNING value`,
    )
    .bind(HIGH_KEY, String(maxExisting + 1), maxExisting, maxExisting, EMPLOYEE_NO_MAX)
    .first();
  const n = toInt(issued?.value, 1, EMPLOYEE_NO_MAX);
  if (Number.isFinite(n)) return prefix + String(n).padStart(6, '0');
  const cur = await db.prepare('SELECT value FROM meta WHERE key = ?').bind(HIGH_KEY).first();
  const high = typeof cur?.value === 'string' && /^\d{1,7}$/.test(cur.value) ? toInt(cur.value) : NaN;
  if (Number.isFinite(high) && high >= EMPLOYEE_NO_MAX) throw exhausted();
  // Present but unreadable: we cannot know what was issued, so issue nothing.
  console.error('users: meta.employee_no_high is unreadable; refusing to issue an employee number');
  throw new HttpError(409, {
    error: 'The employee-number counter can’t be read, so no number was issued. Enter one by hand, or repair meta.employee_no_high.',
    code: 'employee_no_unreadable',
  });
}

// ---------------------------------------------------------------- field parsing

function parseEmployeeNo(v) {
  if (typeof v !== 'string') throw new ValidationError('Employee numbers look like ACME000123.', 'employee_no');
  const s = v.trim().toUpperCase();
  if (!EMPLOYEE_NO_RE.test(s)) throw new ValidationError('Employee numbers look like ACME000123.', 'employee_no');
  return s;
}

function parseOptionalUsername(v) {
  if (blank(v)) return null;
  const u = normUsername(v);
  if (!u || typeof v !== 'string') {
    throw new ValidationError('Usernames are 2–32 letters, digits, dots, dashes or underscores.', 'username');
  }
  return u;
}

function parseOptionalText(v, field) {
  if (blank(v)) return null;
  if (typeof v !== 'string') throw new ValidationError('Enter text.', field);
  return str(v, TEXT_MAX);
}

function parseOptionalPhone(v) {
  if (blank(v)) return null;
  const s = typeof v === 'string' ? v.trim() : '';
  if (!PHONE_RE.test(s)) throw new ValidationError('Enter a phone number using digits, spaces, dashes or brackets.', 'phone');
  return s;
}

function parseFullName(v) {
  const s = strStrict(v, 1, NAME_MAX);
  if (!s) throw new ValidationError('Enter a full name (up to 200 characters).', 'full_name');
  return s;
}

// A manager must be a real person who is here or about to be.
async function parseManager(env, v, selfId = null) {
  if (blank(v)) return null;
  const id = toInt(v, 1);
  if (!Number.isFinite(id)) throw new ValidationError('Choose a manager.', 'manager_id');
  if (id === selfId) throw new ValidationError('Nobody can be their own manager.', 'manager_id');
  const m = await env.DB.prepare('SELECT status FROM users WHERE id = ?').bind(id).first();
  if (!m || (m.status !== 'active' && m.status !== 'invited')) {
    throw new ValidationError('That manager doesn’t exist or has left.', 'manager_id');
  }
  return id;
}

async function taken(env, column, value, exceptId = null) {
  const row = await env.DB.prepare(`SELECT id FROM users WHERE ${column} = ? AND id IS NOT ?`).bind(value, exceptId).first();
  return !!row;
}

// ---------------------------------------------------------------- creating

// Status 'invited', no password: the invitee chooses their own (SPEC §6.7).
// Minting guard on the role; explicit duplicate checks so a typo reads as a
// sentence, and the same sentences when a concurrent insert wins the UNIQUE
// race (B trap 10).
export async function createUser(rc, input) {
  const env = rc.env;
  if (!isPlainObject(input)) throw new ValidationError('Nothing to create.');
  const email = normEmail(input.email);
  if (!email || typeof input.email !== 'string') throw new ValidationError('Enter a valid email address.', 'email');
  const fullName = parseFullName(input.full_name);
  const roleId = toInt(input.role_id, 1);
  if (!Number.isFinite(roleId)) throw new ValidationError('Choose a role.', 'role_id');
  const username = parseOptionalUsername(input.username);
  const explicitNo = blank(input.employee_no) ? null : parseEmployeeNo(input.employee_no);
  const jobTitle = parseOptionalText(input.job_title, 'job_title');
  const department = parseOptionalText(input.department, 'department');
  if (input.status !== undefined && input.status !== null && input.status !== 'invited') {
    throw new ValidationError('New accounts start as invited.', 'status');
  }

  const actor = await actorAuthz(rc);
  const role = await roleById(env, roleId);
  if (!role) throw new ValidationError('That role doesn’t exist.', 'role_id');
  assertCanAssignRole(actor, role);
  const managerId = await parseManager(env, input.manager_id);

  if (await taken(env, 'email', email)) throw duplicate('email');
  if (username && (await taken(env, 'username', username))) throw duplicate('username');
  if (explicitNo && (await taken(env, 'employee_no', explicitNo))) throw duplicate('employee_no');

  const db = env.DB;
  // An auto-issued number that loses a race is simply issued again.
  for (let attempt = 0; ; attempt++) {
    const at = iso(nowOf(rc));
    const employeeNo = explicitNo ?? (await nextEmployeeNo(env));
    const stmts = [
      db
        .prepare(
          `INSERT INTO users (email, username, full_name, employee_no, job_title, department, manager_id,
             status, role_id, perm_grants, perm_denies, mfa_policy, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'invited', ?, '[]', '[]', 'inherit', ?, ?, ?)`,
        )
        .bind(email, username, fullName, employeeNo, jobTitle, department, managerId, role.id, actor.userId, at, at),
    ];
    const typed = prefixedNumber(env, explicitNo);
    if (Number.isFinite(typed)) stmts.push(raiseHighWaterStmt(db, typed));
    try {
      const [ins] = await db.batch(stmts);
      return getUser(env, ins.meta.last_row_id);
    } catch (e) {
      const field = uniqueField(e);
      if (field === 'employee_no' && !explicitNo && attempt < 3) continue;
      if (field) throw duplicate(field);
      throw e;
    }
  }
}

// Bootstrap only (CONTRACTS §8.4 POST /api/setup): the first account, an
// active Super Admin with a password. The INSERT is conditional on the table
// being empty, so two racing setups cannot both create an owner.
export async function createOwner(env, input, nowMs) {
  if (!isPlainObject(input)) throw new ValidationError('Nothing to create.');
  const email = normEmail(input.email);
  if (!email || typeof input.email !== 'string') throw new ValidationError('Enter a valid email address.', 'email');
  const fullName = parseFullName(input.full_name);
  validatePassword(input.password, { email });
  const done = () => new HttpError(409, { error: 'Setup has already been completed.', code: 'setup_done' });
  if (await anyUsers(env)) throw done();
  const role = await env.DB.prepare('SELECT * FROM roles WHERE key = ? AND is_system = 1').bind(SUPER_ROLE_KEY).first();
  if (!isSuperRole(role)) throw new Error('users: the super_admin system role is missing or altered');
  const h = await hashPassword(env, input.password);
  const employeeNo = await nextEmployeeNo(env);
  const at = iso(finite(nowMs) ? nowMs : now(env));
  const res = await env.DB.prepare(
    `INSERT INTO users (email, full_name, employee_no, password_hash, password_salt, password_algo, password_iters,
       status, role_id, mfa_policy, created_at, updated_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, 'active', ?, 'inherit', ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`,
  )
    .bind(email, fullName, employeeNo, h.hash, h.salt, h.algo, h.iters, role.id, at, at)
    .run();
  if (res.meta.changes !== 1) throw done();
  return getUser(env, res.meta.last_row_id);
}

// ---------------------------------------------------------------- profile

// Self is allowed; without users.edit a person may change only their own
// name (PATCH /api/me). Returns prior = the changed fields' old values — the
// 'user.profile' undo payload's `fields`.
export async function updateProfile(rc, userId, patch) {
  const env = rc.env;
  const t = nowOf(rc);
  if (!isPlainObject(patch)) throw new ValidationError('Nothing to change.');
  const actor = await actorAuthz(rc);
  const { row, authz: target } = await loadTarget(env, userId, t);
  const self = actor.userId === row.id;
  const editor = can(actor, 'users.edit');
  if (!self) {
    requirePerm(actor, 'users.edit');
    assertCanActOn(actor, target);
  }

  const next = {};
  for (const k of PROFILE_FIELDS) {
    if (!Object.hasOwn(patch, k)) continue;
    if (self && !editor && k !== 'full_name') throw forbidden('You can change only your own name.');
    const v = patch[k];
    if (k === 'full_name') next[k] = parseFullName(v);
    else if (k === 'username') next[k] = parseOptionalUsername(v);
    else if (k === 'job_title' || k === 'department') next[k] = parseOptionalText(v, k);
    else if (k === 'phone') next[k] = parseOptionalPhone(v);
    else if (k === 'manager_id') next[k] = await parseManager(env, v, row.id);
    else if (k === 'employee_no') {
      if (blank(v)) throw new ValidationError('Employee numbers can be changed but not removed.', 'employee_no');
      next[k] = parseEmployeeNo(v);
    }
  }
  const prior = {};
  const changed = Object.keys(next).filter((k) => next[k] !== (row[k] ?? null));
  for (const k of changed) prior[k] = row[k] ?? null;
  if (!changed.length) return { prior, row };

  if (changed.includes('username') && next.username && (await taken(env, 'username', next.username, row.id))) throw duplicate('username');
  if (changed.includes('employee_no') && (await taken(env, 'employee_no', next.employee_no, row.id))) throw duplicate('employee_no');

  const db = env.DB;
  // Conditional on the values we read: a concurrent edit is a conflict, not
  // a silent overwrite.
  const sets = changed.map((k) => `${k} = ?`).join(', ');
  const checks = changed.map((k) => `${k} IS ?`).join(' AND ');
  const stmts = [
    db
      .prepare(`UPDATE users SET ${sets}, updated_at = ? WHERE id = ? AND ${checks}`)
      .bind(...changed.map((k) => next[k]), iso(t), row.id, ...changed.map((k) => prior[k])),
  ];
  const typed = changed.includes('employee_no') ? prefixedNumber(env, next.employee_no) : NaN;
  if (Number.isFinite(typed)) stmts.push(raiseHighWaterStmt(db, typed));
  let res;
  try {
    [res] = await db.batch(stmts);
  } catch (e) {
    const field = uniqueField(e);
    if (field) throw duplicate(field);
    throw e;
  }
  if (res.meta.changes !== 1) throw conflict();
  return { prior, row: await getUser(env, row.id) };
}

// ---------------------------------------------------------------- status

// SPEC §5.6. Guards: self, rank, the transition table and its permission,
// the last Super Admin. Leaving 'active' ends sessions and drops grace in the
// same batch; disabling also revokes pending invitations, so a link sent to
// someone who never started does not outlive the decision.
export async function setStatus(rc, userId, status) {
  const env = rc.env;
  const t = nowOf(rc);
  const next = typeof status === 'string' && STATUSES.includes(status) ? status : null;
  if (!next) throw new ValidationError('Status must be active, suspended or disabled.', 'status');
  const actor = await actorAuthz(rc);
  const { row, authz: target } = await loadTarget(env, userId, t);
  refuseSelf(actor, row.id, 'change the status of');
  assertCanActOn(actor, target);
  const from = row.status;
  const perm = Object.hasOwn(TRANSITIONS, from) && Object.hasOwn(TRANSITIONS[from], next) ? TRANSITIONS[from][next] : null;
  if (!perm) throw new GuardError('invalid_transition', `An account that is ${str(from, 20) || 'unreadable'} can’t be made ${next}.`, 409);
  requirePerm(actor, perm);
  const hasPassword = typeof row.password_hash === 'string' && row.password_hash !== '';
  if (next === 'active' && !hasPassword) {
    throw new GuardError('invalid_transition', 'They never set a password. Make them invited again and reissue their invitation.', 409);
  }
  if (next === 'invited' && hasPassword) {
    throw new GuardError('invalid_transition', 'They already set a password, so they can be re-enabled but not re-invited.', 409);
  }
  const leavingActive = from === 'active';
  if (leavingActive) await assertNotLastSuper(env, row.id, t);

  const at = iso(t);
  const disabledAt = next === 'disabled' ? at : next === 'suspended' ? row.disabled_at ?? null : null;
  const g = superGuard(leavingActive && target.isSuper, row.id, t);
  const db = env.DB;
  const stmts = [
    db
      .prepare(`UPDATE users SET status = ?, disabled_at = ?, updated_at = ? WHERE id = ? AND status = ?${g.sql}`)
      .bind(next, disabledAt, at, row.id, from, ...g.args),
  ];
  if (next !== 'active') {
    stmts.push(revokeSessionsStmt(db, row.id, `user.${next}`, at, next));
    stmts.push(db.prepare('DELETE FROM mfa_grace WHERE user_id = ? AND (SELECT status FROM users WHERE id = ?) = ?').bind(row.id, row.id, next));
  }
  if (next === 'disabled') {
    stmts.push(
      db
        .prepare(
          `UPDATE invitations SET revoked_at = ? WHERE user_id = ? AND used_at IS NULL AND revoked_at IS NULL
           AND (SELECT status FROM users WHERE id = ?) = 'disabled'`,
        )
        .bind(at, row.id, row.id),
    );
  }
  const [res] = await db.batch(stmts);
  if (res.meta.changes !== 1) await explainNoChange(env, row.id, !!g.sql, t);
  return { prior: { status: from }, row: await getUser(env, row.id) };
}

// ---------------------------------------------------------------- roles

function parseGrants(actor, v) {
  if (!Array.isArray(v) || v.length > 200) throw new ValidationError('Permissions must be a list.', 'perm_grants');
  assertCanGrantPerms(actor, v);
  const seen = new Set(v);
  return PERMISSION_KEYS.filter((k) => seen.has(k));
}

// Denies narrow, so anyone may set them — but only to catalogue keys. '*'
// would read as deny-everything (rbac), which is not something to type.
function parseDenies(v) {
  if (!Array.isArray(v) || v.length > 200) throw new ValidationError('Denied permissions must be a list.', 'perm_denies');
  for (const k of v) {
    if (typeof k !== 'string' || !Object.hasOwn(PERMISSION_BY_KEY, k)) throw new ValidationError('Unknown permission.', 'perm_denies');
  }
  const seen = new Set(v);
  return PERMISSION_KEYS.filter((k) => seen.has(k));
}

// Guards (SPEC §5.5): rank on the target BEFORE (you outrank who they are
// now) and AFTER (the new role is below your own — assertCanAssignRole), the
// grants you hand out are ones you hold and none reserved, and the last Super
// Admin cannot be demoted. Omitted grants/denies are kept as stored.
export async function changeRole(rc, userId, input) {
  const env = rc.env;
  const t = nowOf(rc);
  if (!isPlainObject(input)) throw new ValidationError('Choose a role.', 'role_id');
  const actor = await actorAuthz(rc);
  const { row, authz: before } = await loadTarget(env, userId, t);
  refuseSelf(actor, row.id, 'change the role of');
  requirePerm(actor, 'users.roles');
  assertCanActOn(actor, before);
  const roleId = toInt(input.role_id, 1);
  if (!Number.isFinite(roleId)) throw new ValidationError('Choose a role.', 'role_id');
  const role = await roleById(env, roleId);
  if (!role) throw new ValidationError('That role doesn’t exist.', 'role_id');
  assertCanAssignRole(actor, role);
  const grants = input.perm_grants === undefined ? row.perm_grants : JSON.stringify(parseGrants(actor, input.perm_grants));
  const denies = input.perm_denies === undefined ? row.perm_denies : JSON.stringify(parseDenies(input.perm_denies));

  const after = await effectivePermissions(env, { ...row, role_id: role.id, perm_grants: grants, perm_denies: denies }, t);
  const losesSuper = before.isSuper && !after.isSuper;
  if (losesSuper) await assertNotLastSuper(env, row.id, t);

  const g = superGuard(losesSuper && row.status === 'active', row.id, t);
  const res = await env.DB.prepare(
    `UPDATE users SET role_id = ?, perm_grants = ?, perm_denies = ?, updated_at = ?
     WHERE id = ? AND role_id = ? AND perm_grants IS ? AND perm_denies IS ?${g.sql}`,
  )
    .bind(role.id, grants, denies, iso(t), row.id, row.role_id, row.perm_grants, row.perm_denies, ...g.args)
    .run();
  if (res.meta.changes !== 1) await explainNoChange(env, row.id, !!g.sql, t);
  // An unreadable stored list goes into the undo payload verbatim, so a
  // revert refuses it rather than inventing a value.
  const prior = {
    role_id: row.role_id,
    perm_grants: readJsonList(row.perm_grants) ?? row.perm_grants,
    perm_denies: readJsonList(row.perm_denies) ?? row.perm_denies,
  };
  return { prior, row: await getUser(env, row.id) };
}

// "Admin for a week" (SPEC §5.6): an expiry is required, in the future, at
// most 90 days out; the role passes the same minting guard as a permanent one.
export async function grantTempRole(rc, userId, roleId, expiresAtIso) {
  const env = rc.env;
  const t = nowOf(rc);
  const actor = await actorAuthz(rc);
  const { row, authz: target } = await loadTarget(env, userId, t);
  refuseSelf(actor, row.id, 'grant a temporary role to');
  requirePerm(actor, 'users.roles');
  assertCanActOn(actor, target);
  const role = await roleById(env, roleId);
  if (!role) throw new ValidationError('That role doesn’t exist.', 'role_id');
  assertCanAssignRole(actor, role);
  const exp = parseIsoStrict(expiresAtIso);
  if (!Number.isFinite(exp)) throw new ValidationError('A temporary role needs an expiry date and time.', 'expires_at');
  if (exp <= t) throw new ValidationError('The expiry must be in the future.', 'expires_at');
  if (exp > t + TEMP_ROLE_MAX_MS) throw new ValidationError('A temporary role can last at most 90 days.', 'expires_at');

  const db = env.DB;
  const old = await db.prepare('SELECT expires_at, granted_by FROM user_roles WHERE user_id = ? AND role_id = ?').bind(row.id, role.id).first();
  const expiresAt = iso(exp);
  await db
    .prepare(
      `INSERT INTO user_roles (user_id, role_id, granted_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id, role_id) DO UPDATE SET granted_by = excluded.granted_by, expires_at = excluded.expires_at`,
    )
    .bind(row.id, role.id, actor.userId, expiresAt, iso(t))
    .run();
  return {
    prior: old ? { expires_at: old.expires_at ?? null, granted_by: old.granted_by ?? null } : null,
    row: { user_id: row.id, role_id: role.id, expires_at: expiresAt, granted_by: actor.userId },
  };
}

export async function revokeTempRole(rc, userId, roleId) {
  const env = rc.env;
  const t = nowOf(rc);
  const actor = await actorAuthz(rc);
  const { row, authz: before } = await loadTarget(env, userId, t);
  refuseSelf(actor, row.id, 'revoke a temporary role from');
  requirePerm(actor, 'users.roles');
  assertCanActOn(actor, before);
  const rid = toInt(roleId, 1);
  if (!Number.isFinite(rid)) throw notFound('They don’t hold that temporary role.');
  const db = env.DB;
  const old = await db
    .prepare(
      `SELECT ur.expires_at, ur.granted_by, r.key, r.permissions, r.is_system FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? AND ur.role_id = ?`,
    )
    .bind(row.id, rid)
    .first();
  if (!old) throw notFound('They don’t hold that temporary role.');
  // (user, role) is the primary key, so this is their only grant of that
  // role: removing a Super Admin grant leaves them super only by their
  // permanent role.
  const losesSuper = before.isSuper && isSuperRole(old) && !isSuperRole(await roleById(env, row.role_id));
  if (losesSuper) await assertNotLastSuper(env, row.id, t);
  const g = superGuard(losesSuper && row.status === 'active', row.id, t);
  const res = await db
    .prepare(`DELETE FROM user_roles WHERE user_id = ? AND role_id = ?${g.sql}`)
    .bind(row.id, rid, ...g.args)
    .run();
  if (res.meta.changes !== 1) await explainNoChange(env, row.id, !!g.sql, t);
  return { prior: { expires_at: old.expires_at ?? null, granted_by: old.granted_by ?? null } };
}

// ---------------------------------------------------------------- lockout

// D6: ten consecutive failures lock the account for fifteen minutes. One
// atomic UPDATE (SQLite reads the OLD failed_logins on the right-hand side),
// so concurrent failures cannot under-count. The API decides when a known
// device bypasses the lock (knownDeviceFor).
export async function recordLoginFailure(env, user, nowMs) {
  const id = toInt(user?.id, 1);
  if (!Number.isFinite(id)) return;
  const t = finite(nowMs) ? nowMs : now(env);
  await env.DB.prepare(
    `UPDATE users SET failed_logins = COALESCE(failed_logins, 0) + 1,
       locked_until = CASE WHEN COALESCE(failed_logins, 0) + 1 >= ? THEN ? ELSE locked_until END
     WHERE id = ?`,
  )
    .bind(LOCK_AFTER, iso(t + LOCK_MS), id)
    .run();
}

export async function clearLoginFailures(env, userId) {
  const id = toInt(userId, 1);
  if (!Number.isFinite(id)) return;
  await env.DB.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?').bind(id).run();
}

// Absent → unlocked. Present but unreadable → LOCKED (A §14.3): a lock we
// cannot read might be the only thing stopping a guessing run.
export function isLocked(user, nowMs) {
  const v = user?.locked_until;
  if (v === undefined || v === null) return false;
  const until = parseIsoStrict(v);
  if (!Number.isFinite(until) || !finite(nowMs)) return true;
  return until > nowMs;
}

// "A device that has signed in to that account before" (SPEC §6.4): the
// device_users ledger, and the device not blocked. An unrecognised device
// status reads as blocked.
export async function knownDeviceFor(env, userId, deviceId) {
  const id = toInt(userId, 1);
  if (!Number.isFinite(id) || typeof deviceId !== 'string' || !deviceId || deviceId.length > 128) return false;
  const row = await env.DB.prepare(
    'SELECT d.status FROM device_users du JOIN devices d ON d.id = du.device_id WHERE du.user_id = ? AND du.device_id = ?',
  )
    .bind(id, deviceId)
    .first();
  return !!row && (row.status === 'approved' || row.status === 'pending');
}

// ---------------------------------------------------------------- second-factor policy

// SPEC §7.8: per-person inherit/prompt/required over the global setting; a
// Super Admin is always 'required'; anything unrecognised reads 'required'.
// A missing policy object means the §5 default ('prompt'). Pass authz to
// catch Super Admins by temporary role; a row joined with role_key also works.
export function mfaPolicyFor(user, policy, authz = null) {
  if (authz?.isSuper === true || user?.role_key === SUPER_ROLE_KEY) return 'required';
  const own = user?.mfa_policy;
  if (own === 'prompt' || own === 'required') return own;
  if (own !== 'inherit' && own !== undefined) return 'required';
  if (!policy || typeof policy !== 'object' || policy.mfa_policy === undefined) return 'prompt';
  return policy.mfa_policy === 'prompt' ? 'prompt' : 'required';
}

function smsReady(env) {
  return ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_FROM'].every((k) => typeof env?.[k] === 'string' && env[k].trim() !== '');
}

function emailReady(env) {
  return ['RESEND_API_KEY', 'MAIL_FROM'].every((k) => typeof env?.[k] === 'string' && env[k].trim() !== '');
}

// True when policy says 'required' and the person has no confirmed
// authenticator, no passkey and no code destination a configured provider
// can reach — the 'mfa_enroll' pin (B trap 3: pin, never refuse). Direct SQL
// so this does not depend on the factor modules.
export async function mfaEnrolmentPending(env, user, policy, authz = null) {
  const id = toInt(user?.id, 1);
  if (!Number.isFinite(id)) return true;
  const a = authz && authz.userId === id ? authz : await effectivePermissions(env, user, now(env));
  if (mfaPolicyFor(user, policy, a) !== 'required') return false;
  const f = await env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND confirmed_at IS NOT NULL) AS totp,
            (SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?) AS passkeys,
            (SELECT COUNT(*) FROM code_destinations WHERE user_id = ? AND kind = 'sms') AS sms,
            (SELECT COUNT(*) FROM code_destinations WHERE user_id = ? AND kind = 'email') AS email`,
  )
    .bind(id, id, id, id)
    .first();
  const n = (k) => toInt(f?.[k], 1) >= 1;
  if (n('totp') || n('passkeys')) return false;
  if (n('sms') && smsReady(env)) return false;
  if (n('email') && emailReady(env)) return false;
  return true;
}
