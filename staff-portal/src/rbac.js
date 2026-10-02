// Effective permissions and the guards that make delegation safe
// (CONTRACTS §6, B §4). catalog.js holds the data; this file decides.
//
// Rank is the whole authority model: you act only on people of strictly
// lower rank (Super Admins are peers), you assign only roles below your own,
// and you grant only what you hold. Reserved permissions come only from the
// Super Admin's '*' (A §9).

import { PERMISSION_KEYS, PERMISSION_BY_KEY, RESERVED, DANGER, SUPER_RANK } from './catalog.js';
import { GuardError, ValidationError, stepUpRequired } from './errors.js';
import { now, toInt, toNum, parseIsoStrict, MINUTE } from './util.js';

export const SUPER_ROLE_KEY = 'super_admin';

const STEP_UP_DEFAULT_MINUTES = 15;
// What an unreadable step_up_minutes means (§5: unrecognised → 5).
const STEP_UP_UNREADABLE_MINUTES = 5;

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function isCatalogKey(k) {
  return typeof k === 'string' && Object.hasOwn(PERMISSION_BY_KEY, k);
}

function isGrantable(k) {
  return isCatalogKey(k) && !RESERVED.has(k);
}

// A stored JSON list → { list } or { unreadable: true }. Absent is an empty
// list; present-but-unparseable is a different thing (A §14.3).
function readList(raw) {
  if (raw === undefined || raw === null) return { list: [] };
  let v = raw;
  if (typeof raw === 'string') {
    try {
      v = JSON.parse(raw);
    } catch {
      return { unreadable: true };
    }
  }
  return Array.isArray(v) ? { list: v } : { unreadable: true };
}

// '*' is honoured ONLY on the seeded system role 'super_admin' (keys are
// unique, so no custom role can take that name). A custom role whose stored
// permissions contain '*' gets nothing from it.
export function isSuperRole(row) {
  if (!row || row.key !== SUPER_ROLE_KEY || toInt(row.is_system) !== 1) return false;
  const { list } = readList(row.permissions);
  return !!list && list.includes('*');
}

// Non-super roles are capped below SUPER_RANK: a tampered rank of 100+ would
// otherwise outrank the owner. Unreadable or out of range → 0.
function roleRank(row) {
  if (isSuperRole(row)) return SUPER_RANK;
  const r = toInt(row?.rank, 0, SUPER_RANK - 1);
  return Number.isFinite(r) ? r : 0;
}

function roleGrants(row) {
  const { list } = readList(row?.permissions);
  return (list || []).filter(isGrantable);
}

// NULL = permanent. An unreadable expiry is expired (fail closed).
function tempRoleActive(expiresAt, nowMs) {
  if (expiresAt === null || expiresAt === undefined) return true;
  const ms = parseIsoStrict(expiresAt);
  return Number.isFinite(ms) && finite(nowMs) && ms > nowMs;
}

function emptyAuthz(userId = null) {
  return { userId, isSuper: false, rank: 0, role: null, perms: new Set(), sources: {}, denied: new Set() };
}

// perm_grants unparseable → no grants. perm_denies unparseable (or holding a
// non-string, or '*') → deny EVERYTHING: a deny list we cannot read might
// have been the only thing standing between this account and a permission.
export async function effectivePermissions(env, user, nowMs) {
  if (!user || typeof user !== 'object') return emptyAuthz();
  const id = toInt(user.id, 1);
  const authz = emptyAuthz(Number.isFinite(id) ? id : null);
  const t = finite(nowMs) ? nowMs : now(env);
  const roleId = toInt(user.role_id, 1);
  if (!Number.isFinite(roleId)) return authz;

  const db = env.DB;
  const [roleRow, temp] = await Promise.all([
    db.prepare('SELECT id, key, name, rank, permissions, is_system FROM roles WHERE id = ?').bind(roleId).first(),
    authz.userId === null
      ? { results: [] }
      : db
          .prepare(
            `SELECT r.id, r.key, r.name, r.rank, r.permissions, r.is_system, ur.expires_at
             FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ?`,
          )
          .bind(authz.userId)
          .all(),
  ]);
  // A role row that has vanished grants nothing at all, not even flags.
  if (!roleRow) return authz;

  // First source wins, most durable first: account > role > temp_role > flag.
  const sources = {};
  const add = (k, src) => {
    if (!Object.hasOwn(sources, k)) sources[k] = src;
  };

  authz.role = { id: roleRow.id, key: roleRow.key, name: roleRow.name, rank: roleRank(roleRow) };
  let rank = authz.role.rank;
  if (isSuperRole(roleRow)) {
    authz.isSuper = true;
    for (const k of PERMISSION_KEYS) add(k, 'account');
  } else {
    for (const k of roleGrants(roleRow)) add(k, 'role');
  }

  for (const row of temp?.results || []) {
    if (!tempRoleActive(row.expires_at, t)) continue;
    rank = Math.max(rank, roleRank(row));
    if (isSuperRole(row)) {
      authz.isSuper = true;
      for (const k of PERMISSION_KEYS) add(k, 'temp_role');
    } else {
      for (const k of roleGrants(row)) add(k, 'temp_role');
    }
  }
  authz.rank = rank;

  const grants = readList(user.perm_grants);
  for (const k of grants.list || []) if (isGrantable(k)) add(k, 'flag');

  const denies = readList(user.perm_denies);
  const denyAll = !!denies.unreadable || denies.list.some((k) => typeof k !== 'string' || k === '*');
  const denySet = new Set(denyAll ? [] : denies.list);

  // Denies beat grants, from every source.
  for (const k of PERMISSION_KEYS) {
    if (!Object.hasOwn(sources, k)) continue;
    if (denyAll || denySet.has(k)) {
      authz.denied.add(k);
      continue;
    }
    authz.perms.add(k);
    authz.sources[k] = sources[k];
  }
  return authz;
}

// Loads the user, then effectivePermissions. null when there is no such user.
export async function userAuthz(env, userId, nowMs) {
  const id = toInt(userId, 1);
  if (!Number.isFinite(id)) return null;
  const user = await env.DB.prepare('SELECT id, role_id, perm_grants, perm_denies, status FROM users WHERE id = ?').bind(id).first();
  return user ? effectivePermissions(env, user, nowMs) : null;
}

export function can(authz, perm) {
  return !!authz && authz.perms instanceof Set && typeof perm === 'string' && authz.perms.has(perm);
}

export function canAll(authz, perms) {
  if (typeof perms === 'string') return can(authz, perms);
  return Array.isArray(perms) && perms.every((p) => can(authz, p));
}

export function routeNeedsStepUp(perm) {
  const list = typeof perm === 'string' ? [perm] : Array.isArray(perm) ? perm : [];
  return list.some((k) => typeof k === 'string' && DANGER.has(k));
}

// A dangerous action needs a second factor within step_up_minutes (B §4.4).
export function requireStepUp(rc) {
  const s = rc?.session;
  const t = finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
  const configured = rc?.policy?.step_up_minutes;
  let minutes = STEP_UP_DEFAULT_MINUTES;
  if (configured !== undefined && configured !== null) {
    const m = toInt(configured, 1, 120);
    minutes = Number.isFinite(m) ? m : STEP_UP_UNREADABLE_MINUTES;
  }
  const mfaAt = parseIsoStrict(s?.mfa_at);
  // A step-up stamped in the future (a moved clock, a restore) is not fresh
  // forever; allow a minute of skew and no more.
  const fresh = !!s && s.aal === 2 && Number.isFinite(mfaAt) && mfaAt <= t + MINUTE && t - mfaAt <= minutes * MINUTE;
  if (!fresh) throw stepUpRequired();
}

export function assertCanActOn(actorAuthz, targetAuthz, { allowSelf = false } = {}) {
  if (!actorAuthz || !targetAuthz) throw new GuardError('rank', 'You can only act on people ranked below you.');
  if (actorAuthz.userId !== null && actorAuthz.userId !== undefined && actorAuthz.userId === targetAuthz.userId) {
    if (allowSelf === true) return;
    throw new GuardError('rank', 'You can’t do that to your own account.');
  }
  // Super Admins are peers; the last-superuser guard protects the final one.
  if (actorAuthz.isSuper === true && targetAuthz.isSuper === true) return;
  const a = toNum(actorAuthz.rank);
  const b = toNum(targetAuthz.rank);
  if (Number.isFinite(a) && Number.isFinite(b) && a > b) return;
  throw new GuardError('rank', 'You can only act on people ranked below you.');
}

// role: a roles row (permissions as stored JSON) or { rank, key, permissions: [] }.
export function assertCanAssignRole(actorAuthz, role) {
  if (!actorAuthz || !role || typeof role !== 'object') throw new GuardError('minting', 'You can only assign roles ranked below your own.');
  const perms = readList(role.permissions);
  // Unreadable permissions might be anything, so only a Super Admin may hand them out.
  const holdsEverything = role.key === SUPER_ROLE_KEY || !!perms.unreadable || perms.list.includes('*');
  if (actorAuthz.isSuper === true) return;
  if (holdsEverything) throw new GuardError('minting', 'Only a Super Admin can assign that role.');
  // An unreadable rank is refused, not read as 0.
  const r = toInt(role.rank, 0, SUPER_RANK);
  const a = toNum(actorAuthz.rank);
  if (!(Number.isFinite(r) && Number.isFinite(a) && r < a)) {
    throw new GuardError('minting', 'You can only assign roles ranked below your own.');
  }
  // B §4 guard 2: nor a role that carries a permission you do not hold.
  for (const k of perms.list) {
    if (isGrantable(k) && !can(actorAuthz, k)) throw new GuardError('minting', 'That role grants permissions you don’t hold yourself.');
  }
}

export function assertCanGrantPerms(actorAuthz, perms) {
  if (!Array.isArray(perms)) throw new ValidationError('Permissions must be a list.', 'perm_grants');
  for (const k of perms) {
    if (typeof k !== 'string') throw new ValidationError('Unknown permission.', 'perm_grants');
    if (k === '*' || RESERVED.has(k)) throw new GuardError('reserved', `Nobody can be granted “${k}”.`);
    if (!isCatalogKey(k)) throw new ValidationError(`Unknown permission “${k.slice(0, 64)}”.`, 'perm_grants');
    if (!can(actorAuthz, k)) throw new GuardError('minting', 'You can’t grant a permission you don’t hold.');
  }
}

// Catalogue keys only, no '*', no reserved. Returns them deduplicated in
// catalogue order.
export function validateRolePermissions(perms) {
  if (!Array.isArray(perms)) throw new ValidationError('Permissions must be a list.', 'permissions');
  const seen = new Set();
  for (const k of perms) {
    if (k === '*') throw new ValidationError('A role can’t hold every permission.', 'permissions');
    if (!isCatalogKey(k)) throw new ValidationError('Unknown permission.', 'permissions');
    if (RESERVED.has(k)) throw new ValidationError(`A role can’t include the reserved permission “${k}”.`, 'permissions');
    seen.add(k);
  }
  return PERMISSION_KEYS.filter((k) => seen.has(k));
}

// Active users who are Super Admin by role, or by an unexpired temporary role.
async function activeSuperIds(env, nowMs) {
  const db = env.DB;
  const [viaRole, viaTemp] = await Promise.all([
    db
      .prepare(
        `SELECT u.id, r.key, r.permissions, r.is_system FROM users u JOIN roles r ON r.id = u.role_id
         WHERE u.status = 'active' AND r.key = ?`,
      )
      .bind(SUPER_ROLE_KEY)
      .all(),
    db
      .prepare(
        `SELECT u.id, r.key, r.permissions, r.is_system, ur.expires_at FROM user_roles ur
         JOIN users u ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id
         WHERE u.status = 'active' AND r.key = ?`,
      )
      .bind(SUPER_ROLE_KEY)
      .all(),
  ]);
  // Only PERMANENT Super Admins count as owners who will remain: by role, or
  // by a temporary-role row with no expiry. A timed grant lapses on its own,
  // so counting it would let the last permanent owner be demoted while a
  // week-long grant exists — and a week later nobody holds '*'.
  const ids = new Set();
  for (const row of viaRole.results) if (isSuperRole(row)) ids.add(row.id);
  for (const row of viaTemp.results) if (isSuperRole(row) && row.expires_at === null && tempRoleActive(row.expires_at, nowMs)) ids.add(row.id);
  return ids;
}

// The one last-superuser guard (A §14.8, B §4.3). Call BEFORE any change that
// could leave the target not an active Super Admin. Counts permanent Super
// Admins only (see activeSuperIds); a target who is super only through a timed
// grant is never "the last". Fails CLOSED: if the count cannot be read, the
// change is refused.
export async function assertNotLastSuper(env, targetUserId, nowMs) {
  const unsure = () => new GuardError('last_superuser', 'Couldn’t confirm another Super Admin would remain, so nothing was changed.');
  const target = toInt(targetUserId, 1);
  if (!Number.isFinite(target) || !finite(nowMs)) throw unsure();
  let supers;
  try {
    supers = await activeSuperIds(env, nowMs);
  } catch (e) {
    console.error('rbac: Super Admin count unreadable; refusing:', e && e.message);
    throw unsure();
  }
  if (supers.has(target) && supers.size <= 1) {
    throw new GuardError('last_superuser', 'That would leave no active Super Admin. Make someone else a Super Admin first.');
  }
}
