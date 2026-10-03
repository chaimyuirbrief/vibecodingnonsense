// The admin console's people, roles, devices, sessions, streaks and audit
// routes (CONTRACTS §8.4 "Admin"; A §7.5, §9; B §4, §7, traps 5 and 10).
//
// Guards live in the domain functions (users.js, devices.js, factors.js, …)
// so the reverters re-run them (B trap 5); the handler checks the route's
// permission, calls the domain function, and writes the audit row with the
// undo snapshot built from the returned prior state (CONTRACTS §4.2). Where a
// domain function has no account guard of its own (reset-mfa, sign-outs,
// destinations, streaks), assertActOnUser supplies it — for the handler and
// the reverter alike.
//
// Role CRUD has no other home, so its domain functions are here, exported for
// reverters.js. (The import cycle with reverters.js is safe: both sides only
// use the other's function declarations at call time.)

import { json, readJson, iso, now, toInt, str, strStrict, safeJsonParse, parseIsoStrict, MINUTE, DAY } from '../util.js';
import { HttpError, GuardError, ValidationError, forbidden, notFound } from '../errors.js';
import { PERMISSIONS, SYSTEM_ROLES, SUPER_RANK } from '../catalog.js';
import {
  can, effectivePermissions, assertCanActOn, assertCanAssignRole, validateRolePermissions, requireStepUp, roleCarriesDanger,
} from '../rbac.js';
import { audit, auditError, listAudit, getAuditEntry, verifyChain } from '../audit.js';
import { undoFor } from '../undo.js';
import {
  getUser, listUsers, publicUser, createUser, updateProfile, setStatus, changeRole, grantTempRole, revokeTempRole, adminResetPassword, actorAuthz,
} from '../users.js';
import {
  createInvitation, reissueInvitation, revokeInvitation, listInvitations, listAccessRequests, approveAccessRequest, denyAccessRequest,
} from '../invitations.js';
import { revokeSession, revokeUserSessions, findSessionByRef } from '../sessions.js';
import { listDevices, setDeviceStatus, renameDevice, revokeDevice, deviceCode, deviceState, normalizeDeviceCode } from '../devices.js';
import { streakConfig, streakStatus, getStreak, adjustStreak, STREAK_FIELDS } from '../streak.js';
import { userFactors, resetFactors } from '../mfa/factors.js';
import { listDestinations, addDestination, removeDestination, destinationHint } from '../mfa/otp.js';
import { emailConfigured, sendEmail } from '../notify.js';
import { listAllowed, listBlocked } from '../network.js';
import { ADMIN_CONSOLE_PERMS } from '../pages.js';
import { REVERTERS } from '../reverters.js';
import { orgName } from './auth.js';

const ROLE_KEY_RE = /^[a-z][a-z0-9_]{1,31}$/;
const SYSTEM_KEYS = new Set(SYSTEM_ROLES.map((r) => r.key));
const ROLE_NAME_MAX = 60;
const ROLE_DESC_MAX = 200;
const REASON_MAX = 200;

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

async function body(rc) {
  return (await readJson(rc.request)) || {};
}

function requireAny(rc, perms) {
  if (!perms.some((p) => can(rc.authz, p))) throw forbidden();
}

function userTarget(id) {
  return { type: 'user', id };
}

// Guard refusals are recorded as 'denied'; anything unexpected as the real
// error at critical severity, then one polite sentence (B trap 2).
async function writing(rc, action, target, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof GuardError) {
      await audit(rc, { action, outcome: 'denied', target, detail: `Refused: ${e.message}` });
      throw e;
    }
    if (e instanceof HttpError) throw e;
    await auditError(rc, action, e, { target });
    throw new HttpError(500, { error: 'That couldn’t be done. The details are in the audit log.' });
  }
}

// The account guard for actions whose domain function has none: the
// permission (denies apply even to a Super Admin), never yourself unless
// allowed, and strictly lower rank (Super Admins are peers). Used by the
// handlers and the reverters alike (B trap 5).
export async function assertActOnUser(rc, userId, { perm = null, allowSelf = false } = {}) {
  const actor = await actorAuthz(rc);
  if (perm && !can(actor, perm)) throw forbidden();
  const row = await getUser(rc.env, userId);
  if (!row) throw notFound('No such person.');
  const target = await effectivePermissions(rc.env, row, nowOf(rc));
  assertCanActOn(actor, target, { allowSelf });
  return { actor, row, target };
}

async function roleRow(env, id) {
  const n = toInt(id, 1);
  return Number.isFinite(n) ? env.DB.prepare('SELECT * FROM roles WHERE id = ?').bind(n).first() : null;
}

async function roleByKey(env, key) {
  return env.DB.prepare('SELECT * FROM roles WHERE key = ?').bind(key).first();
}

// `locked` is for administrators (CONTRACTS §4.5), not a manager's team view.
async function userView(env, row, nowMs, { withLocked = true } = {}) {
  const role = await roleRow(env, row.role_id);
  return publicUser(row, role, { withLocked, nowMs });
}

// An invitation link goes by email too when a provider is configured (D11);
// the link itself is the deliverable either way.
async function emailInvitation(rc, to, name, inv) {
  if (!emailConfigured(rc.env)) return false;
  const org = orgName(rc.env);
  const r = await sendEmail(
    rc.env,
    to,
    `You’re invited to ${org}`,
    `Hello ${str(name, 200) || 'there'},\n\nYou’ve been invited to the ${org} staff portal. Open this link to choose your password:\n\n${inv.url}\n\nThe link works once and expires ${inv.expires_at}.`,
  );
  return r.sent === true;
}

function invitationOut(inv) {
  return { url: inv.url, expires_at: inv.expires_at };
}

// ---------------------------------------------------------------- overview

async function count(env, sql, ...args) {
  const n = toInt(await env.DB.prepare(sql).bind(...args).first('n'), 0);
  return Number.isFinite(n) ? n : 0;
}

// The streak is decoration (SPEC §10.16, §16.38): a broken streaks table must
// not take the admin overview or a person's panel — suspend, reset, sign out —
// down with it. The read answers null and the real error goes to the audit
// log, at most once per isolate per ten minutes (the log is never trimmed).
const STREAK_ERROR_AUDIT_EVERY_MS = 10 * MINUTE;
let lastStreakErrorAuditMs = -Infinity;

async function streakOrNull(rc, read, target) {
  try {
    return await read();
  } catch (e) {
    console.error('[streak] read failed:', e && e.message);
    if (rc.nowMs - lastStreakErrorAuditMs >= STREAK_ERROR_AUDIT_EVERY_MS || rc.nowMs < lastStreakErrorAuditMs) {
      lastStreakErrorAuditMs = rc.nowMs;
      await auditError(rc, 'streak.error', e, { target, detail: 'Could not read the streak; the page was served without it.' });
    }
    return null;
  }
}

// Only the counts this caller may see (CONTRACTS §8.4).
async function overview(rc) {
  requireAny(rc, ADMIN_CONSOLE_PERMS);
  const env = rc.env;
  const a = rc.authz;
  const t = rc.nowMs;
  const counts = {};
  if (can(a, 'users.view')) {
    const { results } = await env.DB.prepare('SELECT status, COUNT(*) AS n FROM users GROUP BY status').all();
    for (const s of ['active', 'invited', 'suspended', 'disabled']) counts[`users_${s}`] = toInt(results.find((r) => r.status === s)?.n, 0) || 0;
  } else if (can(a, 'team.view')) {
    counts.team_reports = await count(env, "SELECT COUNT(*) AS n FROM users WHERE manager_id = ? AND status != 'disabled'", rc.user.id);
  }
  if (can(a, 'devices.view')) {
    for (const s of ['pending', 'approved', 'blocked']) counts[`devices_${s}`] = await count(env, 'SELECT COUNT(*) AS n FROM devices WHERE status = ?', s);
  }
  if (can(a, 'requests.manage')) counts.requests_pending = await count(env, "SELECT COUNT(*) AS n FROM access_requests WHERE status = 'pending'");
  if (can(a, 'users.invite')) {
    counts.invitations_pending = await count(env, 'SELECT COUNT(*) AS n FROM invitations WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?', iso(t));
  }
  if (can(a, 'sessions.view')) {
    counts.sessions_active = await count(
      env,
      'SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?',
      iso(t),
      iso(t),
    );
  }
  if (can(a, 'network.view')) {
    counts.allow_entries = (await listAllowed(env, t)).filter((r) => r.active).length;
    counts.block_entries = (await listBlocked(env, t)).filter((r) => r.active).length;
  }
  if (can(a, 'visitors.view')) {
    counts.visitors_24h = await count(env, 'SELECT COUNT(DISTINCT ip) AS n FROM visits WHERE at > ?', iso(t - DAY));
    counts.denied_24h = await count(env, "SELECT COUNT(*) AS n FROM visits WHERE at > ? AND decision = 'none'", iso(t - DAY));
  }
  if (can(a, 'streaks.view_all')) {
    const cfg = streakConfig(rc.policy);
    counts.streaks_active = await streakOrNull(rc, async () => {
      const { results } = await env.DB.prepare("SELECT s.* FROM streaks s JOIN users u ON u.id = s.user_id WHERE u.status = 'active'").all();
      return results.filter((r) => streakStatus(r, t, cfg).current > 0).length;
    }, null);
  }
  const out = { counts };
  if (can(a, 'audit.view')) {
    counts.audit_entries = await count(env, 'SELECT COUNT(*) AS n FROM audit_log');
    out.recent_audit = (await listAudit(env, { limit: 10 })).entries;
  }
  if (can(a, 'settings.view') || can(a, 'gate.open')) {
    const g = rc.policy?.gate_open;
    out.gate = { open: g?.open === true, until: finite(g?.until) ? iso(g.until) : null, forever: g?.forever === true };
  }
  return json(200, out);
}

async function directory(rc) {
  const { results } = await rc.env.DB.prepare(
    `SELECT id, full_name, email, username, employee_no, job_title, department, manager_id FROM users
     WHERE status = 'active' ORDER BY full_name COLLATE NOCASE, id LIMIT 2000`,
  ).all();
  return json(200, { people: results });
}

// ---------------------------------------------------------------- people

// users.view sees everyone; team.view alone sees only direct reports.
async function listPeople(rc) {
  requireAny(rc, ['users.view', 'team.view']);
  const all = can(rc.authz, 'users.view');
  const sp = rc.url.searchParams;
  const me = toInt(rc.user?.id, 1);
  // A team view with no readable caller id would be an unfiltered list.
  if (!all && !Number.isFinite(me)) return json(200, { users: [], total: 0, scope: 'team' });
  const r = await listUsers(rc.env, {
    status: sp.get('status'),
    q: sp.get('q'),
    role: all ? sp.get('role') : null,
    managerId: all ? sp.get('manager') : me,
    limit: sp.get('limit'),
    offset: sp.get('offset'),
    withLocked: all,
    nowMs: rc.nowMs,
  });
  return json(200, { ...r, scope: all ? 'all' : 'team' });
}

async function tempRolesOf(env, userId, nowMs) {
  const { results } = await env.DB.prepare(
    `SELECT ur.role_id, ur.expires_at, ur.granted_by, ur.created_at, r.key, r.name, r.rank FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY ur.created_at`,
  )
    .bind(userId)
    .all();
  // An unreadable expiry has expired (rbac reads it the same way).
  return results.map((r) => ({
    role_id: r.role_id,
    role: { id: r.role_id, key: r.key, name: r.name, rank: r.rank },
    expires_at: r.expires_at,
    granted_by: r.granted_by,
    active: r.expires_at === null || parseIsoStrict(r.expires_at) > nowMs,
  }));
}

async function getPerson(rc, params) {
  requireAny(rc, ['users.view', 'team.view']);
  const env = rc.env;
  const t = rc.nowMs;
  const all = can(rc.authz, 'users.view');
  const row = await getUser(env, params.id);
  if (!row || (!all && row.manager_id !== rc.user.id)) throw notFound('No such person.');
  const cfg = streakConfig(rc.policy);
  const streak = cfg.enabled ? await streakOrNull(rc, () => getStreak(env, row.id, t, cfg), userTarget(row.id)) : null;
  const user = await userView(env, row, t, { withLocked: all });
  if (!all) return json(200, { user, streak, scope: 'team' });
  const authz = await effectivePermissions(env, row, t);
  let invitation = null;
  if (row.status === 'invited') {
    invitation = await env.DB.prepare(
      'SELECT id, created_at, expires_at FROM invitations WHERE user_id = ? AND used_at IS NULL AND revoked_at IS NULL ORDER BY id DESC LIMIT 1',
    )
      .bind(row.id)
      .first();
  }
  return json(200, {
    user,
    permissions: [...authz.perms].sort(),
    sources: authz.sources,
    denied: [...authz.denied].sort(),
    rank: authz.rank,
    is_super: authz.isSuper === true,
    perm_grants: safeJsonParse(row.perm_grants, null),
    perm_denies: safeJsonParse(row.perm_denies, null),
    temp_roles: await tempRolesOf(env, row.id, t),
    factors: await userFactors(env, row.id),
    streak,
    invitation: invitation ?? null,
    scope: 'all',
  });
}

// An ABSENT role_id means the employee role: a manager cannot list roles.
// Anything present — null and '' included — must name a role (A §14.1).
async function defaultRoleId(env, given) {
  if (given !== undefined) return given;
  const r = await roleByKey(env, 'employee');
  return r ? r.id : null;
}

// Minting an account hands out its role. Giving an existing person a role
// that carries a danger permission takes users.roles and a fresh step-up, so
// creating a person with one — an invitation, an approved access request, or
// a new link for someone still invited — takes the step-up too (SPEC §5.5,
// §7.9); otherwise a stale session mints a Super Admin. A role that does not
// exist is left to createUser to refuse.
async function requireStepUpToMint(rc, roleId, invitee = null) {
  const rid = toInt(roleId, 1);
  if (!Number.isFinite(rid)) return;
  const role = await rc.env.DB.prepare('SELECT id, key, rank, permissions, is_system FROM roles WHERE id = ?').bind(rid).first();
  if (!role || !roleCarriesDanger(role)) return;
  // Someone who may not hand this out at all is told that, not "confirm it's you".
  const actor = await actorAuthz(rc);
  if (invitee) assertCanActOn(actor, await effectivePermissions(rc.env, invitee, rc.nowMs));
  else assertCanAssignRole(actor, role);
  requireStepUp(rc);
}

async function invite(rc) {
  const b = await body(rc);
  const roleId = await defaultRoleId(rc.env, b.role_id);
  return writing(rc, 'user.invite', null, async () => {
    await requireStepUpToMint(rc, roleId);
    const user = await createUser(rc, {
      email: b.email,
      full_name: b.full_name,
      role_id: roleId,
      username: b.username,
      employee_no: b.employee_no,
      job_title: b.job_title,
      department: b.department,
      manager_id: b.manager_id,
    });
    const inv = await createInvitation(rc, user.id);
    const emailed = await emailInvitation(rc, user.email, user.full_name, inv);
    await audit(rc, {
      action: 'user.invite',
      target: userTarget(user.id),
      detail: `Invited ${user.email} (${user.employee_no})${emailed ? '; the link was emailed' : ''}`,
      after: { email: user.email, role_id: user.role_id, status: user.status },
    });
    return json(200, { ok: true, user: await userView(rc.env, user, rc.nowMs), invitation: invitationOut(inv), emailed });
  });
}

async function editPerson(rc, params) {
  const b = await body(rc);
  return writing(rc, 'user.edit', userTarget(String(params.id)), async () => {
    const { prior, row } = await updateProfile(rc, params.id, b);
    const fields = Object.keys(prior);
    if (fields.length) {
      await audit(rc, {
        action: 'user.edit',
        target: userTarget(row.id),
        detail: `Edited ${row.email}: ${fields.join(', ')}`,
        before: prior,
        after: Object.fromEntries(fields.map((k) => [k, row[k] ?? null])),
        undo: undoFor('user.profile', { userId: row.id, fields: prior }),
      });
    }
    return json(200, { ok: true, changed: fields, user: await userView(rc.env, row, rc.nowMs) });
  });
}

const STATUS_VERB = { active: 'Reinstated', suspended: 'Suspended', disabled: 'Disabled', invited: 'Re-invited' };

// users.suspend for active↔suspended, users.disable for disabled↔active —
// setStatus checks the exact one; both are danger, so the step-up is here.
async function postStatus(rc, params) {
  requireAny(rc, ['users.suspend', 'users.disable']);
  requireStepUp(rc);
  const b = await body(rc);
  return writing(rc, 'user.status', userTarget(String(params.id)), async () => {
    const { prior, row } = await setStatus(rc, params.id, b.status);
    await audit(rc, {
      action: 'user.status',
      target: userTarget(row.id),
      severity: row.status === 'active' ? 'info' : 'notice',
      detail: `${STATUS_VERB[row.status] || 'Changed'} ${row.email}`,
      before: { status: prior.status },
      after: { status: row.status },
      undo: undoFor('user.status', { userId: row.id, status: prior.status }),
    });
    return json(200, { ok: true, user: await userView(rc.env, row, rc.nowMs) });
  });
}

async function postRole(rc, params) {
  const b = await body(rc);
  return writing(rc, 'user.role', userTarget(String(params.id)), async () => {
    const { prior, row } = await changeRole(rc, params.id, { role_id: b.role_id, perm_grants: b.perm_grants, perm_denies: b.perm_denies });
    const role = await roleRow(rc.env, row.role_id);
    await audit(rc, {
      action: 'user.role',
      target: userTarget(row.id),
      severity: 'notice',
      detail: `Changed ${row.email}’s role and permissions (now ${role?.name ?? row.role_id})`,
      before: prior,
      after: { role_id: row.role_id, perm_grants: safeJsonParse(row.perm_grants, null), perm_denies: safeJsonParse(row.perm_denies, null) },
      undo: undoFor('user.role', { userId: row.id, ...prior }),
    });
    return json(200, { ok: true, user: await userView(rc.env, row, rc.nowMs) });
  });
}

async function postTempRole(rc, params) {
  const b = await body(rc);
  return writing(rc, 'user.temp_role.grant', userTarget(String(params.id)), async () => {
    const { prior, row } = await grantTempRole(rc, params.id, b.role_id, b.expires_at);
    const role = await roleRow(rc.env, row.role_id);
    await audit(rc, {
      action: 'user.temp_role.grant',
      target: userTarget(row.user_id),
      severity: 'notice',
      detail: `Granted ${role?.name ?? `role ${row.role_id}`} until ${row.expires_at}`,
      before: prior,
      after: { role_id: row.role_id, expires_at: row.expires_at },
      undo: undoFor('user.temp_role', { userId: row.user_id, roleId: row.role_id, prior }),
    });
    return json(200, { ok: true, temp_role: row });
  });
}

async function deleteTempRole(rc, params) {
  return writing(rc, 'user.temp_role.revoke', userTarget(String(params.id)), async () => {
    const roleId = toInt(params.roleId, 1);
    const { prior } = await revokeTempRole(rc, params.id, roleId);
    const role = await roleRow(rc.env, roleId);
    const uid = toInt(params.id, 1);
    await audit(rc, {
      action: 'user.temp_role.revoke',
      target: userTarget(uid),
      severity: 'notice',
      detail: `Revoked the temporary ${role?.name ?? `role ${roleId}`} role`,
      before: prior,
      undo: undoFor('user.temp_role', { userId: uid, roleId, prior }),
    });
    return json(200, { ok: true });
  });
}

// Not revertible: restoring an old hash restores a credential (SPEC §11.4).
async function resetPassword(rc, params) {
  return writing(rc, 'password.reset', userTarget(String(params.id)), async () => {
    const { temporary_password } = await adminResetPassword(rc, params.id);
    const row = await getUser(rc.env, params.id);
    await audit(rc, {
      action: 'password.reset',
      target: userTarget(row.id),
      severity: 'notice',
      detail: `Reset ${row.email}’s password; their sessions were ended and the next sign-in must choose a new one`,
    });
    return json(200, { ok: true, temporary_password });
  });
}

// A §7.5 "I've lost my phone". The snapshot (TOTP still encrypted, passkeys,
// backup hashes, grace) is the undo payload — server-only, never returned.
async function resetMfa(rc, params) {
  return writing(rc, 'mfa.reset', userTarget(String(params.id)), async () => {
    const { row } = await assertActOnUser(rc, params.id, { perm: 'users.reset_mfa' });
    const { cleared, prior } = await resetFactors(rc, row.id);
    await audit(rc, {
      action: 'mfa.reset',
      target: userTarget(row.id),
      severity: 'notice',
      detail: `Cleared ${row.email}’s second factors (authenticator: ${cleared.totp ? 'yes' : 'no'}, passkeys: ${cleared.passkeys}, backup codes: ${cleared.backup}) and grace windows`,
      after: { cleared },
      undo: undoFor('mfa.reset', prior),
    });
    return json(200, { ok: true, cleared });
  });
}

async function logoutPerson(rc, params) {
  return writing(rc, 'user.sessions_revoked', userTarget(String(params.id)), async () => {
    const { row } = await assertActOnUser(rc, params.id, { perm: 'users.suspend' });
    const n = await revokeUserSessions(rc.env, row.id, 'admin_logout');
    await audit(rc, { action: 'user.sessions_revoked', target: userTarget(row.id), detail: `Signed ${row.email} out everywhere (${n} session${n === 1 ? '' : 's'})` });
    return json(200, { ok: true, revoked: n });
  });
}

// Every device they used goes back to pending (a blocked one stays blocked),
// their grace windows go, their sessions end. The caller's own device is
// skipped: revoking it would lock the caller out (B trap 8).
async function revokePersonDevices(rc, params) {
  return writing(rc, 'user.devices_revoked', userTarget(String(params.id)), async () => {
    const { row } = await assertActOnUser(rc, params.id, { perm: 'users.suspend' });
    const env = rc.env;
    const { results } = await env.DB.prepare('SELECT device_id FROM device_users WHERE user_id = ?').bind(row.id).all();
    let revoked = 0;
    let skipped = 0;
    for (const { device_id } of results) {
      if (device_id === rc.device?.id) {
        skipped++;
        continue;
      }
      try {
        await revokeDevice(rc, device_id);
        revoked++;
      } catch (e) {
        if (!(e instanceof HttpError)) throw e;
        skipped++;
      }
    }
    await env.DB.batch([
      env.DB.prepare('DELETE FROM mfa_grace WHERE user_id = ?').bind(row.id),
      env.DB.prepare("UPDATE sessions SET revoked_at = ?, revoke_reason = 'devices_revoked' WHERE user_id = ? AND revoked_at IS NULL").bind(iso(rc.nowMs), row.id),
    ]);
    await audit(rc, {
      action: 'user.devices_revoked',
      target: userTarget(row.id),
      severity: 'notice',
      detail: `Revoked ${revoked} of ${row.email}’s devices${skipped ? ` (${skipped} left alone: the device you are using is never revoked here)` : ''}; their sessions and grace windows were dropped`,
    });
    return json(200, { ok: true, revoked, skipped });
  });
}

// ---------------------------------------------------------------- destinations

async function getDestinations(rc, params) {
  const { row } = await assertActOnUser(rc, params.id, { perm: 'destinations.manage', allowSelf: true });
  return json(200, { destinations: await listDestinations(rc.env, row.id) });
}

// Adding one is handing out a second factor (A §9), so it is reserved; the
// audit row carries the masked hint, never the address.
async function postDestination(rc, params) {
  const b = await body(rc);
  return writing(rc, 'user.destination.add', userTarget(String(params.id)), async () => {
    const { row: user } = await assertActOnUser(rc, params.id, { perm: 'destinations.manage', allowSelf: true });
    const row = await addDestination(rc, user.id, { kind: b.kind, address: b.address, label: b.label });
    const hint = destinationHint(row);
    await audit(rc, {
      action: 'user.destination.add',
      target: userTarget(user.id),
      severity: 'notice',
      detail: `Added ${row.kind === 'sms' ? 'a phone number' : 'an email address'} (${hint}) for ${user.email}’s sign-in codes`,
      after: { id: row.id, kind: row.kind, hint },
      undo: undoFor('destination.add', { userId: user.id, id: row.id }),
    });
    return json(200, { ok: true, destination: { id: row.id, kind: row.kind, hint, label: row.label ?? null, is_primary: row.is_primary === 1 } });
  });
}

async function deleteDestination(rc, params) {
  return writing(rc, 'user.destination.remove', userTarget(String(params.id)), async () => {
    const { row: user } = await assertActOnUser(rc, params.id, { perm: 'destinations.manage', allowSelf: true });
    const { row } = await removeDestination(rc, user.id, params.did);
    const hint = destinationHint(row);
    await audit(rc, {
      action: 'user.destination.remove',
      target: userTarget(user.id),
      severity: 'notice',
      detail: `Removed ${hint} from ${user.email}’s sign-in code destinations`,
      before: { id: row.id, kind: row.kind, hint },
      undo: undoFor('destination.remove', { userId: user.id, row }),
    });
    return json(200, { ok: true });
  });
}

async function reissue(rc, params) {
  return writing(rc, 'invitation.reissue', userTarget(String(params.id)), async () => {
    const invitee = await getUser(rc.env, params.id);
    if (invitee) await requireStepUpToMint(rc, invitee.role_id, invitee);
    const inv = await reissueInvitation(rc, params.id);
    const row = await getUser(rc.env, params.id);
    const emailed = await emailInvitation(rc, row.email, row.full_name, inv);
    await audit(rc, { action: 'invitation.reissue', target: userTarget(row.id), detail: `Reissued ${row.email}’s invitation${emailed ? '; the link was emailed' : ''}` });
    return json(200, { ok: true, ...invitationOut(inv), invitation: invitationOut(inv), emailed });
  });
}

// SPEC §10.18: a reason is required; the prior row is the undo snapshot.
async function postStreak(rc, params) {
  const b = await body(rc);
  const reason = strStrict(b.reason, 1, REASON_MAX);
  if (reason === null) throw new ValidationError('Say why — it goes in the audit log.', 'reason');
  return writing(rc, 'streak.adjust', userTarget(String(params.id)), async () => {
    const { row: user } = await assertActOnUser(rc, params.id, { perm: 'streaks.manage' });
    const cfg = streakConfig(rc.policy);
    const { prior, row } = await adjustStreak(rc.env, user.id, { current: b.current, longest: b.longest }, rc.nowMs, cfg);
    await audit(rc, {
      action: 'streak.adjust',
      target: userTarget(user.id),
      severity: 'notice',
      detail: `Set ${user.email}’s streak to ${row.current} (longest ${row.longest}): ${reason}`,
      before: prior ? { current: prior.current, longest: prior.longest } : null,
      after: { current: row.current, longest: row.longest },
      // `wrote`: what this adjustment left, so a revert can tell whether the
      // person has signed in since (and refuse rather than wipe those days).
      undo: undoFor('streak', { userId: user.id, prior, wrote: Object.fromEntries(STREAK_FIELDS.map((k) => [k, row[k] ?? null])) }),
    });
    return json(200, { ok: true, streak: streakStatus(row, rc.nowMs, cfg) });
  });
}

// ---------------------------------------------------------------- invitations, requests

async function getInvitations(rc) {
  return json(200, { invitations: await listInvitations(rc.env, { pending: rc.url.searchParams.get('pending') === '1' }) });
}

async function postRevokeInvitation(rc, params) {
  return writing(rc, 'invitation.revoke', { type: 'invitation', id: str(params.id, 20) }, async () => {
    const { row } = await revokeInvitation(rc, params.id);
    await audit(rc, { action: 'invitation.revoke', target: userTarget(row.user_id), detail: `Revoked the invitation for ${row.email}` });
    return json(200, { ok: true });
  });
}

async function getRequests(rc) {
  const s = rc.url.searchParams.get('status');
  return json(200, { requests: await listAccessRequests(rc.env, { status: s }) });
}

async function approveRequest(rc, params) {
  const b = await body(rc);
  const roleId = await defaultRoleId(rc.env, b.role_id);
  return writing(rc, 'request.approve', { type: 'access_request', id: str(params.id, 20) }, async () => {
    await requireStepUpToMint(rc, roleId);
    const { user, invitation } = await approveAccessRequest(rc, params.id, { role_id: roleId });
    const emailed = await emailInvitation(rc, user.email, user.full_name, invitation);
    await audit(rc, {
      action: 'request.approve',
      target: userTarget(user.id),
      detail: `Approved ${user.email}’s access request and invited them${emailed ? '; the link was emailed' : ''}`,
    });
    return json(200, { ok: true, user: await userView(rc.env, user, rc.nowMs), invitation: invitationOut(invitation), emailed });
  });
}

async function denyRequest(rc, params) {
  return writing(rc, 'request.deny', { type: 'access_request', id: str(params.id, 20) }, async () => {
    await denyAccessRequest(rc, params.id);
    await audit(rc, { action: 'request.deny', target: { type: 'access_request', id: str(params.id, 20) }, detail: 'Denied an access request' });
    return json(200, { ok: true });
  });
}

// ---------------------------------------------------------------- roles (domain)

function roleList(raw) {
  const v = typeof raw === 'string' ? safeJsonParse(raw, null) : raw;
  return Array.isArray(v) ? v : null;
}

function parseRoleName(v) {
  const s = strStrict(v, 1, ROLE_NAME_MAX);
  if (s === null) throw new ValidationError(`A role needs a name of 1 to ${ROLE_NAME_MAX} characters.`, 'name');
  return s;
}

// A §14.1: '' and booleans are refused before coercion; 1–99 (100 is the owner's).
function parseRoleRank(v) {
  const n = typeof v === 'number' || typeof v === 'string' ? toInt(v, 1, SUPER_RANK - 1) : NaN;
  if (!Number.isFinite(n)) throw new ValidationError(`Rank must be a whole number from 1 to ${SUPER_RANK - 1}.`, 'rank');
  return n;
}

function parseRoleDescription(v) {
  if (v === undefined || v === null || (typeof v === 'string' && v.trim() === '')) return null;
  const s = strStrict(v, 1, ROLE_DESC_MAX);
  if (s === null) throw new ValidationError(`A description is text of at most ${ROLE_DESC_MAX} characters.`, 'description');
  return s;
}

async function requireRolesManage(rc) {
  const actor = await actorAuthz(rc);
  if (!can(actor, 'roles.manage')) throw forbidden();
  return actor;
}

async function customRole(rc, id) {
  const row = await roleRow(rc.env, id);
  if (!row) throw notFound('No such role.');
  if (toInt(row.is_system) !== 0 || SYSTEM_KEYS.has(row.key)) {
    throw new GuardError('system_role', 'System roles are fixed, so every portal means the same thing by them.', 409);
  }
  return row;
}

async function freeKey(env, name) {
  let base = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 26);
  if (!/^[a-z]/.test(base)) base = `role_${base}`.slice(0, 26);
  if (base.length < 2) base = 'role';
  for (let i = 1; i < 100; i++) {
    const key = i === 1 ? base : `${base}_${i}`;
    if (!SYSTEM_KEYS.has(key) && !(await roleByKey(env, key))) return key;
  }
  throw new HttpError(409, { error: 'Choose a different name.', code: 'duplicate', field: 'name' });
}

async function holders(env, roleId) {
  return count(
    env,
    'SELECT (SELECT COUNT(*) FROM users WHERE role_id = ?) + (SELECT COUNT(*) FROM user_roles WHERE role_id = ?) AS n',
    roleId,
    roleId,
  );
}

// → { row }. roles.manage is reserved, but the minting checks run anyway so
// a revert and a future delegation hit the same wall (B trap 5).
export async function createRole(rc, input) {
  const actor = await requireRolesManage(rc);
  if (!isPlainObject(input)) throw new ValidationError('Nothing to create.');
  const name = parseRoleName(input.name);
  const rank = parseRoleRank(input.rank);
  const permissions = validateRolePermissions(input.permissions);
  const description = parseRoleDescription(input.description);
  let key;
  if (input.key !== undefined && input.key !== null) {
    if (typeof input.key !== 'string' || !ROLE_KEY_RE.test(input.key)) throw new ValidationError('A role key is 2–32 lowercase letters, digits or underscores.', 'key');
    if (SYSTEM_KEYS.has(input.key) || (await roleByKey(rc.env, input.key))) throw new HttpError(409, { error: 'A role with that key exists.', code: 'duplicate', field: 'key' });
    key = input.key;
  } else key = await freeKey(rc.env, name);
  assertCanAssignRole(actor, { key, rank, permissions });
  const at = iso(nowOf(rc));
  const row = await rc.env.DB.prepare(
    `INSERT INTO roles (key, name, rank, permissions, is_system, description, created_at, updated_at)
     VALUES (?, ?, ?, ?, 0, ?, ?, ?) RETURNING *`,
  )
    .bind(key, name, rank, JSON.stringify(permissions), description, at, at)
    .first();
  return { row };
}

// → { prior: { name, rank, permissions, description }, row }. Minting is
// checked on the role as it is AND as it will be (like users.changeRole).
export async function editRole(rc, id, patch) {
  const actor = await requireRolesManage(rc);
  if (!isPlainObject(patch)) throw new ValidationError('Nothing to change.');
  const row = await customRole(rc, id);
  const has = (k) => patch[k] !== undefined;
  if (!['name', 'rank', 'permissions', 'description'].some(has)) throw new ValidationError('Nothing to change.');
  const stored = roleList(row.permissions);
  const next = {
    name: has('name') ? parseRoleName(patch.name) : row.name,
    rank: has('rank') ? parseRoleRank(patch.rank) : row.rank,
    permissions: has('permissions') ? validateRolePermissions(patch.permissions) : stored,
    description: has('description') ? parseRoleDescription(patch.description) : row.description ?? null,
  };
  // Unreadable stored permissions are not rewritten silently: say so.
  if (next.permissions === null) throw new ValidationError('This role’s stored permissions are unreadable; send the full list.', 'permissions');
  assertCanAssignRole(actor, row);
  assertCanAssignRole(actor, { key: row.key, rank: next.rank, permissions: next.permissions });
  const res = await rc.env.DB.prepare(
    `UPDATE roles SET name = ?, rank = ?, permissions = ?, description = ?, updated_at = ?
     WHERE id = ? AND is_system = 0 AND updated_at IS ? RETURNING *`,
  )
    .bind(next.name, next.rank, JSON.stringify(next.permissions), next.description, iso(nowOf(rc)), row.id, row.updated_at)
    .first();
  if (!res) throw new HttpError(409, { error: 'Someone changed this role at the same moment. Reload and try again.', code: 'conflict' });
  const prior = { name: row.name, rank: row.rank, permissions: stored ?? row.permissions, description: row.description ?? null };
  return { prior, row: res };
}

// → { row } (as stored: the 'role.delete' undo payload). Refused while anyone
// holds it, permanently or for a while; the DELETE re-checks in one statement.
export async function deleteRole(rc, id) {
  await requireRolesManage(rc);
  const row = await customRole(rc, id);
  const n = await holders(rc.env, row.id);
  const inUse = (k) => new GuardError('role_in_use', `${k === 1 ? 'Someone holds' : `${k} people hold`} this role. Move them to another role first.`, 409);
  if (n > 0) throw inUse(n);
  const res = await rc.env.DB.prepare(
    `DELETE FROM roles WHERE id = ? AND is_system = 0
       AND NOT EXISTS (SELECT 1 FROM users WHERE role_id = ?) AND NOT EXISTS (SELECT 1 FROM user_roles WHERE role_id = ?)`,
  )
    .bind(row.id, row.id, row.id)
    .run();
  if (res.meta.changes !== 1) throw inUse(await holders(rc.env, row.id));
  return { row };
}

// The 'role.delete' reverter's half: recreate with the same key (and id, if
// still free), through the same validation and minting checks.
export async function recreateRole(rc, snapshot) {
  const actor = await requireRolesManage(rc);
  if (!isPlainObject(snapshot)) throw new ValidationError('That role snapshot is unreadable.');
  const key = snapshot.key;
  if (typeof key !== 'string' || !ROLE_KEY_RE.test(key) || SYSTEM_KEYS.has(key)) throw new ValidationError('That role snapshot is unreadable.');
  const name = parseRoleName(snapshot.name);
  const rank = parseRoleRank(snapshot.rank);
  const list = roleList(snapshot.permissions);
  if (list === null) throw new ValidationError('That role snapshot is unreadable.');
  const permissions = validateRolePermissions(list);
  const description = parseRoleDescription(snapshot.description);
  assertCanAssignRole(actor, { key, rank, permissions });
  if (await roleByKey(rc.env, key)) throw new HttpError(409, { error: 'A role with that key exists again.', code: 'duplicate' });
  const id = toInt(snapshot.id, 1);
  const free = Number.isFinite(id) && !(await roleRow(rc.env, id));
  const at = iso(nowOf(rc));
  const created = Number.isFinite(parseIsoStrict(snapshot.created_at)) ? snapshot.created_at : at;
  const row = await rc.env.DB.prepare(
    `INSERT INTO roles (${free ? 'id, ' : ''}key, name, rank, permissions, is_system, description, created_at, updated_at)
     VALUES (${free ? '?, ' : ''}?, ?, ?, ?, 0, ?, ?, ?) RETURNING *`,
  )
    .bind(...(free ? [id] : []), key, name, rank, JSON.stringify(permissions), description, created, at)
    .first();
  return { row };
}

function roleView(r, n) {
  const list = roleList(r.permissions);
  return {
    id: r.id,
    key: r.key,
    name: r.name,
    rank: r.rank,
    permissions: list ?? [],
    description: r.description ?? null,
    is_system: toInt(r.is_system) === 1,
    system: toInt(r.is_system) === 1,
    holders: n,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

// ---------------------------------------------------------------- roles (routes)

async function getRoles(rc) {
  const { results } = await rc.env.DB.prepare(
    `SELECT r.*, (SELECT COUNT(*) FROM users u WHERE u.role_id = r.id) + (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id = r.id) AS n
     FROM roles r ORDER BY r.rank DESC, r.id`,
  ).all();
  return json(200, { roles: results.map((r) => roleView(r, toInt(r.n, 0) || 0)) });
}

async function getPermissions() {
  return json(200, {
    permissions: PERMISSIONS.map((p) => ({ key: p.key, group: p.group, label: p.label, danger: p.danger === true, reserved: p.reserved === true })),
  });
}

async function postRoleDef(rc) {
  const b = await body(rc);
  return writing(rc, 'role.create', null, async () => {
    const { row } = await createRole(rc, b);
    await audit(rc, {
      action: 'role.create',
      target: { type: 'role', id: row.id },
      severity: 'notice',
      detail: `Created the role ${row.name} (rank ${row.rank})`,
      after: roleView(row, 0),
      undo: undoFor('role.create', { roleId: row.id }),
    });
    return json(200, { ok: true, role: roleView(row, 0) });
  });
}

async function patchRoleDef(rc, params) {
  const b = await body(rc);
  return writing(rc, 'role.edit', { type: 'role', id: str(params.id, 20) }, async () => {
    const { prior, row } = await editRole(rc, params.id, b);
    await audit(rc, {
      action: 'role.edit',
      target: { type: 'role', id: row.id },
      severity: 'notice',
      detail: `Edited the role ${row.name}`,
      before: prior,
      after: { name: row.name, rank: row.rank, permissions: roleList(row.permissions), description: row.description ?? null },
      undo: undoFor('role.edit', { roleId: row.id, prior }),
    });
    return json(200, { ok: true, role: roleView(row, await holders(rc.env, row.id)) });
  });
}

async function deleteRoleDef(rc, params) {
  return writing(rc, 'role.delete', { type: 'role', id: str(params.id, 20) }, async () => {
    const { row } = await deleteRole(rc, params.id);
    await audit(rc, {
      action: 'role.delete',
      target: { type: 'role', id: row.id },
      severity: 'notice',
      detail: `Deleted the role ${row.name}`,
      before: roleView(row, 0),
      undo: undoFor('role.delete', { row }),
    });
    return json(200, { ok: true });
  });
}

// ---------------------------------------------------------------- devices

// The code is what approves a waiting device (POST /api/me/devices/approve
// takes it from anyone with an approved device and a step-up), so only a
// caller who may approve devices sees it — never a read-only role (§16.19).
function deviceView(d, showCode) {
  return {
    id: d.id,
    code: showCode ? d.code ?? null : null,
    status: deviceState(d),
    label: d.label ?? null,
    ua: d.ua ?? null,
    platform: d.platform ?? null,
    ip: d.last_ip ?? null,
    first_ip: d.first_ip ?? null,
    created_at: d.first_seen ?? null,
    last_seen_at: d.last_seen ?? null,
    approved_at: d.approved_at ?? null,
    approved_by: d.approved_by ?? null,
    blocked_at: d.blocked_at ?? null,
    users: Array.isArray(d.users) ? d.users : [],
  };
}

async function getDevices(rc) {
  const s = rc.url.searchParams.get('status');
  const rows = await listDevices(rc.env, { status: s === null || s === '' ? undefined : s, limit: 500 });
  const showCode = can(rc.authz, 'devices.approve');
  return json(200, { devices: rows.map((d) => deviceView(d, showCode)) });
}

function deviceTarget(id) {
  return { type: 'device', id: str(id, 128) };
}

const DEVICE_ACTIONS = {
  approve: { status: 'approved', action: 'device.approve', verb: 'Approved' },
  block: { status: 'blocked', action: 'device.block', verb: 'Blocked' },
  unblock: { status: 'pending', action: 'device.unblock', verb: 'Unblocked' },
};

function deviceStatusRoute(kind) {
  const d = DEVICE_ACTIONS[kind];
  return async (rc, params) => {
    const b = await body(rc);
    return writing(rc, d.action, deviceTarget(params.id), async () => {
      // The console approves by the code the waiting device shows; a code
      // that does not name THIS device is refused rather than trusted.
      if (kind === 'approve' && b.code !== undefined) {
        const want = normalizeDeviceCode(b.code);
        if (!want || want !== (await deviceCode(params.id))) {
          throw new HttpError(409, { error: 'That code doesn’t match this device. Check it with the person.', code: 'code_mismatch' });
        }
      }
      if (kind === 'unblock') {
        const cur = await rc.env.DB.prepare('SELECT status FROM devices WHERE id = ?').bind(str(params.id, 128)).first();
        if (cur && cur.status !== 'blocked') throw new HttpError(409, { error: 'That device isn’t blocked.', code: 'not_blocked' });
      }
      // devices.approve approves WAITING devices. Lifting a block is
      // devices.manage's (…/unblock), so approve never reaches past one.
      if (kind === 'approve') {
        const cur = await rc.env.DB.prepare('SELECT status FROM devices WHERE id = ?').bind(str(params.id, 128)).first();
        if (cur && cur.status !== 'pending') throw new HttpError(409, { error: 'That device isn’t waiting for approval.', code: 'not_pending' });
      }
      const { prior, row } = await setDeviceStatus(rc, params.id, d.status, {});
      await audit(rc, {
        action: d.action,
        target: deviceTarget(row.id),
        severity: kind === 'block' ? 'notice' : 'info',
        detail: `${d.verb} ${row.label || 'a device'}${kind === 'block' ? '; its sessions ended and its grace windows were dropped' : ''}`,
        before: { status: prior.status },
        after: { status: row.status },
        undo: undoFor('device.status', { deviceId: row.id, status: prior.status }),
      });
      return json(200, { ok: true, device: { id: row.id, label: row.label ?? null, status: deviceState(row) } });
    });
  };
}

async function postRenameDevice(rc, params) {
  const b = await body(rc);
  return writing(rc, 'device.rename', deviceTarget(params.id), async () => {
    const { prior, row } = await renameDevice(rc, params.id, b.label);
    await audit(rc, {
      action: 'device.rename',
      target: deviceTarget(row.id),
      detail: `Renamed a device from “${prior.label ?? 'unnamed'}” to “${row.label}”`,
      before: { label: prior.label ?? null },
      after: { label: row.label },
      undo: undoFor('device.label', { deviceId: row.id, label: prior.label ?? null }),
    });
    return json(200, { ok: true });
  });
}

async function deleteDevice(rc, params) {
  return writing(rc, 'device.revoke', deviceTarget(params.id), async () => {
    const before = await rc.env.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(str(params.id, 128)).first();
    if (!before) throw notFound('No such device.');
    await revokeDevice(rc, before.id);
    const after = await rc.env.DB.prepare('SELECT status FROM devices WHERE id = ?').bind(before.id).first();
    const changed = after && after.status !== before.status;
    await audit(rc, {
      action: 'device.revoke',
      target: deviceTarget(before.id),
      detail: `Revoked ${before.label || 'a device'}: back to waiting for approval; its sessions ended and its grace windows were dropped`,
      before: { status: before.status },
      after: { status: after?.status ?? null },
      undo: changed ? undoFor('device.status', { deviceId: before.id, status: before.status }) : undefined,
    });
    return json(200, { ok: true });
  });
}

// ---------------------------------------------------------------- sessions

async function getSessions(rc) {
  const t = iso(rc.nowMs);
  const { results } = await rc.env.DB.prepare(
    `SELECT s.id, s.user_id, s.device_id, s.created_at, s.last_seen_at, s.ip, s.ua, s.aal, u.full_name, u.email
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.revoked_at IS NULL AND s.idle_expires_at > ? AND s.absolute_expires_at > ?
     ORDER BY s.last_seen_at DESC LIMIT 1000`,
  )
    .bind(t, t)
    .all();
  // id_ref only: the stored hash itself never leaves (CONTRACTS §7.7).
  const sessions = results.map((s) => ({
    id_ref: String(s.id).slice(0, 12),
    user_id: s.user_id,
    user: { id: s.user_id, full_name: s.full_name, email: s.email },
    full_name: s.full_name,
    email: s.email,
    device_id: s.device_id ?? null,
    created_at: s.created_at,
    last_seen_at: s.last_seen_at,
    ip: s.ip ?? null,
    ua: s.ua ?? null,
    aal: toInt(s.aal, 1, 2) === 2 ? 2 : 1,
    current: s.id === rc.session?.id,
  }));
  return json(200, { sessions });
}

async function deleteSession(rc, params) {
  const s = await findSessionByRef(rc.env, params.ref);
  if (!s || s.revoked_at) throw notFound('No such session.');
  return writing(rc, 'session.revoke', userTarget(s.user_id), async () => {
    // Your own sessions are ended from your account page (A §9: nobody
    // force-logs-out themselves from the console).
    const { row } = await assertActOnUser(rc, s.user_id, { perm: 'sessions.revoke' });
    await revokeSession(rc.env, s.id, 'admin_revoked');
    await audit(rc, { action: 'session.revoke', target: userTarget(row.id), detail: `Ended one of ${row.email}’s sessions` });
    return json(200, { ok: true });
  });
}

// ---------------------------------------------------------------- streaks

async function getStreaks(rc) {
  requireAny(rc, ['streaks.view_all', 'team.view']);
  const all = can(rc.authz, 'streaks.view_all');
  const me = toInt(rc.user?.id, 1);
  if (!all && !Number.isFinite(me)) return json(200, { streaks: [], scope: 'team' });
  const cfg = streakConfig(rc.policy);
  const { results } = await rc.env.DB.prepare(
    `SELECT u.id AS uid, u.full_name, u.email, u.manager_id, s.user_id, s.current, s.longest, s.total_days, s.started_day,
            s.last_day, s.last_at, s.updated_at
     FROM users u LEFT JOIN streaks s ON s.user_id = u.id
     WHERE u.status = 'active' AND (? IS NULL OR u.manager_id = ?) ORDER BY u.full_name COLLATE NOCASE, u.id LIMIT 5000`,
  )
    .bind(all ? null : me, all ? null : me)
    .all();
  const streaks = results.map((r) => ({
    user_id: r.uid,
    full_name: r.full_name,
    email: r.email,
    ...streakStatus(r.user_id === null ? null : r, rc.nowMs, cfg),
  }));
  return json(200, { streaks, scope: all ? 'all' : 'team', enabled: cfg.enabled });
}

// ---------------------------------------------------------------- audit

function revertibleKinds() {
  return new Set(Object.keys(REVERTERS));
}

async function getAudit(rc) {
  const sp = rc.url.searchParams;
  const filters = {};
  for (const k of ['action', 'actor', 'target_type', 'target_id', 'outcome', 'severity', 'q', 'before_seq', 'limit']) {
    const v = sp.get(k);
    if (v !== null) filters[k] = v;
  }
  return json(200, await listAudit(rc.env, filters, { canRevert: can(rc.authz, 'audit.revert'), revertibleKinds: revertibleKinds() }));
}

async function postVerify(rc) {
  const r = await verifyChain(rc.env);
  await audit(rc, {
    action: 'audit.verify',
    outcome: r.ok ? 'success' : 'failure',
    severity: r.ok ? 'info' : 'critical',
    detail: r.ok ? `Verified the audit chain: intact across ${r.checked} entries` : `The audit chain is broken at entry #${r.broken_at.seq} (${r.broken_at.reason})`,
  });
  return json(200, r);
}

// One new 'audit.revert' row pointing at the original (D10); the reverter
// re-runs every guard the original ran (B trap 5). Refusals are recorded as
// 'denied' with the same pointer, which the derived "reverted" ignores.
async function postRevert(rc, params) {
  const entry = await getAuditEntry(rc.env, params.id);
  if (!entry) throw notFound('No such audit entry.');
  const target = entry.target_type ? { type: entry.target_type, id: entry.target_id } : null;
  const refuse = (code, message) => new GuardError(code, message, 409);
  try {
    if (entry.action === 'audit.revert') throw refuse('not_revertible', 'A revert can’t itself be reverted. Make the change again instead.');
    if (entry.reverted_by !== null) throw refuse('already_reverted', `Entry #${entry.seq} was already reverted (by entry ${entry.reverted_by}).`);
    if (entry.outcome !== 'success') throw refuse('not_revertible', 'Only a change that succeeded can be reverted.');
    if (entry.undo_unreadable) throw refuse('undo_unreadable', 'Its saved copy of the earlier state is unreadable, so it can’t be reverted.');
    const kind = entry.undo_kind;
    if (typeof kind !== 'string' || entry.undo_payload === null || !Object.hasOwn(REVERTERS, kind)) {
      throw refuse('not_revertible', 'That entry has nothing that can be put back.');
    }
    const out = await REVERTERS[kind](rc, entry.undo_payload, entry);
    const row = await audit(rc, {
      action: 'audit.revert',
      target,
      severity: 'notice',
      detail: `Reverted entry #${entry.seq} (${entry.action}): ${out.detail}`,
      // What the revert overwrote and what it left, when the reverter says.
      before: out.before,
      after: out.after,
      revertsId: entry.id,
    });
    return json(200, { ok: true, reverted: entry.id, revert_id: row ? row.id : null, detail: out.detail, notices: out.notices ?? [], warnings: out.warnings ?? [] });
  } catch (e) {
    if (e instanceof HttpError) {
      await audit(rc, {
        action: 'audit.revert',
        outcome: 'denied',
        target,
        detail: `Refused to revert entry #${entry.seq} (${entry.action}): ${e.message}`,
        revertsId: entry.id,
      });
      throw e;
    }
    await auditError(rc, 'audit.revert', e, { target, detail: `Reverting entry #${entry.seq} (${entry.action}) failed.`, revertsId: entry.id });
    throw new HttpError(500, { error: 'That revert couldn’t be completed. The details are in the audit log.' });
  }
}

export function register(router) {
  const any = (list) => ({ anyOf: list });
  router.add('GET', '/api/admin/overview', overview, any(ADMIN_CONSOLE_PERMS));
  router.add('GET', '/api/directory', directory, { perm: 'directory.view' });

  router.add('GET', '/api/admin/users', listPeople, any(['users.view', 'team.view']));
  router.add('POST', '/api/admin/users', invite, { perm: 'users.invite' });
  router.add('GET', '/api/admin/users/:id', getPerson, any(['users.view', 'team.view']));
  router.add('PATCH', '/api/admin/users/:id', editPerson, { perm: 'users.edit' });
  router.add('POST', '/api/admin/users/:id/status', postStatus, any(['users.suspend', 'users.disable']));
  router.add('POST', '/api/admin/users/:id/role', postRole, { perm: 'users.roles' });
  router.add('POST', '/api/admin/users/:id/temp-role', postTempRole, { perm: 'users.roles' });
  router.add('DELETE', '/api/admin/users/:id/temp-role/:roleId', deleteTempRole, { perm: 'users.roles' });
  router.add('POST', '/api/admin/users/:id/reset-password', resetPassword, { perm: 'users.reset_password' });
  router.add('POST', '/api/admin/users/:id/reset-mfa', resetMfa, { perm: 'users.reset_mfa' });
  router.add('POST', '/api/admin/users/:id/logout', logoutPerson, { perm: 'users.suspend' });
  router.add('POST', '/api/admin/users/:id/revoke-devices', revokePersonDevices, { perm: 'users.suspend' });
  router.add('GET', '/api/admin/users/:id/destinations', getDestinations, { perm: 'destinations.manage' });
  router.add('POST', '/api/admin/users/:id/destinations', postDestination, { perm: 'destinations.manage' });
  router.add('DELETE', '/api/admin/users/:id/destinations/:did', deleteDestination, { perm: 'destinations.manage' });
  router.add('POST', '/api/admin/users/:id/invitation', reissue, { perm: 'users.invite' });
  router.add('POST', '/api/admin/users/:id/streak', postStreak, { perm: 'streaks.manage' });

  router.add('GET', '/api/admin/invitations', getInvitations, { perm: 'users.invite' });
  router.add('POST', '/api/admin/invitations/:id/revoke', postRevokeInvitation, { perm: 'users.invite' });
  router.add('GET', '/api/admin/requests', getRequests, { perm: 'requests.manage' });
  router.add('POST', '/api/admin/requests/:id/approve', approveRequest, { perm: 'requests.manage' });
  router.add('POST', '/api/admin/requests/:id/deny', denyRequest, { perm: 'requests.manage' });

  router.add('GET', '/api/admin/roles', getRoles, { perm: 'roles.view' });
  router.add('GET', '/api/admin/permissions', getPermissions, { perm: 'roles.view' });
  router.add('POST', '/api/admin/roles', postRoleDef, { perm: 'roles.manage' });
  router.add('PATCH', '/api/admin/roles/:id', patchRoleDef, { perm: 'roles.manage' });
  router.add('DELETE', '/api/admin/roles/:id', deleteRoleDef, { perm: 'roles.manage' });

  router.add('GET', '/api/admin/devices', getDevices, { perm: 'devices.view' });
  router.add('POST', '/api/admin/devices/:id/approve', deviceStatusRoute('approve'), { perm: 'devices.approve' });
  router.add('POST', '/api/admin/devices/:id/block', deviceStatusRoute('block'), { perm: 'devices.manage' });
  router.add('POST', '/api/admin/devices/:id/unblock', deviceStatusRoute('unblock'), { perm: 'devices.manage' });
  router.add('POST', '/api/admin/devices/:id/rename', postRenameDevice, { perm: 'devices.manage' });
  router.add('DELETE', '/api/admin/devices/:id', deleteDevice, { perm: 'devices.manage' });

  router.add('GET', '/api/admin/sessions', getSessions, { perm: 'sessions.view' });
  router.add('DELETE', '/api/admin/sessions/:ref', deleteSession, { perm: 'sessions.revoke' });

  router.add('GET', '/api/admin/streaks', getStreaks, any(['streaks.view_all', 'team.view']));

  router.add('GET', '/api/admin/audit', getAudit, { perm: 'audit.view' });
  router.add('POST', '/api/admin/audit/verify', postVerify, { perm: 'audit.verify' });
  router.add('POST', '/api/admin/audit/:id/revert', postRevert, { perm: 'audit.revert' });
  return router;
}
