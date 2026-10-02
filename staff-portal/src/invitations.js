// Invitations and access requests (CONTRACTS §7.7, SPEC §6.7–6.8, D11).
//
// An invitation is a 256-bit random token in a link; the database keeps only
// its SHA-256. Seven days, single use, revocable, and a new one revokes the
// earlier ones. Accepting it sets the person's own password, activates the
// account and approves the device it was accepted on — the invitation IS the
// administrator's approval. Email is the API's business: the link always
// works without it.

import { now, iso, toInt, str, strStrict, normEmail, parseIsoStrict, randomToken, DAY } from './util.js';
import { sha256Hex, hashPassword } from './crypto.js';
import { HttpError, ValidationError, forbidden, notFound, tooMany } from './errors.js';
import { effectivePermissions, assertCanActOn, userAuthz } from './rbac.js';
import { charge } from './ratelimit.js';
import { getUser, createUser, validatePassword, actorAuthz } from './users.js';

export const INVITE_TTL_MS = 7 * DAY;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const REQUEST_STATUSES = Object.freeze(['pending', 'approved', 'denied']);
const REASON_MAX = 1000;

function finite(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function nowOf(rc) {
  return finite(rc?.nowMs) ? rc.nowMs : now(rc?.env);
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function invalidLink() {
  return new HttpError(404, { error: 'This invitation link is no longer valid. Ask for a new one.', code: 'invitation_invalid' });
}

function inviteUrl(env, token) {
  let origin = '';
  try {
    const u = new URL(typeof env?.ORIGIN === 'string' ? env.ORIGIN : '');
    if (u.protocol === 'https:' || u.protocol === 'http:') origin = u.origin;
  } catch {
    /* no configured origin: a relative link still works when pasted on the portal */
  }
  return `${origin}/invite?token=${token}`;
}

function invitationState(row, nowMs) {
  if (row.used_at !== null && row.used_at !== undefined) return 'used';
  if (row.revoked_at !== null && row.revoked_at !== undefined) return 'revoked';
  const exp = parseIsoStrict(row.expires_at);
  return Number.isFinite(exp) && exp > nowMs ? 'pending' : 'expired';
}

// ---------------------------------------------------------------- invitations

// The invitee must still be 'invited', and the actor must outrank them (a
// manager cannot reissue an administrator's link). The email and role come
// from the account itself, never from the caller. → { id, token, url,
// expires_at }; the token exists only in this return value.
export async function createInvitation(rc, userId, _opts = {}) {
  const env = rc.env;
  const t = nowOf(rc);
  const actor = await actorAuthz(rc);
  const user = await getUser(env, userId);
  if (!user) throw notFound('No such person.');
  if (user.status !== 'invited') {
    throw new HttpError(409, { error: 'That account has already been set up, so it doesn’t need an invitation.', code: 'not_invited' });
  }
  assertCanActOn(actor, await effectivePermissions(env, user, t));
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  const at = iso(t);
  const expiresAt = iso(t + INVITE_TTL_MS);
  const db = env.DB;
  const [, ins] = await db.batch([
    db.prepare('UPDATE invitations SET revoked_at = ? WHERE user_id = ? AND used_at IS NULL AND revoked_at IS NULL').bind(at, user.id),
    db
      .prepare(
        `INSERT INTO invitations (token_hash, user_id, email, role_id, created_by, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(tokenHash, user.id, user.email, user.role_id, actor.userId, at, expiresAt),
  ]);
  return { id: ins.meta.last_row_id, token, url: inviteUrl(env, token), expires_at: expiresAt };
}

// Unused, unrevoked, unexpired, for an account still 'invited'. A malformed
// token is refused before it is hashed or reaches a query.
export async function lookupInvitation(env, token, nowMs) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
  const t = finite(nowMs) ? nowMs : now(env);
  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE token_hash = ?').bind(await sha256Hex(token)).first();
  if (!inv || invitationState(inv, t) !== 'pending') return null;
  const user = await getUser(env, inv.user_id);
  if (!user || user.status !== 'invited') return null;
  const { token_hash: _hidden, ...invitation } = inv;
  return { invitation, user };
}

// The claim is one conditional UPDATE (used_at IS NULL), so a double submit
// activates once. The account and the device are written only after the
// claim is known to be ours. rc.device is minted by the API beforehand; a
// blocked device stays blocked.
export async function acceptInvitation(rc, token, input = {}) {
  const env = rc.env;
  const t = nowOf(rc);
  const found = await lookupInvitation(env, token, t);
  if (!found) throw invalidLink();
  const { invitation, user } = found;
  const body = isPlainObject(input) ? input : {};
  validatePassword(body.password, { email: user.email, username: user.username });
  let fullName = null;
  if (body.full_name !== undefined && body.full_name !== null) {
    if (typeof body.full_name !== 'string') throw new ValidationError('Enter your full name.', 'full_name');
    if (body.full_name.trim()) {
      fullName = strStrict(body.full_name, 1, 200);
      if (!fullName) throw new ValidationError('Enter your full name (up to 200 characters).', 'full_name');
    }
  }
  const h = await hashPassword(env, body.password);
  const at = iso(t);
  const db = env.DB;
  const claim = await db
    .prepare('UPDATE invitations SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?')
    .bind(at, invitation.id, at)
    .run();
  if (claim.meta.changes !== 1) throw invalidLink();

  const deviceId = typeof rc.device?.id === 'string' && rc.device.id ? rc.device.id : null;
  const stmts = [
    db
      .prepare(
        `UPDATE users SET password_hash = ?, password_salt = ?, password_algo = ?, password_iters = ?, status = 'active',
           full_name = COALESCE(?, full_name), must_change_password = 0, failed_logins = 0, locked_until = NULL, updated_at = ?
         WHERE id = ? AND status = 'invited'`,
      )
      .bind(h.hash, h.salt, h.algo, h.iters, fullName, at, user.id),
  ];
  if (deviceId) {
    stmts.push(
      db
        .prepare(
          `UPDATE devices SET status = 'approved', approved_by = ?, approved_at = ?
           WHERE id = ? AND status = 'pending' AND EXISTS (SELECT 1 FROM users WHERE id = ? AND status = 'active')`,
        )
        .bind(invitation.created_by ?? null, at, deviceId, user.id),
    );
  }
  let activated;
  try {
    [activated] = await db.batch(stmts);
  } catch (e) {
    // Give the link back so the person can retry; the real error propagates.
    await db.prepare('UPDATE invitations SET used_at = NULL WHERE id = ? AND used_at = ?').bind(invitation.id, at).run().catch(() => {});
    throw e;
  }
  // Disabled between the lookup and now: the link stays spent.
  if (activated.meta.changes !== 1) throw invalidLink();
  return getUser(env, user.id);
}

export async function revokeInvitation(rc, invitationId) {
  const env = rc.env;
  const t = nowOf(rc);
  const id = toInt(invitationId, 1);
  if (!Number.isFinite(id)) throw notFound('No such invitation.');
  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE id = ?').bind(id).first();
  if (!inv) throw notFound('No such invitation.');
  const actor = await actorAuthz(rc);
  const target = await userAuthz(env, inv.user_id, t);
  if (target) assertCanActOn(actor, target);
  else if (!actor.isSuper) throw forbidden();
  const res = await env.DB.prepare('UPDATE invitations SET revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL')
    .bind(iso(t), id)
    .run();
  if (res.meta.changes !== 1) {
    throw new HttpError(409, { error: 'That invitation has already been used or revoked.', code: 'invitation_closed' });
  }
  const { token_hash: _hidden, ...row } = (await env.DB.prepare('SELECT * FROM invitations WHERE id = ?').bind(id).first()) || {};
  return { row };
}

export async function reissueInvitation(rc, userId) {
  return createInvitation(rc, userId);
}

// Never token material.
export async function listInvitations(env, opts = {}) {
  const pending = opts?.pending === true;
  const t = now(env);
  const { results } = await env.DB.prepare(
    `SELECT i.id, i.user_id, i.email, i.role_id, i.created_by, i.created_at, i.expires_at, i.used_at, i.revoked_at,
            u.full_name, u.status AS user_status, r.name AS role_name
     FROM invitations i LEFT JOIN users u ON u.id = i.user_id LEFT JOIN roles r ON r.id = i.role_id
     ${pending ? 'WHERE i.used_at IS NULL AND i.revoked_at IS NULL' : ''}
     ORDER BY i.id DESC LIMIT 500`,
  ).all();
  const rows = results.map((r) => ({ ...r, state: invitationState(r, t) }));
  return pending ? rows.filter((r) => r.state === 'pending') : rows;
}

// ---------------------------------------------------------------- access requests

// Charged to request_ip before anything is read (A §6). The reply is
// { ok: true } whatever happened to the email: the code never asks whether
// it belongs to someone, so no branch can leak it. A second pending request
// for the same address is not stored twice. The evidence a reviewer needs —
// address, country, visitor, risk — is recorded with it.
export async function createAccessRequest(rc, input) {
  const env = rc.env;
  const t = nowOf(rc);
  const ip = typeof rc.ip === 'string' && rc.ip ? rc.ip.slice(0, 64) : null;
  const lim = await charge(env, 'request_ip', ip ?? '?', t);
  if (!lim.allowed) throw tooMany(lim.retryAfterSec);
  const body = isPlainObject(input) ? input : {};
  const email = normEmail(body.email);
  if (!email || typeof body.email !== 'string') throw new ValidationError('Enter a valid email address.', 'email');
  const fullName = strStrict(body.full_name, 1, 200);
  if (!fullName) throw new ValidationError('Enter your full name.', 'full_name');
  let reason = null;
  if (body.reason !== undefined && body.reason !== null) {
    if (typeof body.reason !== 'string' || body.reason.trim().length > REASON_MAX) {
      throw new ValidationError('Keep the reason under 1,000 characters.', 'reason');
    }
    reason = body.reason.trim() || null;
  }
  const country = typeof rc.cf?.country === 'string' && /^[A-Z0-9]{2}$/.test(rc.cf.country) ? rc.cf.country : null;
  const visitor = typeof rc.fp?.hash === 'string' && /^[0-9a-f]{16,128}$/.test(rc.fp.hash) ? rc.fp.hash : null;
  const risk = toInt(rc.gate?.risk?.score, 0, 100);
  await env.DB.prepare(
    `INSERT INTO access_requests (email, full_name, reason, ip, country, visitor_id, risk, status, created_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, 'pending', ?
     WHERE NOT EXISTS (SELECT 1 FROM access_requests WHERE email = ? AND status = 'pending')`,
  )
    .bind(email, fullName, reason, ip, country, visitor, Number.isFinite(risk) ? risk : null, iso(t), email)
    .run();
  return { ok: true };
}

export async function listAccessRequests(env, opts = {}) {
  const filter = REQUEST_STATUSES.includes(opts?.status) ? opts.status : null;
  const { results } = await env.DB.prepare(
    `SELECT * FROM access_requests WHERE (? IS NULL OR status = ?) ORDER BY created_at DESC, id DESC LIMIT 500`,
  )
    .bind(filter, filter)
    .all();
  return results;
}

async function pendingRequest(env, id) {
  const rid = toInt(id, 1);
  if (!Number.isFinite(rid)) throw notFound('No such request.');
  const req = await env.DB.prepare('SELECT * FROM access_requests WHERE id = ?').bind(rid).first();
  if (!req) throw notFound('No such request.');
  if (req.status !== 'pending') throw new HttpError(409, { error: 'That request has already been decided.', code: 'request_decided' });
  return req;
}

// createUser carries the minting guard: the approver can only grant a role
// below their own. A duplicate email surfaces as createUser's 409 sentence.
export async function approveAccessRequest(rc, id, opts = {}) {
  const env = rc.env;
  const req = await pendingRequest(env, id);
  const roleId = isPlainObject(opts) ? opts.role_id : undefined;
  const name = strStrict(req.full_name, 1, 200) ?? str(String(req.email).split('@')[0], 200);
  const user = await createUser(rc, { email: req.email, full_name: name, role_id: roleId });
  const invitation = await createInvitation(rc, user.id);
  const actor = await actorAuthz(rc);
  await env.DB.prepare(
    `UPDATE access_requests SET status = 'approved', decided_by = ?, decided_at = ?, invitation_id = ?
     WHERE id = ? AND status = 'pending'`,
  )
    .bind(actor.userId, iso(nowOf(rc)), invitation.id, req.id)
    .run();
  return { user, invitation };
}

export async function denyAccessRequest(rc, id) {
  const env = rc.env;
  const req = await pendingRequest(env, id);
  const actor = await actorAuthz(rc);
  const res = await env.DB.prepare(
    "UPDATE access_requests SET status = 'denied', decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
  )
    .bind(actor.userId, iso(nowOf(rc)), req.id)
    .run();
  if (res.meta.changes !== 1) throw new HttpError(409, { error: 'That request has already been decided.', code: 'request_decided' });
}
