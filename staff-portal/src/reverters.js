// REVERTERS: one object whose keys ARE the undo catalogue (CONTRACTS §4.2.1,
// A §9, §14.9). The kinds that may record an undo (undo.js) and the kinds
// that can be reverted are the same set — enforced at import below, and by
// tests/unit/undo-catalogue.test.mjs scanning src/ for every undoFor call.
//
// Each reverter puts the PRIOR state back by calling the same domain
// function the original action used, so every guard runs again: rank,
// minting, last Super Admin, last factor, self-lockout (B trap 5, SPEC
// §11.5). Where a domain function checks no permission itself, the reverter
// checks the one the original route needed — a Super Admin with a deny on it
// may not revert it either. The revert endpoint writes the single
// 'audit.revert' row; a reverter only returns { detail, notices?, warnings? }.
//
// Payloads come out of storage, so they are re-validated: an unreadable one
// is refused, never guessed at (CONTRACTS §0.2).

import { GuardError, ValidationError, forbidden, notFound } from './errors.js';
import { toInt, str, safeJsonParse, parseIsoStrict } from './util.js';
import { can } from './rbac.js';
import { UNDO_KINDS } from './undo.js';
import { SETTINGS, writeSetting } from './policy.js';
import { setStatus, changeRole, grantTempRole, revokeTempRole, updateProfile, actorAuthz, TEMP_ROLE_MAX_MS } from './users.js';
import { setDeviceStatus, renameDevice } from './devices.js';
import { addAllowed, editAllowed, removeAllowed, addBlocked, removeBlocked } from './network.js';
import { restoreFactors } from './mfa/factors.js';
import { addDestination, removeDestination, destinationHint } from './mfa/otp.js';
import { restoreStreak } from './streak.js';
import { checkSettings, approveCallerDevice, assertCanRemoveAllowed, assertCanEditAllowed, assertCanBlock } from './guards.js';
import { assertActOnUser, editRole, deleteRole, recreateRole } from './api/admin.js';

function unreadable() {
  return new GuardError('undo_unreadable', 'Its saved copy of the earlier state is unreadable, so it can’t be reverted.', 409);
}

function obj(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw unreadable();
  return p;
}

// A snapshot missing a field it always records is unreadable: writing the
// gaps back as null would clear what was never captured.
function whole(p, keys) {
  const o = obj(p);
  if (!keys.every((k) => Object.hasOwn(o, k))) throw unreadable();
  return o;
}

function id(v) {
  const n = toInt(v, 1);
  if (!Number.isFinite(n)) throw unreadable();
  return n;
}

async function requirePerm(rc, perm) {
  if (!can(await actorAuthz(rc), perm)) throw forbidden();
}

async function loadById(rc, table, rowId, what) {
  const row = await rc.env.DB.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(rowId).first();
  if (!row) throw notFound(`That ${what} no longer exists.`);
  return row;
}

export const REVERTERS = Object.freeze({
  // ------------------------------------------------------------ people

  async 'user.status'(rc, payload) {
    const p = obj(payload);
    if (typeof p.status !== 'string') throw unreadable();
    const { row } = await setStatus(rc, id(p.userId), p.status);
    return { detail: `${row.email} is ${row.status} again` };
  },

  // changeRole re-runs rank (before and after), minting, the grant check and
  // the last-Super-Admin guard: someone demoted cannot revert their own
  // demotion through a low-ranked role holding audit.revert (B trap 5).
  async 'user.role'(rc, payload) {
    const p = obj(payload);
    if (!Array.isArray(p.perm_grants) || !Array.isArray(p.perm_denies)) throw unreadable();
    const { row } = await changeRole(rc, id(p.userId), { role_id: id(p.role_id), perm_grants: p.perm_grants, perm_denies: p.perm_denies });
    return { detail: `${row.email}’s role and permissions are back as they were` };
  },

  // null prior → the grant was new: revoke it. A prior grant that is still in
  // the future is granted again (minting guard included); one that had
  // already lapsed is the same as none. A permanent row, or one beyond the
  // 90-day limit, cannot go back through grantTempRole — refused.
  async 'user.temp_role'(rc, payload) {
    const p = obj(payload);
    const userId = id(p.userId);
    const roleId = id(p.roleId);
    if (p.prior === null || p.prior === undefined) {
      await revokeTempRole(rc, userId, roleId);
      return { detail: 'the temporary role was revoked again' };
    }
    const prior = obj(p.prior);
    if (prior.expires_at === null) {
      throw new GuardError('not_restorable', 'The earlier grant had no expiry; grant it again by hand if it is still wanted.', 409);
    }
    const exp = parseIsoStrict(prior.expires_at);
    if (!Number.isFinite(exp)) throw unreadable();
    if (exp <= rc.nowMs) {
      await revokeTempRole(rc, userId, roleId);
      return { detail: 'the earlier grant had already lapsed, so the role was revoked' };
    }
    if (exp > rc.nowMs + TEMP_ROLE_MAX_MS) {
      throw new GuardError('not_restorable', 'The earlier grant ran past the 90-day limit; grant it again by hand.', 409);
    }
    await grantTempRole(rc, userId, roleId, prior.expires_at);
    return { detail: `the temporary role runs until ${prior.expires_at} again` };
  },

  async 'user.profile'(rc, payload) {
    const p = obj(payload);
    const fields = obj(p.fields);
    // An empty snapshot would "revert" nothing and still mark the entry done.
    if (!Object.keys(fields).length) throw unreadable();
    const { row } = await updateProfile(rc, id(p.userId), fields);
    return { detail: `${row.email}’s ${Object.keys(fields).join(', ')} put back` };
  },

  // ------------------------------------------------------------ devices

  // setDeviceStatus refuses to block, or with gating on un-approve, the
  // device the reverter is using (B trap 8).
  async 'device.status'(rc, payload) {
    const p = obj(payload);
    if (typeof p.status !== 'string' || typeof p.deviceId !== 'string') throw unreadable();
    await requirePerm(rc, p.status === 'approved' ? 'devices.approve' : 'devices.manage');
    const { row } = await setDeviceStatus(rc, p.deviceId, p.status, {});
    return { detail: `${row.label || 'the device'} is ${row.status} again` };
  },

  async 'device.label'(rc, payload) {
    const p = obj(payload);
    if (typeof p.deviceId !== 'string' || (p.label !== null && typeof p.label !== 'string')) throw unreadable();
    await requirePerm(rc, 'devices.manage');
    if (p.label === null) {
      // renameDevice takes a name; "unnamed" is the one value it cannot set.
      const row = await rc.env.DB.prepare('SELECT id FROM devices WHERE id = ?').bind(str(p.deviceId, 128)).first();
      if (!row) throw notFound('That device no longer exists.');
      await rc.env.DB.prepare('UPDATE devices SET label = NULL WHERE id = ?').bind(row.id).run();
      return { detail: 'the device is unnamed again' };
    }
    const { row } = await renameDevice(rc, p.deviceId, p.label);
    return { detail: `the device is called “${row.label}” again` };
  },

  // ------------------------------------------------------------ network

  // Undoing an add is a removal, so it passes the same anti-lockout guards
  // as DELETE …/allow/:id (A §9, SPEC §11.5).
  async 'network.allow.add'(rc, payload) {
    const p = obj(payload);
    await requirePerm(rc, 'network.manage');
    const row = await loadById(rc, 'allowed_ips', id(p.id), 'allowlist entry');
    await assertCanRemoveAllowed(rc, row);
    await removeAllowed(rc, row.id);
    return { detail: `${row.cidr} is off the allowlist again` };
  },

  // Re-added through validation: a range that has since become refusable,
  // or an expiry that has passed, is refused rather than restored.
  async 'network.allow.remove'(rc, payload) {
    const r = obj(obj(payload).row);
    await requirePerm(rc, 'network.manage');
    const row = await addAllowed(rc, {
      cidr: r.cidr,
      tier: r.tier,
      label: r.label ?? null,
      owner: r.owner ?? null,
      user_id: r.user_id ?? null,
      expires_at: r.expires_at ?? null,
    });
    return { detail: `${row.cidr} is on the allowlist again (entry ${row.id})` };
  },

  async 'network.allow.edit'(rc, payload) {
    const p = obj(payload);
    const prior = whole(p.prior, ['tier', 'label', 'owner', 'user_id', 'expires_at']);
    await requirePerm(rc, 'network.manage');
    const row = await loadById(rc, 'allowed_ips', id(p.id), 'allowlist entry');
    const patch = {
      tier: prior.tier,
      label: prior.label ?? null,
      owner: prior.owner ?? null,
      user_id: prior.user_id ?? null,
      expires_at: prior.expires_at ?? null,
    };
    await assertCanEditAllowed(rc, row, patch);
    const { row: next } = await editAllowed(rc, row.id, patch);
    return { detail: `allowlist entry ${next.cidr} is back as it was` };
  },

  async 'network.block.add'(rc, payload) {
    const p = obj(payload);
    await requirePerm(rc, 'network.manage');
    const { row } = await removeBlocked(rc, id(p.id));
    return { detail: `${row.cidr} is no longer blocked` };
  },

  // Re-blocking passes the self-block guard (CONTRACTS §4.2.1).
  async 'network.block.remove'(rc, payload) {
    const r = obj(obj(payload).row);
    if (typeof r.cidr !== 'string') throw unreadable();
    await requirePerm(rc, 'network.manage');
    assertCanBlock(rc, r.cidr);
    const row = await addBlocked(rc, { cidr: r.cidr, reason: r.reason ?? null, expires_at: r.expires_at ?? null });
    return { detail: `${row.cidr} is blocked again` };
  },

  // ------------------------------------------------------------ settings

  // Back through validation AND the self-lockout guards (with auto-approve).
  // A prior of null means the row was absent: the default comes back.
  async setting(rc, payload) {
    const p = obj(payload);
    const key = p.key;
    if (typeof key !== 'string' || !Object.hasOwn(SETTINGS, key)) throw unreadable();
    if (key === 'gate_open') throw new GuardError('not_revertible', 'Opening or closing the gate is never reverted.', 409);
    if (p.prior !== null && typeof p.prior !== 'string') throw unreadable();
    const def = SETTINGS[key];
    await requirePerm(rc, def.perm);
    let input = null;
    let raw = null;
    if (p.prior !== null) {
      // json-list settings take the array itself, not its JSON text.
      input = def.type === 'json-list' ? safeJsonParse(p.prior, undefined) : p.prior;
      try {
        raw = def.serialize(input);
      } catch (e) {
        if (e instanceof ValidationError) throw new ValidationError(`The earlier value of ${key} would not be accepted today: ${e.message}`, key);
        throw e;
      }
    }
    const g = await checkSettings(rc, { [key]: raw });
    if (g.approve) await approveCallerDevice(rc);
    if (raw === null) await rc.env.DB.prepare('DELETE FROM settings WHERE key = ?').bind(key).run();
    else await writeSetting(rc, key, input);
    return { detail: `${key} is ${raw === null ? 'back to its default' : `${str(raw, 120)} again`}`, notices: g.notices, warnings: g.warnings };
  },

  // ------------------------------------------------------------ factors

  // Rank guard, then restoreFactors — which refuses if anything was
  // enrolled since (A §7.5).
  async 'mfa.reset'(rc, payload) {
    const p = obj(payload);
    const { row } = await assertActOnUser(rc, id(p.userId), { perm: 'users.reset_mfa' });
    await restoreFactors(rc, p);
    return { detail: `${row.email}’s second factors are restored` };
  },

  // Never the last usable factor (removeDestination → canDropFactor).
  async 'destination.add'(rc, payload) {
    const p = obj(payload);
    const { row: user } = await assertActOnUser(rc, id(p.userId), { perm: 'destinations.manage', allowSelf: true });
    const { row } = await removeDestination(rc, user.id, id(p.id));
    return { detail: `${destinationHint(row)} removed from ${user.email}’s code destinations again` };
  },

  async 'destination.remove'(rc, payload) {
    const p = obj(payload);
    const r = obj(p.row);
    const { row: user } = await assertActOnUser(rc, id(p.userId), { perm: 'destinations.manage', allowSelf: true });
    const row = await addDestination(rc, user.id, { kind: r.kind, address: r.address, label: r.label ?? undefined });
    return { detail: `${destinationHint(row)} is one of ${user.email}’s code destinations again` };
  },

  // ------------------------------------------------------------ roles

  async 'role.create'(rc, payload) {
    const { row } = await deleteRole(rc, id(obj(payload).roleId));
    return { detail: `the role ${row.name} is deleted again` };
  },

  async 'role.edit'(rc, payload) {
    const p = obj(payload);
    const prior = whole(p.prior, ['name', 'rank', 'permissions', 'description']);
    const { row } = await editRole(rc, id(p.roleId), {
      name: prior.name,
      rank: prior.rank,
      permissions: prior.permissions,
      description: prior.description ?? null,
    });
    return { detail: `the role ${row.name} is back as it was` };
  },

  async 'role.delete'(rc, payload) {
    const { row } = await recreateRole(rc, obj(payload).row);
    return { detail: `the role ${row.name} exists again (id ${row.id})` };
  },

  // ------------------------------------------------------------ streaks

  async streak(rc, payload) {
    const p = obj(payload);
    const { row: user } = await assertActOnUser(rc, id(p.userId), { perm: 'streaks.manage' });
    if (p.prior !== null && p.prior !== undefined) obj(p.prior);
    await restoreStreak(rc.env, user.id, p.prior ?? null, rc.nowMs);
    return { detail: p.prior ? `${user.email}’s streak is back to ${p.prior.current} (longest ${p.prior.longest})` : `${user.email} has no streak again` };
  },
});

// A §14.9: the catalogue and the reverters are one set, or nothing loads.
{
  const have = Object.keys(REVERTERS).sort();
  const want = [...UNDO_KINDS].sort();
  if (have.length !== want.length || have.some((k, i) => k !== want[i])) {
    const missing = want.filter((k) => !have.includes(k));
    const extra = have.filter((k) => !want.includes(k));
    throw new Error(`reverters.js: REVERTERS must match UNDO_KINDS exactly (missing: ${missing.join(', ') || '—'}; extra: ${extra.join(', ') || '—'})`);
  }
}
