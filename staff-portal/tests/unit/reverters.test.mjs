// Each reverter called directly (CONTRACTS §4.2.1; A §9; B trap 5): hostile
// payloads are refused with an HTTP error and change nothing, the original
// route's permission is re-checked (denies bind a Super Admin too), and the
// branches the HTTP suites do not reach.

import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { HttpError, GuardError, ValidationError } from '../../src/errors.js';
import { createOwner, createUser, getUser } from '../../src/users.js';
import { effectivePermissions } from '../../src/rbac.js';
import { resolvePolicy } from '../../src/policy.js';
import { addAllowed } from '../../src/network.js';
import { iso, DAY, HOUR } from '../../src/util.js';
import { REVERTERS } from '../../src/reverters.js';
import { UNDO_KINDS } from '../../src/undo.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const HOME = '81.2.69.142';
const EDGE = { country: 'US', asn: 7922, ua: 'Mozilla/5.0 (Macintosh) Chrome/129.0.0.0 Safari/537.36', accept_language: 'en' };

async function world() {
  const env = await makeEnvWithSchema();
  const owner = await createOwner(env, { email: 'owner@acme.com', full_name: 'Olive Owner', password: 'owner-password-0123' }, env.__clock());
  return { env, owner };
}

async function rcFor(env, user, extra = {}) {
  const nowMs = env.__clock();
  return {
    env, nowMs, user, authz: await effectivePermissions(env, user, nowMs), policy: await resolvePolicy(env),
    ip: HOME, edge: EDGE, fp: null, cookies: {}, device: { id: 'dev-x', row: { id: 'dev-x', status: 'approved' } }, setCookies: [], ...extra,
  };
}

function roleId(env, key) {
  return env.DB.q('SELECT id FROM roles WHERE key = ?', key)[0].id;
}

async function person(env, rc, role = 'employee', status = 'active') {
  const u = await createUser(rc, { email: `p${Math.random().toString(36).slice(2, 8)}@acme.com`, full_name: 'P', role_id: roleId(env, role) });
  env.DB.q("UPDATE users SET status = ?, password_hash = 'x' WHERE id = ?", status, u.id);
  return getUser(env, u.id);
}

function snapshot(env) {
  return JSON.stringify(['users', 'roles', 'settings', 'allowed_ips', 'blocked_ips', 'devices', 'user_roles', 'streaks', 'code_destinations', 'user_totp']
    .map((t) => env.DB.q(`SELECT * FROM ${t} ORDER BY rowid`)));
}

function show(v) {
  return typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v);
}

test('REVERTERS is the catalogue: one async function per kind', () => {
  assert.deepEqual(Object.keys(REVERTERS).sort(), [...UNDO_KINDS].sort());
  for (const k of UNDO_KINDS) assert.equal(REVERTERS[k].constructor.name, 'AsyncFunction', k);
});

test('hostile payloads — whole, and in every field — are refused with an HTTP error and change nothing', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const emp = await person(env, rc);
  const shapes = {
    'user.status': (v) => [v, { userId: v, status: 'active' }, { userId: emp.id, status: v }],
    // [] is a legal grants list, so it is not hostile there.
    'user.role': (v) => [v, { userId: emp.id, role_id: v, perm_grants: [], perm_denies: [] }, ...(Array.isArray(v) ? [] : [{ userId: emp.id, role_id: roleId(env, 'guest'), perm_grants: v, perm_denies: [] }])],
    'user.temp_role': (v) => [v, { userId: v, roleId: roleId(env, 'guest'), prior: null }, { userId: emp.id, roleId: roleId(env, 'guest'), prior: { expires_at: v } }],
    'user.profile': (v) => [v, { userId: emp.id, fields: v }, ...(v === 'abc' ? [] : [{ userId: emp.id, fields: { full_name: v } }])],
    'device.status': (v) => [v, { deviceId: v, status: 'approved' }, { deviceId: 'dev-x', status: v }],
    'device.label': (v) => [v, { deviceId: v, label: 'x' }, { deviceId: 'dev-x', label: v }],
    'network.allow.add': (v) => [v, { id: v }],
    'network.allow.remove': (v) => [v, { row: v }, { row: { cidr: v, tier: 2 } }, { row: { cidr: '185.15.56.0/24', tier: v } }],
    'network.allow.edit': (v) => [v, { id: v, prior: {} }, { id: 1, prior: v }],
    'network.block.add': (v) => [v, { id: v }],
    'network.block.remove': (v) => [v, { row: v }, { row: { cidr: v } }],
    setting: (v) => [v, { key: v, prior: null }, { key: 'step_up_minutes', prior: v }, { key: 'block_tor', prior: v }],
    // totp: null and passkeys: [] are what a reset that cleared nothing records.
    'mfa.reset': (v) => [
      v,
      { userId: v },
      ...(v === null ? [] : [{ userId: emp.id, totp: v, passkeys: [], backup: [], grace: [] }]),
      ...(Array.isArray(v) ? [] : [{ userId: emp.id, totp: null, passkeys: v, backup: [], grace: [] }]),
    ],
    'role.create': (v) => [v, { roleId: v }],
    'role.edit': (v) => [v, { roleId: v, prior: {} }, { roleId: 1, prior: v }],
    'role.delete': (v) => [v, { row: v }, ...(v === 'abc' ? [] : [{ row: { key: v, name: 'X', rank: 10, permissions: '[]' } }])],
    streak: (v) => [v, { userId: v, prior: null }, { userId: emp.id, prior: v }],
    'destination.add': (v) => [v, { userId: v, id: 1 }, { userId: emp.id, id: v }],
    'destination.remove': (v) => [v, { userId: emp.id, row: v }, { userId: emp.id, row: { kind: v, address: 'a@b.co' } }],
  };
  assert.deepEqual(Object.keys(shapes).sort(), [...UNDO_KINDS].sort());
  await addAllowed(rc, { cidr: `${HOME}/32`, tier: 1 });
  const before = snapshot(env);
  for (const [kind, make] of Object.entries(shapes)) {
    for (const v of HOSTILE) {
      for (const payload of make(v)) {
        // Some hostile fields are legitimately "absent" (prior: undefined on
        // a streak means no row); those may succeed only on a no-op.
        try {
          await REVERTERS[kind](rc, payload, { id: 1 });
        } catch (e) {
          assert.ok(e instanceof HttpError, `${kind} ${show(v)}: ${e && e.stack}`);
          continue;
        }
        assert.ok((kind === 'streak' && v === undefined) || (['streak', 'setting'].includes(kind) && v === null), `${kind} ${show(v)} succeeded`);
      }
    }
  }
  // The only successes above put an absent row (no streak, no stored
  // setting) back onto an absent row.
  assert.equal(snapshot(env), before);
});

test('the original route’s permission is re-checked: an auditor, and a Super Admin with a deny, are refused', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  await addAllowed(rc, { cidr: `${HOME}/32`, tier: 1 });
  const net = await addAllowed(rc, { cidr: '185.15.56.0/24', tier: 2 });
  const emp = await person(env, rc);
  const auditorRow = await person(env, rc, 'auditor');
  const auditor = await rcFor(env, auditorRow);
  const deniedRow = await person(env, rc, 'super_admin');
  env.DB.q('UPDATE users SET perm_denies = ? WHERE id = ?', JSON.stringify(['network.manage', 'settings.manage', 'streaks.manage', 'users.suspend', 'devices.manage', 'roles.manage', 'users.reset_mfa', 'destinations.manage', 'users.edit', 'users.roles']), deniedRow.id);
  const denied = await rcFor(env, await getUser(env, deniedRow.id));
  assert.equal(denied.authz.isSuper, true);
  const cases = [
    ['network.allow.add', { id: net.id }],
    ['network.block.add', { id: 1 }],
    ['setting', { key: 'timezone', prior: 'UTC' }],
    ['streak', { userId: emp.id, prior: null }],
    ['user.status', { userId: emp.id, status: 'suspended' }],
    ['user.profile', { userId: emp.id, fields: { full_name: 'X' } }],
    ['user.role', { userId: emp.id, role_id: roleId(env, 'guest'), perm_grants: [], perm_denies: [] }],
    ['device.label', { deviceId: 'dev-x', label: 'X' }],
    ['role.create', { roleId: 1 }],
    ['mfa.reset', { userId: emp.id, totp: null, passkeys: [], backup: [], grace: [] }],
    ['destination.add', { userId: emp.id, id: 1 }],
  ];
  const before = snapshot(env);
  for (const r of [auditor, denied]) {
    for (const [kind, payload] of cases) {
      await assert.rejects(() => REVERTERS[kind](r, payload, { id: 1 }), (e) => e instanceof HttpError && e.status === 403, `${kind} by ${r.user.email}`);
    }
  }
  assert.equal(snapshot(env), before);
});

test('user.temp_role: none → revoke; lapsed → revoke; future → re-grant; permanent or over 90 days → refused', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const emp = await person(env, rc);
  const role = roleId(env, 'manager');
  const t = env.__clock();
  const grant = (exp) => env.DB.q('INSERT OR REPLACE INTO user_roles (user_id, role_id, granted_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?)', emp.id, role, owner.id, exp, iso(t));
  const row = () => env.DB.q('SELECT * FROM user_roles WHERE user_id = ?', emp.id)[0];
  grant(iso(t + DAY));
  await REVERTERS['user.temp_role'](rc, { userId: emp.id, roleId: role, prior: null });
  assert.equal(row(), undefined);
  grant(iso(t + DAY));
  await REVERTERS['user.temp_role'](rc, { userId: emp.id, roleId: role, prior: { expires_at: iso(t - HOUR), granted_by: owner.id } });
  assert.equal(row(), undefined, 'a grant that had lapsed is the same as none');
  await REVERTERS['user.temp_role'](rc, { userId: emp.id, roleId: role, prior: { expires_at: iso(t + 2 * DAY), granted_by: owner.id } });
  assert.equal(row().expires_at, iso(t + 2 * DAY));
  for (const prior of [{ expires_at: null }, { expires_at: iso(t + 91 * DAY) }]) {
    await assert.rejects(() => REVERTERS['user.temp_role'](rc, { userId: emp.id, roleId: role, prior }), (e) => e instanceof GuardError && e.code === 'not_restorable');
  }
  for (const exp of ['42', '2026-01-07', 'tomorrow', 5]) {
    await assert.rejects(() => REVERTERS['user.temp_role'](rc, { userId: emp.id, roleId: role, prior: { expires_at: exp } }), GuardError, String(exp));
  }
  assert.equal(row().expires_at, iso(t + 2 * DAY), 'refusals leave the row alone');
});

test('setting: never the gate; an unreadable prior is refused; null deletes the row; lists go back as lists', async () => {
  const { env, owner } = await world();
  await addAllowed(await rcFor(env, owner), { cidr: `${HOME}/32`, tier: 1 });
  const rc = await rcFor(env, owner);
  const raw = (k) => env.DB.q('SELECT value FROM settings WHERE key = ?', k)[0]?.value ?? null;
  await assert.rejects(() => REVERTERS.setting(rc, { key: 'gate_open', prior: '1' }), (e) => e.code === 'not_revertible');
  for (const [key, prior] of [['block_tor', 'maybe'], ['step_up_minutes', '0'], ['step_up_minutes', ''], ['country_deny', '["us"'], ['access_mode', 'open'], ['timezone', 'Mars/Base']]) {
    await assert.rejects(() => REVERTERS.setting(rc, { key, prior }), ValidationError, `${key}=${prior}`);
    assert.equal(raw(key), null);
  }
  env.DB.q("INSERT INTO settings (key, value, updated_at) VALUES ('timezone', 'Europe/London', 'x')");
  await REVERTERS.setting(rc, { key: 'timezone', prior: null });
  assert.equal(raw('timezone'), null);
  await REVERTERS.setting(rc, { key: 'country_deny', prior: '["KP","RU"]' });
  assert.equal(raw('country_deny'), '["KP","RU"]');
  // Back through the self-lockout guards too: from away, it may not refuse you.
  const away = await rcFor(env, owner, { ip: '91.198.174.9' });
  await assert.rejects(() => REVERTERS.setting(away, { key: 'country_deny', prior: '["US"]' }), (e) => e.code === 'self_lockout');
  assert.equal(raw('country_deny'), '["KP","RU"]');
});

test('network reverters run the same guards as the routes', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const mine = await addAllowed(rc, { cidr: `${HOME}/32`, tier: 1 });
  await assert.rejects(() => REVERTERS['network.allow.add'](rc, { id: mine.id }), (e) => e.code === 'self_lockout');
  await assert.rejects(() => REVERTERS['network.block.remove'](rc, { row: { cidr: '81.2.69.0/24' } }), (e) => e.code === 'self_lockout');
  await assert.rejects(() => REVERTERS['network.allow.edit'](rc, { id: mine.id, prior: { tier: 4, label: null, owner: null, user_id: null, expires_at: null } }), (e) => e.code === 'self_lockout');
  await assert.rejects(() => REVERTERS['network.allow.remove'](rc, { row: { cidr: '10.0.0.0/8', tier: 2 } }), ValidationError);
  await assert.rejects(() => REVERTERS['network.allow.remove'](rc, { row: { cidr: '185.15.56.0/24', tier: 2, expires_at: iso(env.__clock() - HOUR) } }), ValidationError, 'a lapsed entry is not revived');
  await assert.rejects(() => REVERTERS['network.allow.add'](rc, { id: 9999 }), (e) => e.status === 404);
  // A partial snapshot would clear the fields it never captured: refused.
  await assert.rejects(() => REVERTERS['network.allow.edit'](rc, { id: mine.id, prior: { tier: 2 } }), (e) => e.code === 'undo_unreadable');
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM allowed_ips')[0].n, 1);
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM blocked_ips')[0].n, 0);
});

test('device.label: a null prior makes the device unnamed again; renaming needs devices.manage', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  env.DB.q("INSERT INTO devices (id, status, label, first_seen, last_seen) VALUES ('dev-l', 'approved', 'Named', 'x', 'x')");
  await REVERTERS['device.label'](rc, { deviceId: 'dev-l', label: null });
  assert.equal(env.DB.q("SELECT label FROM devices WHERE id = 'dev-l'")[0].label, null);
  await REVERTERS['device.label'](rc, { deviceId: 'dev-l', label: 'Back' });
  assert.equal(env.DB.q("SELECT label FROM devices WHERE id = 'dev-l'")[0].label, 'Back');
  await assert.rejects(() => REVERTERS['device.label'](rc, { deviceId: 'nope', label: null }), (e) => e.status === 404);
  // Blocking the reverter's own device is refused (B trap 8).
  const onIt = await rcFor(env, owner, { device: { id: 'dev-l', row: { status: 'approved' } } });
  await assert.rejects(() => REVERTERS['device.status'](onIt, { deviceId: 'dev-l', status: 'blocked' }), (e) => e.code === 'self_lockout');
});

test('role reverters: system roles are fixed; a recreated key that exists again is refused', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  await assert.rejects(() => REVERTERS['role.create'](rc, { roleId: roleId(env, 'admin') }), (e) => e.code === 'system_role');
  await assert.rejects(() => REVERTERS['role.edit'](rc, { roleId: roleId(env, 'employee'), prior: { name: 'X', rank: 99, permissions: [], description: null } }), (e) => e.code === 'system_role');
  await assert.rejects(() => REVERTERS['role.delete'](rc, { row: { key: 'admin', name: 'Admin', rank: 80, permissions: '[]' } }), ValidationError);
  await assert.rejects(() => REVERTERS['role.delete'](rc, { row: { key: 'sneaky', name: 'Sneaky', rank: 50, permissions: '["audit.revert"]' } }), ValidationError, 'reserved permissions are refused on the way back in');
  await assert.rejects(() => REVERTERS['role.delete'](rc, { row: { key: 'too_high', name: 'Too high', rank: 100, permissions: '[]' } }), ValidationError);
  const t = iso(env.__clock());
  env.DB.q("INSERT INTO roles (key, name, rank, permissions, is_system, created_at, updated_at) VALUES ('desk', 'Desk', 30, '[]', 0, ?, ?)", t, t);
  await assert.rejects(() => REVERTERS['role.delete'](rc, { row: { id: 77, key: 'desk', name: 'Desk', rank: 30, permissions: '[]' } }), (e) => e.status === 409);
  const out = await REVERTERS['role.delete'](rc, { row: { id: 77, key: 'desk_two', name: 'Desk two', rank: 30, permissions: '["devices.view"]' } });
  assert.match(out.detail, /exists again \(id 77\)/);
});

test('mfa.reset and destinations re-run the account guard: never yourself where it is refused, never above your rank', async () => {
  const { env, owner } = await world();
  const rc = await rcFor(env, owner);
  const adminRow = await person(env, rc, 'admin');
  const peer = await person(env, rc, 'admin');
  const admin = await rcFor(env, adminRow);
  // An administrator reverting (were they ever allowed to) still could not touch a peer.
  await assert.rejects(() => REVERTERS['mfa.reset'](admin, { userId: peer.id, totp: null, passkeys: [], backup: [], grace: [] }), (e) => e.status === 403);
  await assert.rejects(() => REVERTERS['mfa.reset'](rc, { userId: owner.id, totp: null, passkeys: [], backup: [], grace: [] }), (e) => e.status === 403, 'not on yourself');
  await assert.rejects(() => REVERTERS.streak(rc, { userId: owner.id, prior: null }), (e) => e.status === 403);
  // A snapshot naming another user's rows is refused by restoreFactors.
  await assert.rejects(
    () => REVERTERS['mfa.reset'](rc, { userId: peer.id, totp: { user_id: owner.id, secret_enc: 'x', created_at: 'x' }, passkeys: [], backup: [], grace: [] }),
    (e) => e.code === 'snapshot_unreadable',
  );
  assert.equal(env.DB.q('SELECT COUNT(*) AS n FROM user_totp')[0].n, 0);
});

await run();
