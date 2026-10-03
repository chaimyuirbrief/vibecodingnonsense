import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, HOUR, MINUTE, DAY } from '../../src/util.js';
import { PERMISSION_KEYS, RESERVED, DANGER, SYSTEM_ROLES, SUPER_RANK } from '../../src/catalog.js';
import { GuardError, ValidationError, HttpError } from '../../src/errors.js';
import {
  effectivePermissions,
  userAuthz,
  can,
  canAll,
  routeNeedsStepUp,
  requireStepUp,
  assertCanActOn,
  assertCanAssignRole,
  assertCanGrantPerms,
  assertNotLastSuper,
  validateRolePermissions,
  isSuperRole,
} from '../../src/rbac.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, -1, 1.5, Symbol('x'), () => 1];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : typeof v === 'function' ? 'fn' : JSON.stringify(v) ?? String(v));
const ROLE_KEYS = SYSTEM_ROLES.map((r) => r.key); // super_admin, admin, auditor, manager, employee, guest
const RANK = Object.fromEntries(SYSTEM_ROLES.map((r) => [r.key, r.rank]));
const GRANTABLE = PERMISSION_KEYS.filter((k) => !RESERVED.has(k));

function roleRow(env, key) {
  return env.DB.q('SELECT * FROM roles WHERE key = ?', key)[0];
}

let emailN = 0;
function addUser(env, roleKey, { status = 'active', grants = '[]', denies = '[]', roleId } = {}) {
  const t = iso(env.__clock());
  const rid = roleId ?? roleRow(env, roleKey).id;
  env.DB.q(
    `INSERT INTO users (email, full_name, role_id, status, perm_grants, perm_denies, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    `u${++emailN}@acme.com`,
    `User ${emailN}`,
    rid,
    status,
    grants,
    denies,
    t,
    t,
  );
  return env.DB.q('SELECT * FROM users WHERE email = ?', `u${emailN}@acme.com`)[0];
}

function addTempRole(env, userId, roleKey, expiresAt) {
  env.DB.q('INSERT INTO user_roles (user_id, role_id, expires_at, created_at) VALUES (?, ?, ?, ?)', userId, roleRow(env, roleKey).id, expiresAt, iso(env.__clock()));
}

function addCustomRole(env, key, rank, permissions) {
  const t = iso(env.__clock());
  env.DB.q('INSERT INTO roles (key, name, rank, permissions, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)', key, key, rank, permissions, t, t);
  return roleRow(env, key);
}

async function authzFor(env, roleKey, opts) {
  const u = addUser(env, roleKey, opts);
  return effectivePermissions(env, u, env.__clock());
}

function guard(code) {
  return (e) => e instanceof GuardError && e.code === code && /^[A-Z].*[.]$/.test(e.message);
}

// ---------------------------------------------------------------- effective permissions

test('the six system roles: ranks, perms and sources; reserved keys only through *', async () => {
  const env = await makeEnvWithSchema();
  for (const r of SYSTEM_ROLES) {
    const a = await authzFor(env, r.key);
    assert.equal(a.rank, r.rank, r.key);
    assert.deepEqual(a.role, { id: roleRow(env, r.key).id, key: r.key, name: r.name, rank: r.rank });
    if (r.key === 'super_admin') {
      assert.equal(a.isSuper, true);
      assert.deepEqual([...a.perms].sort(), [...PERMISSION_KEYS].sort());
      for (const k of RESERVED) assert.ok(a.perms.has(k), `super holds reserved ${k}`);
      for (const k of PERMISSION_KEYS) assert.equal(a.sources[k], 'account');
    } else {
      assert.equal(a.isSuper, false, r.key);
      assert.deepEqual([...a.perms].sort(), [...r.permissions].sort(), r.key);
      for (const k of RESERVED) assert.ok(!a.perms.has(k), `${r.key} must not hold ${k}`);
      for (const k of a.perms) assert.equal(a.sources[k], 'role');
    }
    assert.equal(a.denied.size, 0);
    assert.ok(!a.perms.has('*'), "'*' is expanded, never held literally");
  }
});

test('a custom role holding "*" gets nothing from it, and cannot outrank the owner', async () => {
  const env = await makeEnvWithSchema();
  const evil = addCustomRole(env, 'evil', 90, '["*","users.view","audit.revert"]');
  const u = addUser(env, null, { roleId: evil.id });
  const a = await effectivePermissions(env, u, env.__clock());
  assert.equal(a.isSuper, false);
  assert.deepEqual([...a.perms], ['users.view'], 'reserved audit.revert ignored too');
  assert.equal(a.rank, 90);
  for (const rank of [100, 150, -5, 'x']) {
    const r = addCustomRole(env, `r${rank}`, rank, '["users.view"]');
    const b = await effectivePermissions(env, addUser(env, null, { roleId: r.id }), env.__clock());
    assert.equal(b.rank, 0, `custom rank ${rank} is unrecognised → 0`);
  }
  assert.equal(isSuperRole({ key: 'super_admin', is_system: 0, permissions: '["*"]' }), false);
  assert.equal(isSuperRole({ key: 'super_admin', is_system: 1, permissions: '[]' }), false);
  assert.equal(isSuperRole({ key: 'super_admin', is_system: 1, permissions: 'garbage' }), false);
  assert.equal(isSuperRole({ key: 'admin', is_system: 1, permissions: '["*"]' }), false);
  assert.equal(isSuperRole(roleRow(env, 'super_admin')), true);
  for (const v of HOSTILE) assert.equal(isSuperRole(v), false);
});

test('per-user grants add flags; reserved and unknown keys are ignored', async () => {
  const env = await makeEnvWithSchema();
  const a = await authzFor(env, 'employee', { grants: '["directory.view","users.reset_password","gate.open","users.fly","*",42]' });
  assert.deepEqual([...a.perms], ['directory.view']);
  assert.equal(a.sources['directory.view'], 'flag');
  const m = await authzFor(env, 'manager', { grants: '["directory.view","users.view"]' });
  assert.equal(m.sources['directory.view'], 'role', 'the more durable source wins');
  assert.equal(m.sources['users.view'], 'flag');
});

test('denies beat grants, from every source', async () => {
  const env = await makeEnvWithSchema();
  const e = await authzFor(env, 'employee', { grants: '["users.view"]', denies: '["users.view"]' });
  assert.ok(!e.perms.has('users.view'));
  assert.ok(e.denied.has('users.view'));
  assert.equal(e.sources['users.view'], undefined);
  const ad = await authzFor(env, 'admin', { denies: '["users.suspend","not.a.key"]' });
  assert.ok(!ad.perms.has('users.suspend'));
  assert.deepEqual([...ad.denied], ['users.suspend']);
  assert.equal(ad.perms.size, GRANTABLE.length - 1);
  const s = await authzFor(env, 'super_admin', { denies: '["audit.revert"]' });
  assert.ok(!s.perms.has('audit.revert'), 'even the implicit set');
  assert.equal(s.isSuper, true);
});

test('unparseable perm_denies denies EVERYTHING (fail closed); unparseable perm_grants grants nothing', async () => {
  const env = await makeEnvWithSchema();
  for (const denies of ['not json', '{}', '"users.view"', '[1]', '[null]', '["*"]', '[', 'null', '42']) {
    const a = await authzFor(env, 'admin', { denies });
    assert.equal(a.perms.size, 0, `denies ${denies}`);
    assert.equal(a.denied.size, GRANTABLE.length);
    assert.equal(a.rank, 80, 'rank is unchanged; only permissions are refused');
  }
  for (const grants of ['not json', '{}', '"users.view"', '[', 'null']) {
    const a = await authzFor(env, 'employee', { grants });
    assert.equal(a.perms.size, 0, `grants ${grants}`);
  }
  // A caller-supplied user object with the columns simply absent: nothing denied.
  const row = addUser(env, 'manager');
  const a = await effectivePermissions(env, { id: row.id, role_id: row.role_id }, env.__clock());
  assert.equal(a.perms.size, 3);
  const b = await effectivePermissions(env, { id: row.id, role_id: row.role_id, perm_denies: 7 }, env.__clock());
  assert.equal(b.perms.size, 0, 'present but not a list → deny all');
});

test('temporary roles: unexpired counts, expired and unreadable expiry do not, NULL is permanent', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  const u = addUser(env, 'employee');
  addTempRole(env, u.id, 'admin', iso(now + DAY));
  let a = await effectivePermissions(env, u, now);
  assert.equal(a.rank, 80);
  assert.equal(a.role.key, 'employee', 'role is the primary role');
  assert.equal(a.sources['users.suspend'], 'temp_role');
  a = await effectivePermissions(env, u, now + DAY + 1);
  assert.equal(a.rank, 20, 'expired');
  assert.equal(a.perms.size, 0);
  for (const bad of ['42', 'garbage', '2026-01-07', '2026-01-07T00:00:00', '', ' ']) {
    env.DB.q('UPDATE user_roles SET expires_at = ? WHERE user_id = ?', bad, u.id);
    a = await effectivePermissions(env, u, now);
    assert.equal(a.rank, 20, `unreadable expiry ${bad} is expired`);
  }
  env.DB.q('UPDATE user_roles SET expires_at = NULL WHERE user_id = ?', u.id);
  a = await effectivePermissions(env, u, now + 365 * DAY);
  assert.equal(a.rank, 80, 'NULL = permanent');

  const v = addUser(env, 'manager');
  addTempRole(env, v.id, 'super_admin', iso(now + HOUR));
  a = await effectivePermissions(env, v, now);
  assert.equal(a.isSuper, true);
  assert.equal(a.rank, SUPER_RANK);
  assert.equal(a.sources['directory.view'], 'role');
  assert.equal(a.sources['audit.revert'], 'temp_role');
  a = await effectivePermissions(env, v, now + HOUR);
  assert.equal(a.isSuper, false, 'expired at exactly expires_at');
  assert.equal(a.rank, 50);
});

test('a missing role row is rank 0 with no permissions at all', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, null, { roleId: 9999, grants: '["directory.view"]' });
  addTempRole(env, u.id, 'admin', null);
  const a = await effectivePermissions(env, u, env.__clock());
  assert.equal(a.rank, 0);
  assert.equal(a.perms.size, 0);
  assert.equal(a.role, null);
  assert.equal(a.isSuper, false);
});

test('effectivePermissions survives hostile users', async () => {
  const env = await makeEnvWithSchema();
  for (const v of HOSTILE) {
    const a = await effectivePermissions(env, v, env.__clock());
    assert.equal(a.perms.size, 0, show(v));
    assert.equal(a.rank, 0);
    const b = await effectivePermissions(env, { id: 1, role_id: v }, env.__clock());
    assert.equal(b.perms.size, 0, `role_id ${show(v)}`);
  }
});

test('userAuthz loads the user; unknown or hostile ids give null', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'auditor', { denies: '["audit.verify"]' });
  const a = await userAuthz(env, u.id, env.__clock());
  assert.equal(a.userId, u.id);
  assert.equal(a.rank, 60);
  assert.ok(!a.perms.has('audit.verify'));
  assert.equal((await userAuthz(env, String(u.id), env.__clock())).userId, u.id);
  assert.equal(await userAuthz(env, 99999, env.__clock()), null);
  for (const v of HOSTILE) assert.equal(await userAuthz(env, v, env.__clock()), null, show(v));
});

test('can / canAll / routeNeedsStepUp are total', async () => {
  const env = await makeEnvWithSchema();
  const a = await authzFor(env, 'manager');
  assert.equal(can(a, 'users.invite'), true);
  assert.equal(can(a, 'users.view'), false);
  assert.equal(canAll(a, ['users.invite', 'team.view']), true);
  assert.equal(canAll(a, ['users.invite', 'users.view']), false);
  assert.equal(canAll(a, 'team.view'), true);
  for (const v of HOSTILE) {
    assert.equal(can(v, 'users.view'), false);
    assert.equal(can(a, v), false);
    if (!Array.isArray(v)) assert.equal(canAll(a, v), false, show(v));
    assert.equal(routeNeedsStepUp(v), false, show(v));
  }
  assert.equal(can({ perms: ['users.invite'] }, 'users.invite'), false, 'perms must be the Set effectivePermissions built');
  for (const k of PERMISSION_KEYS) assert.equal(routeNeedsStepUp(k), DANGER.has(k), k);
  assert.equal(routeNeedsStepUp(['users.view', 'users.suspend']), true);
  assert.equal(routeNeedsStepUp(['users.view', 'audit.view']), false);
  assert.equal(routeNeedsStepUp('nope'), false);
});

// ---------------------------------------------------------------- step-up

test('requireStepUp: aal 2 and mfa_at within step_up_minutes, else step_up_required', () => {
  const now = Date.UTC(2026, 0, 6, 15);
  const ctx = (session, policy) => ({ nowMs: now, session, policy });
  const ok = (rc) => assert.doesNotThrow(() => requireStepUp(rc));
  const no = (rc, msg) =>
    assert.throws(() => requireStepUp(rc), (e) => e instanceof HttpError && e.status === 403 && e.body.step_up_required === true, msg);
  ok(ctx({ aal: 2, mfa_at: iso(now - 14 * MINUTE) }, { step_up_minutes: 15 }));
  ok(ctx({ aal: 2, mfa_at: iso(now - 15 * MINUTE) }, { step_up_minutes: 15 }));
  no(ctx({ aal: 2, mfa_at: iso(now - 15 * MINUTE - 1) }, { step_up_minutes: 15 }), 'stale');
  ok(ctx({ aal: 2, mfa_at: iso(now - 14 * MINUTE) }, {}), 'absent → 15');
  ok(ctx({ aal: 2, mfa_at: iso(now - 14 * MINUTE) }), 'no policy → 15');
  no(ctx({ aal: 2, mfa_at: iso(now - 16 * MINUTE) }), 'no policy → 15');
  no(ctx({ aal: 2, mfa_at: iso(now - 6 * MINUTE) }, { step_up_minutes: 5 }));
  ok(ctx({ aal: 2, mfa_at: iso(now - 100 * MINUTE) }, { step_up_minutes: 120 }));
  for (const bad of ['abc', '', 0, 500, true, {}]) {
    no(ctx({ aal: 2, mfa_at: iso(now - 6 * MINUTE) }, { step_up_minutes: bad }), `unreadable ${show(bad)} → 5`);
    ok(ctx({ aal: 2, mfa_at: iso(now - 4 * MINUTE) }, { step_up_minutes: bad }));
  }
  no(ctx({ aal: 1, mfa_at: iso(now - MINUTE) }), 'aal 1');
  no(ctx({ aal: '2', mfa_at: iso(now - MINUTE) }), "aal '2'");
  no(ctx({ aal: 2, mfa_at: null }));
  no(ctx({ aal: 2, mfa_at: '42' }), "'42' is not a time");
  no(ctx({ aal: 2, mfa_at: '2026-01-06T14:59:00' }), 'no zone');
  no(ctx({ aal: 2, mfa_at: iso(now + 2 * MINUTE) }), 'stamped in the future');
  ok(ctx({ aal: 2, mfa_at: iso(now + 30 * 1000) }), 'small skew tolerated');
  for (const v of HOSTILE) no(ctx(v), `session ${show(v)}`);
  no(null);
  no(undefined);
});

// ---------------------------------------------------------------- rank

test('assertCanActOn: strictly lower rank only; Super Admins are peers; matrix over all six roles', async () => {
  const env = await makeEnvWithSchema();
  const az = {};
  for (const k of ROLE_KEYS) az[k] = await authzFor(env, k);
  for (const actor of ROLE_KEYS) {
    for (const target of ROLE_KEYS) {
      const other = await authzFor(env, target);
      const allowed = RANK[actor] > RANK[target] || (actor === 'super_admin' && target === 'super_admin');
      if (allowed) assert.doesNotThrow(() => assertCanActOn(az[actor], other), `${actor} → ${target}`);
      else assert.throws(() => assertCanActOn(az[actor], other), guard('rank'), `${actor} → ${target}`);
    }
  }
  // Equal rank cannot act on equal rank.
  const admin2 = await authzFor(env, 'admin');
  assert.throws(() => assertCanActOn(az.admin, admin2), (e) => e.code === 'rank' && e.message === 'You can only act on people ranked below you.');
  // Super Admin on a temporary Super Admin is peer-to-peer too.
  const temp = addUser(env, 'employee');
  addTempRole(env, temp.id, 'super_admin', iso(env.__clock() + DAY));
  const tempAz = await effectivePermissions(env, temp, env.__clock());
  assert.equal(tempAz.isSuper, true);
  assert.doesNotThrow(() => assertCanActOn(az.super_admin, tempAz));
  assert.doesNotThrow(() => assertCanActOn(tempAz, az.super_admin));
  assert.throws(() => assertCanActOn(az.admin, tempAz), guard('rank'));
});

test('assertCanActOn: self only with allowSelf; hostile authz refused', async () => {
  const env = await makeEnvWithSchema();
  const a = await authzFor(env, 'admin');
  const s = await authzFor(env, 'super_admin');
  assert.throws(() => assertCanActOn(a, a), guard('rank'));
  assert.throws(() => assertCanActOn(s, s), guard('rank'), 'even a Super Admin, without allowSelf');
  assert.doesNotThrow(() => assertCanActOn(a, a, { allowSelf: true }));
  assert.throws(() => assertCanActOn(a, a, { allowSelf: 'yes' }), guard('rank'));
  const g = await authzFor(env, 'guest');
  for (const v of HOSTILE) {
    assert.throws(() => assertCanActOn(v, g), guard('rank'), show(v));
    assert.throws(() => assertCanActOn(a, v), (e) => e instanceof GuardError, show(v));
    assert.throws(() => assertCanActOn({ ...a, rank: v }, g), guard('rank'), `rank ${show(v)}`);
  }
  assert.throws(() => assertCanActOn({ ...a, isSuper: 'true' }, { ...s, userId: 999 }), guard('rank'), 'isSuper must be true');
});

test('assertCanAssignRole: below your rank, never * unless Super, never a role carrying perms you lack', async () => {
  const env = await makeEnvWithSchema();
  const want = {
    super_admin: ROLE_KEYS,
    admin: ['auditor', 'manager', 'employee', 'guest'],
    auditor: ['employee', 'guest'], // manager carries users.invite, which an auditor lacks
    manager: ['employee', 'guest'],
    employee: ['guest'],
    guest: [],
  };
  for (const actor of ROLE_KEYS) {
    const a = await authzFor(env, actor);
    for (const target of ROLE_KEYS) {
      const role = roleRow(env, target);
      if (want[actor].includes(target)) assert.doesNotThrow(() => assertCanAssignRole(a, role), `${actor} assigns ${target}`);
      else assert.throws(() => assertCanAssignRole(a, role), guard('minting'), `${actor} assigns ${target}`);
    }
  }
  const admin = await authzFor(env, 'admin');
  const sup = await authzFor(env, 'super_admin');
  const star = addCustomRole(env, 'star', 10, '["*"]');
  assert.throws(() => assertCanAssignRole(admin, star), guard('minting'));
  assert.doesNotThrow(() => assertCanAssignRole(sup, star));
  const broken = addCustomRole(env, 'broken', 10, 'not json');
  assert.throws(() => assertCanAssignRole(admin, broken), guard('minting'), 'unreadable permissions: Super Admin only');
  assert.throws(() => assertCanAssignRole(admin, { key: 'x', rank: 10, permissions: ['*'] }), guard('minting'));
  assert.doesNotThrow(() => assertCanAssignRole(admin, { key: 'x', rank: 79, permissions: ['users.view'] }));
  const deniedAdmin = await authzFor(env, 'admin', { denies: '["users.view"]' });
  assert.throws(() => assertCanAssignRole(deniedAdmin, { key: 'x', rank: 10, permissions: ['users.view'] }), guard('minting'));
  for (const v of HOSTILE) {
    assert.throws(() => assertCanAssignRole(admin, v), guard('minting'), show(v));
    // 0 is a legal rank; everything else here is unreadable.
    if (v !== 0) assert.throws(() => assertCanAssignRole(admin, { key: 'x', rank: v, permissions: [] }), guard('minting'), `rank ${show(v)}`);
    assert.throws(() => assertCanAssignRole(v, roleRow(env, 'guest')), guard('minting'), show(v));
  }
});

test('assertCanGrantPerms: catalogue keys you hold, never reserved — matrix over all six roles', async () => {
  const env = await makeEnvWithSchema();
  for (const actor of ROLE_KEYS) {
    const a = await authzFor(env, actor);
    for (const k of PERMISSION_KEYS) {
      if (RESERVED.has(k)) assert.throws(() => assertCanGrantPerms(a, [k]), guard('reserved'), `${actor} grants reserved ${k}`);
      else if (a.perms.has(k)) assert.doesNotThrow(() => assertCanGrantPerms(a, [k]), `${actor} grants ${k}`);
      else assert.throws(() => assertCanGrantPerms(a, [k]), guard('minting'), `${actor} grants ${k}`);
    }
  }
  const sup = await authzFor(env, 'super_admin');
  assert.doesNotThrow(() => assertCanGrantPerms(sup, []));
  assert.doesNotThrow(() => assertCanGrantPerms(sup, GRANTABLE));
  assert.throws(() => assertCanGrantPerms(sup, ['*']), guard('reserved'));
  assert.throws(() => assertCanGrantPerms(sup, ['users.view', 'users.fly']), ValidationError);
  for (const v of HOSTILE) {
    if (!Array.isArray(v)) assert.throws(() => assertCanGrantPerms(sup, v), ValidationError, show(v));
    if (typeof v !== 'string') assert.throws(() => assertCanGrantPerms(sup, [v]), ValidationError, `[${show(v)}]`);
    assert.throws(() => assertCanGrantPerms(v, ['users.view']), (e) => e instanceof GuardError, `actor ${show(v)}`);
  }
});

test('validateRolePermissions: catalogue keys only, no *, no reserved; deduplicated in catalogue order', () => {
  assert.deepEqual(validateRolePermissions(['users.view', 'directory.view', 'users.view']), ['directory.view', 'users.view']);
  assert.deepEqual(validateRolePermissions([]), []);
  assert.deepEqual(validateRolePermissions(GRANTABLE), GRANTABLE);
  assert.throws(() => validateRolePermissions(['*']), ValidationError);
  for (const k of RESERVED) assert.throws(() => validateRolePermissions([k]), ValidationError, k);
  assert.throws(() => validateRolePermissions(['users.fly']), ValidationError);
  for (const v of HOSTILE) {
    if (!Array.isArray(v)) assert.throws(() => validateRolePermissions(v), ValidationError, show(v));
    assert.throws(() => validateRolePermissions([v]), ValidationError, `[${show(v)}]`);
  }
});

// ---------------------------------------------------------------- last superuser

test('assertNotLastSuper: the only active Super Admin is immovable; a second one frees them', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  const a = addUser(env, 'super_admin');
  const emp = addUser(env, 'employee');
  await assert.rejects(assertNotLastSuper(env, a.id, now), guard('last_superuser'));
  await assert.doesNotReject(assertNotLastSuper(env, emp.id, now), 'target is not a super');
  const b = addUser(env, 'super_admin', { status: 'suspended' });
  await assert.rejects(assertNotLastSuper(env, a.id, now), guard('last_superuser'), 'a suspended super does not count');
  env.DB.q("UPDATE users SET status = 'active' WHERE id = ?", b.id);
  await assert.doesNotReject(assertNotLastSuper(env, a.id, now));
  await assert.doesNotReject(assertNotLastSuper(env, b.id, now));
});

test('assertNotLastSuper counts only PERMANENT Super Admins: a timed grant lapses, so it never keeps the owner movable', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  const a = addUser(env, 'super_admin');
  const t = addUser(env, 'manager');
  addTempRole(env, t.id, 'super_admin', iso(now + HOUR));
  await assert.rejects(assertNotLastSuper(env, a.id, now), guard('last_superuser'), 'a week-long grant does not make the owner removable');
  await assert.doesNotReject(assertNotLastSuper(env, t.id, now), 'removing a timed grant can never leave zero owners');
  await assert.rejects(assertNotLastSuper(env, a.id, now + HOUR), guard('last_superuser'), 'expired');
  for (const bad of ['42', 'garbage', '2099-01-01']) {
    env.DB.q('UPDATE user_roles SET expires_at = ? WHERE user_id = ?', bad, t.id);
    await assert.rejects(assertNotLastSuper(env, a.id, now), guard('last_superuser'), `unreadable expiry ${bad}`);
  }
  env.DB.q('UPDATE user_roles SET expires_at = NULL WHERE user_id = ?', t.id);
  await assert.doesNotReject(assertNotLastSuper(env, a.id, now), 'NULL = permanent');
  // The last super by temporary role alone is protected too.
  env.DB.q("UPDATE users SET status = 'disabled' WHERE id = ?", a.id);
  await assert.rejects(assertNotLastSuper(env, t.id, now), guard('last_superuser'));
});

test('assertNotLastSuper fails CLOSED when the count cannot be read', async () => {
  const env = await makeEnvWithSchema();
  const now = env.__clock();
  const a = addUser(env, 'super_admin');
  addUser(env, 'super_admin');
  addUser(env, 'super_admin');
  await assert.doesNotReject(assertNotLastSuper(env, a.id, now));
  const origErr = console.error;
  console.error = () => {};
  try {
    for (const re of [/FROM users u JOIN roles/, /FROM user_roles ur/, /users/]) {
      env.DB.failOn = re;
      await assert.rejects(assertNotLastSuper(env, a.id, now), guard('last_superuser'), String(re));
    }
    env.DB.failOn = null;
    env.DB.q('DROP TABLE user_roles');
    await assert.rejects(assertNotLastSuper(env, a.id, now), guard('last_superuser'), 'missing table');
  } finally {
    console.error = origErr;
  }
  for (const v of [NaN, undefined, null, '1767711600000', Infinity]) {
    await assert.rejects(assertNotLastSuper(env, a.id, v), guard('last_superuser'), `nowMs ${show(v)}`);
  }
});

test('assertNotLastSuper refuses hostile target ids rather than guessing', async () => {
  const env = await makeEnvWithSchema();
  addUser(env, 'super_admin');
  addUser(env, 'super_admin');
  for (const v of HOSTILE) await assert.rejects(assertNotLastSuper(env, v, env.__clock()), guard('last_superuser'), show(v));
});

await run();
