import { test, assert, run } from '../helpers/t.js';
import { makeEnvWithSchema } from '../helpers/env.js';
import { iso, MINUTE, HOUR, DAY } from '../../src/util.js';
import { SYSTEM_ROLES, PERMISSION_KEYS } from '../../src/catalog.js';
import { GuardError, ValidationError, HttpError } from '../../src/errors.js';
import { effectivePermissions } from '../../src/rbac.js';
import { verifyPassword } from '../../src/crypto.js';
import * as U from '../../src/users.js';
import { createSession } from '../../src/sessions.js';

const HOSTILE = [null, undefined, NaN, Infinity, '', '   ', 'abc', {}, [], true, 0, Symbol('x')];
const show = (v) => (typeof v === 'symbol' ? 'Symbol' : JSON.stringify(v) ?? String(v));
const ROLE_KEYS = SYSTEM_ROLES.map((r) => r.key);
const RANK = Object.fromEntries(SYSTEM_ROLES.map((r) => [r.key, r.rank]));
const POWERS = JSON.stringify(['users.suspend', 'users.disable', 'users.roles', 'users.edit']);

function roleRow(env, key) {
  return env.DB.q('SELECT * FROM roles WHERE key = ?', key)[0];
}

let seq = 0;
function addUser(env, roleKey, o = {}) {
  const n = ++seq;
  const t = iso(env.__clock());
  const email = o.email ?? `person${n}@acme.com`;
  const status = o.status ?? 'active';
  env.DB.q(
    `INSERT INTO users (email, username, full_name, employee_no, status, role_id, perm_grants, perm_denies,
       password_hash, mfa_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    email,
    o.username ?? null,
    o.full_name ?? `Person ${n}`,
    o.employee_no ?? null,
    status,
    o.roleId ?? roleRow(env, roleKey).id,
    o.grants ?? '[]',
    o.denies ?? '[]',
    o.password_hash !== undefined ? o.password_hash : status === 'invited' ? null : 'placeholder',
    o.mfa_policy ?? 'inherit',
    t,
    t,
  );
  return env.DB.q('SELECT * FROM users WHERE email = ?', email)[0];
}

function row(env, id) {
  return env.DB.q('SELECT * FROM users WHERE id = ?', id)[0];
}

function count(env, sql, ...args) {
  return env.DB.q(sql, ...args)[0].n;
}

async function rcAs(env, user, extra = {}) {
  const nowMs = env.__clock();
  return {
    env,
    nowMs,
    user,
    authz: user ? await effectivePermissions(env, user, nowMs) : null,
    ip: '81.2.69.10',
    cf: { country: 'US' },
    setCookies: [],
    ...extra,
  };
}

function addTempRole(env, userId, roleKey, expiresAt) {
  env.DB.q('INSERT INTO user_roles (user_id, role_id, expires_at, created_at) VALUES (?, ?, ?, ?)', userId, roleRow(env, roleKey).id, expiresAt, iso(env.__clock()));
}

function addGrace(env, userId, deviceId) {
  const t = env.__clock();
  env.DB.q('INSERT INTO mfa_grace (user_id, device_id, tier, verified_at, expires_at) VALUES (?, ?, 1, ?, ?)', userId, deviceId, iso(t), iso(t + DAY));
}

const guard = (code) => (e) => {
  assert.ok(e instanceof GuardError, `expected GuardError(${code}), got ${e && e.stack}`);
  assert.equal(e.code, code);
  assert.match(e.message, /^[A-Z].*[.]$/);
  return true;
};
const http = (status, re) => (e) => {
  assert.ok(e instanceof HttpError, `expected HttpError(${status}), got ${e && e.stack}`);
  assert.equal(e.status, status, e.message);
  if (re) assert.match(e.body.error, re);
  return true;
};
const invalid = (field) => (e) => {
  assert.ok(e instanceof ValidationError, `expected ValidationError, got ${e && e.stack}`);
  if (field) assert.equal(e.body.field, field);
  return true;
};
const activeSupers = (env) =>
  count(env, "SELECT COUNT(*) AS n FROM users u JOIN roles r ON r.id = u.role_id WHERE u.status = 'active' AND r.key = 'super_admin'");

// A Super Admin whose row is no longer active but whose request is already
// in flight: the only actor the last-superuser rule can stop, since anyone
// else acting on a Super Admin is an active Super Admin and counts.
async function ghostSuper(env) {
  const g = addUser(env, 'super_admin', { status: 'suspended' });
  return rcAs(env, g);
}

// ---------------------------------------------------------------- rank

test('rank matrix: suspending needs strictly higher rank; Super Admins are peers', async () => {
  const env = await makeEnvWithSchema();
  addUser(env, 'super_admin');
  addUser(env, 'super_admin');
  for (const a of ROLE_KEYS) {
    // Every actor holds the permissions, so rank alone decides.
    const actor = addUser(env, a, { grants: a === 'super_admin' ? '[]' : POWERS });
    const rc = await rcAs(env, actor);
    for (const b of ROLE_KEYS) {
      const target = addUser(env, b);
      const allowed = (a === 'super_admin' && b === 'super_admin') || RANK[a] > RANK[b];
      if (allowed) {
        const r = await U.setStatus(rc, target.id, 'suspended');
        assert.equal(r.row.status, 'suspended', `${a} → ${b}`);
        assert.deepEqual(r.prior, { status: 'active' });
      } else {
        await assert.rejects(U.setStatus(rc, target.id, 'suspended'), guard('rank'), `${a} → ${b}`);
        assert.equal(row(env, target.id).status, 'active', `${a} → ${b} unchanged`);
      }
    }
  }
});

test('rank matrix: changing a role needs strictly higher rank; Super Admins are peers', async () => {
  const env = await makeEnvWithSchema();
  addUser(env, 'super_admin');
  addUser(env, 'super_admin');
  const guest = roleRow(env, 'guest').id;
  for (const a of ROLE_KEYS) {
    const actor = addUser(env, a, { grants: a === 'super_admin' ? '[]' : POWERS });
    const rc = await rcAs(env, actor);
    for (const b of ROLE_KEYS) {
      const target = addUser(env, b);
      const allowed = (a === 'super_admin' && b === 'super_admin') || RANK[a] > RANK[b];
      if (allowed) {
        const r = await U.changeRole(rc, target.id, { role_id: guest });
        assert.equal(r.row.role_id, guest, `${a} → ${b}`);
        assert.equal(r.prior.role_id, roleRow(env, b).id);
      } else {
        await assert.rejects(U.changeRole(rc, target.id, { role_id: guest }), guard('rank'), `${a} → ${b}`);
        assert.equal(row(env, target.id).role_id, roleRow(env, b).id, `${a} → ${b} unchanged`);
      }
    }
  }
});

test('changeRole AFTER: nobody can lift someone to or above their own rank', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const emp = addUser(env, 'employee');
  const rcAdmin = await rcAs(env, admin);
  for (const key of ['admin', 'super_admin']) {
    await assert.rejects(U.changeRole(rcAdmin, emp.id, { role_id: roleRow(env, key).id }), guard('minting'), key);
    assert.equal(row(env, emp.id).role_id, roleRow(env, 'employee').id);
  }
  const ok = await U.changeRole(rcAdmin, emp.id, { role_id: roleRow(env, 'auditor').id });
  assert.equal(ok.row.role_id, roleRow(env, 'auditor').id);

  const mgr = addUser(env, 'manager', { grants: POWERS });
  const g = addUser(env, 'guest');
  const rcMgr = await rcAs(env, mgr);
  for (const key of ['manager', 'auditor', 'admin', 'super_admin']) {
    await assert.rejects(U.changeRole(rcMgr, g.id, { role_id: roleRow(env, key).id }), guard('minting'), key);
    assert.equal(row(env, g.id).role_id, roleRow(env, 'guest').id);
  }
  assert.equal((await U.changeRole(rcMgr, g.id, { role_id: roleRow(env, 'employee').id })).row.role_id, roleRow(env, 'employee').id);
});

test('equal rank cannot act on equal rank (admin on admin), for every writer', async () => {
  const env = await makeEnvWithSchema();
  const a1 = addUser(env, 'admin');
  const a2 = addUser(env, 'admin');
  const rc = await rcAs(env, a1);
  await assert.rejects(U.setStatus(rc, a2.id, 'suspended'), guard('rank'));
  await assert.rejects(U.setStatus(rc, a2.id, 'disabled'), guard('rank'));
  await assert.rejects(U.changeRole(rc, a2.id, { role_id: roleRow(env, 'guest').id }), guard('rank'));
  await assert.rejects(U.grantTempRole(rc, a2.id, roleRow(env, 'auditor').id, iso(env.__clock() + DAY)), guard('rank'));
  await assert.rejects(U.updateProfile(rc, a2.id, { job_title: 'x' }), guard('rank'));
  assert.equal(row(env, a2.id).status, 'active');
});

// ---------------------------------------------------------------- Super Admins

test('Super Admins act on each other as peers', async () => {
  const env = await makeEnvWithSchema();
  const s1 = addUser(env, 'super_admin');
  const s2 = addUser(env, 'super_admin');
  const rc = await rcAs(env, s1);
  const r = await U.changeRole(rc, s2.id, { role_id: roleRow(env, 'admin').id });
  assert.equal(r.row.role_id, roleRow(env, 'admin').id);
  assert.equal(activeSupers(env), 1);
});

test('last super: suspending, disabling, demoting or revoking the final Super Admin is refused', async () => {
  const env = await makeEnvWithSchema();
  const owner = addUser(env, 'super_admin');
  const rc = await ghostSuper(env);
  await assert.rejects(U.setStatus(rc, owner.id, 'suspended'), guard('last_superuser'));
  await assert.rejects(U.setStatus(rc, owner.id, 'disabled'), guard('last_superuser'));
  await assert.rejects(U.changeRole(rc, owner.id, { role_id: roleRow(env, 'admin').id }), guard('last_superuser'));
  assert.equal(row(env, owner.id).status, 'active');
  assert.equal(row(env, owner.id).role_id, roleRow(env, 'super_admin').id);

  // Super only by a temporary grant.
  const temp = addUser(env, 'admin');
  addTempRole(env, temp.id, 'super_admin', null);
  env.DB.q('UPDATE users SET role_id = ? WHERE id = ?', roleRow(env, 'admin').id, owner.id);
  await assert.rejects(U.revokeTempRole(rc, temp.id, roleRow(env, 'super_admin').id), guard('last_superuser'));
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM user_roles WHERE user_id = ?', temp.id), 1);

  // A second active Super Admin makes the same changes legal.
  addUser(env, 'super_admin');
  await U.revokeTempRole(rc, temp.id, roleRow(env, 'super_admin').id);
  env.DB.q('UPDATE users SET role_id = ? WHERE id = ?', roleRow(env, 'super_admin').id, owner.id);
  assert.equal((await U.setStatus(rc, owner.id, 'suspended')).row.status, 'suspended');
});

test('last super: a timed Super Admin grant never makes the last permanent owner removable', async () => {
  const env = await makeEnvWithSchema();
  const owner = addUser(env, 'super_admin');
  const helper = addUser(env, 'admin');
  addTempRole(env, helper.id, 'super_admin', iso(env.__clock() + HOUR));
  let rc = await ghostSuper(env);
  // The grant lapses on its own; letting it stand in for the owner would leave
  // nobody holding '*' an hour from now.
  await assert.rejects(U.setStatus(rc, owner.id, 'suspended'), guard('last_superuser'));
  assert.equal(row(env, owner.id).status, 'active');

  env.__advance(2 * HOUR); // the temporary grant has lapsed
  rc = { ...rc, nowMs: env.__clock() };
  await assert.rejects(U.setStatus(rc, owner.id, 'suspended'), guard('last_superuser'));
  await assert.rejects(U.changeRole(rc, owner.id, { role_id: roleRow(env, 'admin').id }), guard('last_superuser'));

  // An expiry nobody can read has expired.
  env.DB.q('UPDATE user_roles SET expires_at = ? WHERE user_id = ?', 'garbage', helper.id);
  await assert.rejects(U.setStatus(rc, owner.id, 'disabled'), guard('last_superuser'));
  assert.equal(row(env, owner.id).status, 'active');
});

test('last super fails CLOSED when the Super Admin count cannot be read', async () => {
  const env = await makeEnvWithSchema();
  const a = addUser(env, 'super_admin');
  const b = addUser(env, 'super_admin');
  const rc = await rcAs(env, a);
  const s = await createSession(rc, b, {});
  env.DB.failOn = /r\.key = \?/; // rbac's count query, and nothing else on this path
  await assert.rejects(U.setStatus(rc, b.id, 'suspended'), guard('last_superuser'));
  await assert.rejects(U.setStatus(rc, b.id, 'disabled'), guard('last_superuser'));
  await assert.rejects(U.changeRole(rc, b.id, { role_id: roleRow(env, 'admin').id }), guard('last_superuser'));
  env.DB.failOn = null;
  assert.equal(row(env, b.id).status, 'active');
  assert.equal(row(env, b.id).role_id, roleRow(env, 'super_admin').id);
  assert.equal(env.DB.q('SELECT revoked_at FROM sessions WHERE id = ?', s.id)[0].revoked_at, null, 'a refused change signs nobody out');
  assert.equal((await U.setStatus(rc, b.id, 'suspended')).row.status, 'suspended');
});

test('last super: two Super Admins removing each other at the same moment leave one', async () => {
  for (const op of ['status', 'role']) {
    const env = await makeEnvWithSchema();
    const a = addUser(env, 'super_admin');
    const b = addUser(env, 'super_admin');
    const [rcA, rcB] = [await rcAs(env, a), await rcAs(env, b)];
    // Hold both writes until both have passed every check.
    const orig = env.DB.batch.bind(env.DB);
    const origPrepare = env.DB.prepare.bind(env.DB);
    let arrived = 0;
    let release;
    const gate = new Promise((r) => (release = r));
    const hold = async () => {
      if (++arrived === 2) release();
      await gate;
    };
    env.DB.batch = async (stmts) => {
      await hold();
      return orig(stmts);
    };
    env.DB.prepare = (sql) => {
      const st = origPrepare(sql);
      if (!/^\s*UPDATE users SET role_id/.test(sql)) return st;
      const bind = st.bind.bind(st);
      st.bind = (...args) => {
        const bound = bind(...args);
        const runIt = bound.run.bind(bound);
        bound.run = async () => {
          await hold();
          return runIt();
        };
        return bound;
      };
      return st;
    };
    const admin = roleRow(env, 'admin').id;
    const results = await Promise.allSettled(
      op === 'status'
        ? [U.setStatus(rcA, b.id, 'suspended'), U.setStatus(rcB, a.id, 'suspended')]
        : [U.changeRole(rcA, b.id, { role_id: admin }), U.changeRole(rcB, a.id, { role_id: admin })],
    );
    env.DB.batch = orig;
    env.DB.prepare = origPrepare;
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1, op);
    const lost = results.find((r) => r.status === 'rejected');
    guard('last_superuser')(lost.reason);
    assert.equal(activeSupers(env), 1, op);
  }
});

test('self: status, role, temporary roles and password reset on yourself are refused; profile is allowed', async () => {
  const env = await makeEnvWithSchema();
  addUser(env, 'super_admin');
  const me = addUser(env, 'super_admin');
  const rc = await rcAs(env, me);
  await assert.rejects(U.setStatus(rc, me.id, 'suspended'), guard('self'));
  await assert.rejects(U.setStatus(rc, me.id, 'disabled'), guard('self'));
  await assert.rejects(U.changeRole(rc, me.id, { role_id: roleRow(env, 'admin').id }), guard('self'));
  await assert.rejects(U.grantTempRole(rc, me.id, roleRow(env, 'admin').id, iso(env.__clock() + DAY)), guard('self'));
  await assert.rejects(U.revokeTempRole(rc, me.id, roleRow(env, 'admin').id), guard('self'));
  await assert.rejects(U.adminResetPassword(rc, me.id), guard('self'));
  const r = await U.updateProfile(rc, me.id, { full_name: 'New Name', job_title: 'Owner' });
  assert.deepEqual(Object.keys(r.prior).sort(), ['full_name', 'job_title']);
  assert.equal(r.row.full_name, 'New Name');
  assert.equal(row(env, me.id).status, 'active');
});

// ---------------------------------------------------------------- createUser

test('minting: admin cannot create admin or super; manager may create employee or guest only', async () => {
  const env = await makeEnvWithSchema();
  const cases = {
    super_admin: ['super_admin', 'admin', 'auditor', 'manager', 'employee', 'guest'],
    admin: ['auditor', 'manager', 'employee', 'guest'],
    manager: ['employee', 'guest'],
  };
  for (const [actorKey, allowed] of Object.entries(cases)) {
    const rc = await rcAs(env, addUser(env, actorKey));
    for (const key of ROLE_KEYS) {
      const email = `new-${actorKey}-${key}@acme.com`;
      const p = U.createUser(rc, { email, full_name: 'New Person', role_id: roleRow(env, key).id });
      if (allowed.includes(key)) {
        const u = await p;
        assert.equal(u.role_id, roleRow(env, key).id, `${actorKey} creates ${key}`);
      } else {
        await assert.rejects(p, guard('minting'), `${actorKey} creates ${key}`);
        assert.equal(count(env, 'SELECT COUNT(*) AS n FROM users WHERE email = ?', email), 0, 'no row written');
      }
    }
  }
});

test('createUser: invited, no password, normalised fields, created_by recorded', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const mgr = addUser(env, 'manager');
  const rc = await rcAs(env, admin);
  const u = await U.createUser(rc, {
    email: '  Jane.Doe@ACME.com ',
    full_name: '  Jane Doe ',
    role_id: String(roleRow(env, 'employee').id),
    username: 'JDoe',
    job_title: ' Engineer ',
    department: 'R&D',
    manager_id: mgr.id,
  });
  assert.equal(u.email, 'jane.doe@acme.com');
  assert.equal(u.username, 'jdoe');
  assert.equal(u.full_name, 'Jane Doe');
  assert.equal(u.job_title, 'Engineer');
  assert.equal(u.manager_id, mgr.id);
  assert.equal(u.status, 'invited');
  assert.equal(u.password_hash, null);
  assert.equal(u.password_salt, null);
  assert.equal(u.created_by, admin.id);
  assert.equal(u.perm_grants, '[]');
  assert.equal(u.employee_no, 'ACME000001');
});

test('createUser: explicit duplicates answer 409 with a sentence, and write nothing', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  await U.createUser(rc, { email: 'a@acme.com', full_name: 'A', role_id, username: 'alpha', employee_no: 'ACME000500' });
  const before = count(env, 'SELECT COUNT(*) AS n FROM users');
  await assert.rejects(U.createUser(rc, { email: 'A@Acme.COM', full_name: 'B', role_id }), http(409, /^Someone already has that email address\.$/));
  await assert.rejects(U.createUser(rc, { email: 'b@acme.com', full_name: 'B', role_id, username: 'ALPHA' }), http(409, /^That username is taken\.$/));
  await assert.rejects(U.createUser(rc, { email: 'b@acme.com', full_name: 'B', role_id, employee_no: 'acme000500' }), http(409, /^That employee number is taken\.$/));
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM users'), before);
  // Checked before a number is issued: a refused duplicate burns nothing.
  assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, '500');
  assert.equal((await U.createUser(rc, { email: 'c@acme.com', full_name: 'C', role_id })).employee_no, 'ACME000501');
});

test('createUser: UNIQUE races map to the same sentences; an auto number that loses a race is reissued', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  const origPrepare = env.DB.prepare.bind(env.DB);
  // A concurrent request inserts the conflicting row after our duplicate
  // checks and before our INSERT.
  const raceWith = (inject) => {
    let done = false;
    env.DB.prepare = (sql) => {
      if (!done && /^\s*INSERT INTO users/.test(sql)) {
        done = true;
        inject();
      }
      return origPrepare(sql);
    };
  };
  const racer = (fields) => () => addUser(env, 'employee', fields);
  raceWith(racer({ email: 'race@acme.com' }));
  await assert.rejects(U.createUser(rc, { email: 'race@acme.com', full_name: 'R', role_id }), http(409, /^Someone already has that email address\.$/));
  raceWith(racer({ username: 'racer' }));
  await assert.rejects(U.createUser(rc, { email: 'r2@acme.com', full_name: 'R', role_id, username: 'racer' }), http(409, /^That username is taken\.$/));
  raceWith(racer({ employee_no: 'ACME000900' }));
  await assert.rejects(U.createUser(rc, { email: 'r3@acme.com', full_name: 'R', role_id, employee_no: 'ACME000900' }), http(409, /^That employee number is taken\.$/));
  // The auto-issued number is taken under us: issue the next one instead.
  raceWith(() => {
    const high = env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value;
    addUser(env, 'employee', { employee_no: 'ACME' + high.padStart(6, '0') });
  });
  const u = await U.createUser(rc, { email: 'r4@acme.com', full_name: 'R', role_id });
  env.DB.prepare = origPrepare;
  assert.equal(u.employee_no, 'ACME000902');
  assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, '902', 'stored as a canonical integer');
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM users WHERE employee_no = 'ACME000901'"), 1);
});

test('createUser: manager must exist and be here; role must exist; status must be invited', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  const gone = addUser(env, 'employee', { status: 'disabled' });
  const invited = addUser(env, 'employee', { status: 'invited' });
  await assert.rejects(U.createUser(rc, { email: 'm1@acme.com', full_name: 'M', role_id, manager_id: 99999 }), invalid('manager_id'));
  await assert.rejects(U.createUser(rc, { email: 'm1@acme.com', full_name: 'M', role_id, manager_id: gone.id }), invalid('manager_id'));
  assert.equal((await U.createUser(rc, { email: 'm1@acme.com', full_name: 'M', role_id, manager_id: invited.id })).manager_id, invited.id);
  await assert.rejects(U.createUser(rc, { email: 'm2@acme.com', full_name: 'M', role_id: 99999 }), invalid('role_id'));
  await assert.rejects(U.createUser(rc, { email: 'm2@acme.com', full_name: 'M', role_id, status: 'active' }), invalid('status'));
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM users WHERE email = 'm2@acme.com'"), 0);
});

test('createUser: hostile input is a validation error, never a throw or a row', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  const base = { email: 'h@acme.com', full_name: 'H', role_id };
  const before = count(env, 'SELECT COUNT(*) AS n FROM users');
  // 'abc' is a perfectly good name, username or job title.
  const fine = (k, v) => v === 'abc' && ['full_name', 'username', 'job_title', 'department'].includes(k);
  for (const v of HOSTILE) {
    await assert.rejects(U.createUser(rc, v), invalid(), `input ${show(v)}`);
    for (const k of ['email', 'full_name', 'role_id']) {
      if (fine(k, v)) continue;
      await assert.rejects(U.createUser(rc, { ...base, [k]: v }), invalid(k), `${k} = ${show(v)}`);
    }
    for (const k of ['username', 'employee_no', 'job_title', 'department', 'manager_id']) {
      const blankish = v === null || v === undefined || v === '' || v === '   ';
      if (blankish || fine(k, v)) continue;
      await assert.rejects(U.createUser(rc, { ...base, [k]: v }), invalid(k), `${k} = ${show(v)}`);
    }
  }
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM users'), before);
  await assert.rejects(U.createUser(rc, { ...base, employee_no: 'ACME12345' }), invalid('employee_no'));
  await assert.rejects(U.createUser(rc, { ...base, employee_no: 'A000001' }), invalid('employee_no'));
  await assert.rejects(U.createUser(rc, { ...base, full_name: 'x'.repeat(201) }), invalid('full_name'));
  await assert.rejects(U.createUser({ env, nowMs: env.__clock() }, base), http(403), 'no actor, no account');
});

// ---------------------------------------------------------------- employee numbers

test('employee numbers: ORG_CODE + six digits, in sequence', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  const got = [];
  for (let i = 1; i <= 3; i++) got.push((await U.createUser(rc, { email: `s${i}@acme.com`, full_name: 'S', role_id })).employee_no);
  assert.deepEqual(got, ['ACME000001', 'ACME000002', 'ACME000003']);
  assert.equal(await U.nextEmployeeNo(env), 'ACME000004');
  assert.equal(await U.nextEmployeeNo(env), 'ACME000005', 'every call issues a fresh number');
});

test('employee numbers: never reused after disable or renumbering, never derived from a count', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const rc = await rcAs(env, admin);
  const role_id = roleRow(env, 'employee').id;
  const a = await U.createUser(rc, { email: 'n1@acme.com', full_name: 'N', role_id });
  const b = await U.createUser(rc, { email: 'n2@acme.com', full_name: 'N', role_id });
  const c = await U.createUser(rc, { email: 'n3@acme.com', full_name: 'N', role_id });
  await U.setStatus(rc, c.id, 'disabled');
  await U.updateProfile(rc, b.id, { employee_no: 'XYZ000001' }); // frees ACME000002 from the rows
  assert.equal((await U.createUser(rc, { email: 'n4@acme.com', full_name: 'N', role_id })).employee_no, 'ACME000004');
  assert.equal(a.employee_no, 'ACME000001');

  // Imported rows with no high-water mark: the next number follows the
  // highest existing one, not the number of rows.
  const env2 = await makeEnvWithSchema();
  const rc2 = await rcAs(env2, addUser(env2, 'admin'));
  addUser(env2, 'employee', { employee_no: 'ACME000050' });
  addUser(env2, 'employee', { employee_no: 'ACME000007' });
  addUser(env2, 'employee', { employee_no: 'OTHER000900' });
  addUser(env2, 'employee', { employee_no: 'ACMEX00999' });
  assert.equal((await U.createUser(rc2, { email: 'i@acme.com', full_name: 'I', role_id: roleRow(env2, 'employee').id })).employee_no, 'ACME000051');
});

test('employee numbers: the high-water mark leads, explicit numbers raise it, nothing lowers it', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  env.DB.q("INSERT INTO meta (key, value) VALUES ('employee_no_high', '41')");
  assert.equal(await U.nextEmployeeNo(env), 'ACME000042');
  await U.createUser(rc, { email: 'x1@acme.com', full_name: 'X', role_id, employee_no: 'ACME000010' });
  assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, '42', 'a lower explicit number never lowers it');
  await U.createUser(rc, { email: 'x2@acme.com', full_name: 'X', role_id, employee_no: 'ACME000500' });
  assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, '500');
  await U.createUser(rc, { email: 'x3@acme.com', full_name: 'X', role_id, employee_no: 'OTHER000900' });
  assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, '500', 'another prefix does not move it');
  assert.equal((await U.createUser(rc, { email: 'x4@acme.com', full_name: 'X', role_id })).employee_no, 'ACME000501');
});

test('employee numbers: bad ORG_CODE falls back to EMP; 999999 is the end; an unreadable mark refuses', async () => {
  for (const code of ['acme', 'A', 'TOOLONGCO', '', 'AC1', undefined]) {
    const env = await makeEnvWithSchema({ vars: { ORG_CODE: code } });
    assert.equal(await U.nextEmployeeNo(env), 'EMP000001', show(code));
  }
  let env = await makeEnvWithSchema();
  let rc = await rcAs(env, addUser(env, 'admin'));
  const role_id = roleRow(env, 'employee').id;
  addUser(env, 'employee', { employee_no: 'ACME999999' });
  await assert.rejects(U.createUser(rc, { email: 'e1@acme.com', full_name: 'E', role_id }), http(409, /run out/));
  assert.equal((await U.createUser(rc, { email: 'e1@acme.com', full_name: 'E', role_id, employee_no: 'ACME000002' })).employee_no, 'ACME000002');

  env = await makeEnvWithSchema();
  env.DB.q("INSERT INTO meta (key, value) VALUES ('employee_no_high', '999999')");
  await assert.rejects(U.nextEmployeeNo(env), http(409, /run out/));
  assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, '999999');

  for (const bad of ['abc', '', '007', '-', '12abc', '99999999999999999999']) {
    env = await makeEnvWithSchema();
    rc = await rcAs(env, addUser(env, 'admin'));
    env.DB.q("INSERT INTO meta (key, value) VALUES ('employee_no_high', ?)", bad);
    const before = count(env, 'SELECT COUNT(*) AS n FROM users');
    await assert.rejects(U.createUser(rc, { email: 'e2@acme.com', full_name: 'E', role_id }), http(409, /can’t be read/), show(bad));
    assert.equal(count(env, 'SELECT COUNT(*) AS n FROM users'), before, 'no row written');
    assert.equal(env.DB.q("SELECT value FROM meta WHERE key = 'employee_no_high'")[0].value, bad, 'left for a person to repair');
  }
});

// ---------------------------------------------------------------- status

test('setStatus: the transition table', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'super_admin'));
  const cases = [
    ['active', 'suspended', true],
    ['active', 'disabled', true],
    ['suspended', 'active', true],
    ['suspended', 'disabled', true],
    ['disabled', 'active', true],
    ['invited', 'disabled', true],
    ['disabled', 'invited', true, null],
    ['disabled', 'invited', false],
    ['disabled', 'active', false, null],
    ['active', 'active', false],
    ['active', 'invited', false],
    ['suspended', 'suspended', false],
    ['suspended', 'invited', false],
    ['invited', 'active', false],
    ['invited', 'suspended', false],
    ['disabled', 'suspended', false],
    ['disabled', 'disabled', false],
    ['banned', 'disabled', false],
    ['', 'active', false],
  ];
  for (const [from, to, ok, pw] of cases) {
    const u = addUser(env, 'employee', { status: from, password_hash: pw === undefined ? 'placeholder' : pw });
    const p = U.setStatus(rc, u.id, to);
    if (ok) assert.equal((await p).row.status, to, `${from} → ${to}`);
    else {
      await assert.rejects(p, guard('invalid_transition'), `${from} → ${to}`);
      assert.equal(row(env, u.id).status, from);
    }
  }
});

test('setStatus: leaving active ends sessions and grace in the same write; disabled_at; invitations revoked', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const rc = await rcAs(env, admin);
  const u = addUser(env, 'employee');
  const bystander = addUser(env, 'employee');
  const s1 = await createSession(rc, u, {});
  const s2 = await createSession(rc, u, {});
  const s3 = await createSession(rc, bystander, {});
  addGrace(env, u.id, 'dev-1');
  addGrace(env, bystander.id, 'dev-2');

  await U.setStatus(rc, u.id, 'suspended');
  for (const s of [s1, s2]) {
    const r = env.DB.q('SELECT revoked_at, revoke_reason FROM sessions WHERE id = ?', s.id)[0];
    assert.ok(r.revoked_at);
    assert.equal(r.revoke_reason, 'user.suspended');
  }
  assert.equal(env.DB.q('SELECT revoked_at FROM sessions WHERE id = ?', s3.id)[0].revoked_at, null);
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM mfa_grace WHERE user_id = ?', u.id), 0);
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM mfa_grace WHERE user_id = ?', bystander.id), 1);
  assert.equal(row(env, u.id).disabled_at, null, 'suspension is not disabling');

  await U.setStatus(rc, u.id, 'disabled');
  assert.equal(row(env, u.id).disabled_at, iso(rc.nowMs));
  await U.setStatus(rc, u.id, 'active');
  assert.equal(row(env, u.id).disabled_at, null);

  const inv = addUser(env, 'employee', { status: 'invited' });
  env.DB.q(
    `INSERT INTO invitations (token_hash, user_id, email, role_id, created_at, expires_at) VALUES ('h1', ?, ?, ?, ?, ?)`,
    inv.id,
    inv.email,
    inv.role_id,
    iso(rc.nowMs),
    iso(rc.nowMs + DAY),
  );
  await U.setStatus(rc, inv.id, 'disabled');
  assert.ok(env.DB.q("SELECT revoked_at FROM invitations WHERE token_hash = 'h1'")[0].revoked_at);
});

test('setStatus: each transition needs its own permission', async () => {
  const env = await makeEnvWithSchema();
  const actor = addUser(env, 'manager', { grants: JSON.stringify(['users.suspend']) });
  const rc = await rcAs(env, actor);
  const u = addUser(env, 'employee');
  await U.setStatus(rc, u.id, 'suspended');
  await assert.rejects(U.setStatus(rc, u.id, 'disabled'), http(403));
  await U.setStatus(rc, u.id, 'active');
  await assert.rejects(U.setStatus(rc, u.id, 'disabled'), http(403));
  const plain = await rcAs(env, addUser(env, 'manager'));
  await assert.rejects(U.setStatus(plain, u.id, 'suspended'), http(403));
  assert.equal(row(env, u.id).status, 'active');
});

test('setStatus: hostile statuses and ids', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const u = addUser(env, 'employee');
  for (const v of [...HOSTILE, 'Active', 'banned', 'deleted']) {
    await assert.rejects(U.setStatus(rc, u.id, v), invalid('status'), show(v));
    await assert.rejects(U.setStatus(rc, v, 'suspended'), http(404), show(v));
  }
  assert.equal(row(env, u.id).status, 'active');
});

// ---------------------------------------------------------------- roles

test('changeRole: reserved grants refused, grants must be held, denies are catalogue keys, prior is the undo payload', async () => {
  const env = await makeEnvWithSchema();
  const sup = addUser(env, 'super_admin');
  const admin = addUser(env, 'admin');
  const u = addUser(env, 'employee', { grants: '["directory.view"]', denies: '["team.view"]' });
  const emp = roleRow(env, 'employee').id;
  const rcSup = await rcAs(env, sup);
  for (const k of ['users.reset_password', 'roles.manage', 'audit.revert', 'gate.open', 'security.manage', 'destinations.manage', '*']) {
    await assert.rejects(U.changeRole(rcSup, u.id, { role_id: emp, perm_grants: [k] }), guard('reserved'), k);
  }
  await assert.rejects(U.changeRole(rcSup, u.id, { role_id: emp, perm_grants: ['no.such.perm'] }), invalid('perm_grants'));
  await assert.rejects(U.changeRole(rcSup, u.id, { role_id: emp, perm_denies: ['no.such.perm'] }), invalid('perm_denies'));
  await assert.rejects(U.changeRole(rcSup, u.id, { role_id: emp, perm_denies: ['*'] }), invalid('perm_denies'));
  const mgr = addUser(env, 'manager', { grants: '["users.roles"]' });
  await assert.rejects(U.changeRole(await rcAs(env, mgr), u.id, { role_id: emp, perm_grants: ['devices.approve'] }), guard('minting'));
  assert.equal(row(env, u.id).perm_grants, '["directory.view"]');

  const r = await U.changeRole(await rcAs(env, admin), u.id, {
    role_id: roleRow(env, 'guest').id,
    perm_grants: ['network.manage', 'directory.view', 'network.manage'],
    perm_denies: ['audit.view'],
  });
  assert.deepEqual(r.prior, { role_id: emp, perm_grants: ['directory.view'], perm_denies: ['team.view'] });
  assert.equal(r.row.perm_grants, JSON.stringify(['directory.view', 'network.manage']));
  assert.equal(r.row.perm_denies, '["audit.view"]');

  // Omitted lists are kept as stored; an unreadable one goes into prior verbatim.
  env.DB.q('UPDATE users SET perm_grants = ? WHERE id = ?', 'not json', u.id);
  const r2 = await U.changeRole(rcSup, u.id, { role_id: emp });
  assert.equal(r2.row.perm_grants, 'not json');
  assert.equal(r2.prior.perm_grants, 'not json');
  assert.equal(r2.row.role_id, emp);
});

test('changeRole: hostile input', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'super_admin'));
  const u = addUser(env, 'employee');
  const emp = roleRow(env, 'employee').id;
  for (const v of HOSTILE) {
    await assert.rejects(U.changeRole(rc, u.id, v), (e) => e instanceof ValidationError, `input ${show(v)}`);
    await assert.rejects(U.changeRole(rc, u.id, { role_id: v }), invalid('role_id'), `role_id ${show(v)}`);
    if (v !== undefined) {
      await assert.rejects(U.changeRole(rc, u.id, { role_id: emp, perm_grants: Array.isArray(v) ? [v] : v }), (e) => e instanceof HttpError, `grants ${show(v)}`);
      await assert.rejects(U.changeRole(rc, u.id, { role_id: emp, perm_denies: Array.isArray(v) ? [v] : v }), invalid('perm_denies'), `denies ${show(v)}`);
    }
    await assert.rejects(U.changeRole(rc, v, { role_id: emp }), http(404), `id ${show(v)}`);
  }
  assert.equal(row(env, u.id).perm_grants, '[]');
});

test('grantTempRole: expiry required, in the future, at most 90 days; minting; prior', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const u = addUser(env, 'employee');
  const rc = await rcAs(env, admin);
  const auditor = roleRow(env, 'auditor').id;
  const t = rc.nowMs;
  for (const v of [...HOSTILE, '42', '2026-13-45T00:00:00Z', '2026-01-07', iso(t - 1), iso(t), iso(t + 90 * DAY + 1000)]) {
    await assert.rejects(U.grantTempRole(rc, u.id, auditor, v), invalid('expires_at'), show(v));
  }
  for (const key of ['admin', 'super_admin']) {
    await assert.rejects(U.grantTempRole(rc, u.id, roleRow(env, key).id, iso(t + DAY)), guard('minting'), key);
  }
  for (const v of HOSTILE) await assert.rejects(U.grantTempRole(rc, u.id, v, iso(t + DAY)), invalid('role_id'), show(v));
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM user_roles'), 0);

  const r1 = await U.grantTempRole(rc, u.id, auditor, iso(t + 90 * DAY));
  assert.equal(r1.prior, null);
  const a = await effectivePermissions(env, row(env, u.id), t);
  assert.equal(a.rank, 60);
  assert.equal(a.sources['audit.view'], 'temp_role');
  const r2 = await U.grantTempRole(rc, u.id, auditor, '2026-01-20T00:00:00Z');
  assert.deepEqual(r2.prior, { expires_at: iso(t + 90 * DAY), granted_by: admin.id });
  assert.equal(env.DB.q('SELECT expires_at FROM user_roles WHERE user_id = ?', u.id)[0].expires_at, '2026-01-20T00:00:00.000Z');

  const rv = await U.revokeTempRole(rc, u.id, auditor);
  assert.deepEqual(rv.prior, { expires_at: '2026-01-20T00:00:00.000Z', granted_by: admin.id });
  await assert.rejects(U.revokeTempRole(rc, u.id, auditor), http(404));
  for (const v of HOSTILE) await assert.rejects(U.revokeTempRole(rc, u.id, v), http(404), show(v));
});

// ---------------------------------------------------------------- profile

test('updateProfile: own name without users.edit; rank for others; prior holds only what changed', async () => {
  const env = await makeEnvWithSchema();
  const admin = addUser(env, 'admin');
  const emp = addUser(env, 'employee', { full_name: 'Old Name', username: 'olduser' });
  const rcEmp = await rcAs(env, emp);
  const r = await U.updateProfile(rcEmp, emp.id, { full_name: 'New Name' });
  assert.deepEqual(r.prior, { full_name: 'Old Name' });
  await assert.rejects(U.updateProfile(rcEmp, emp.id, { job_title: 'CEO' }), http(403));
  await assert.rejects(U.updateProfile(rcEmp, emp.id, { employee_no: 'ACME000099' }), http(403));
  const other = addUser(env, 'guest');
  await assert.rejects(U.updateProfile(rcEmp, other.id, { full_name: 'X' }), http(403));

  const rc = await rcAs(env, admin);
  const mgr = addUser(env, 'manager');
  const r2 = await U.updateProfile(rc, emp.id, {
    full_name: 'New Name',
    username: 'NewUser',
    job_title: 'Engineer',
    department: '',
    manager_id: mgr.id,
    employee_no: 'acme000123',
    phone: '+1 (555) 010-2000',
    role_id: roleRow(env, 'admin').id,
    status: 'disabled',
  });
  assert.deepEqual(r2.prior, { username: 'olduser', job_title: null, manager_id: null, employee_no: null, phone: null });
  assert.equal(r2.row.username, 'newuser');
  assert.equal(r2.row.employee_no, 'ACME000123');
  assert.equal(r2.row.role_id, roleRow(env, 'employee').id, 'unknown keys are never written');
  assert.equal(r2.row.status, 'active');

  const stamp = row(env, emp.id).updated_at;
  env.__advance(MINUTE);
  const same = await U.updateProfile(await rcAs(env, admin), emp.id, { full_name: 'New Name' });
  assert.deepEqual(same.prior, {});
  assert.equal(row(env, emp.id).updated_at, stamp, 'no change, no write');

  const rc2 = await rcAs(env, admin);
  addUser(env, 'employee', { username: 'taken', employee_no: 'ACME000777' });
  await assert.rejects(U.updateProfile(rc2, emp.id, { username: 'taken' }), http(409, /^That username is taken\.$/));
  await assert.rejects(U.updateProfile(rc2, emp.id, { employee_no: 'ACME000777' }), http(409, /^That employee number is taken\.$/));
  await assert.rejects(U.updateProfile(rc2, emp.id, { employee_no: '' }), invalid('employee_no'));
  await assert.rejects(U.updateProfile(rc2, emp.id, { manager_id: emp.id }), invalid('manager_id'));
  await assert.rejects(U.updateProfile(rc2, emp.id, { manager_id: addUser(env, 'employee', { status: 'disabled' }).id }), invalid('manager_id'));
  await assert.rejects(U.updateProfile(rc2, admin.id === emp.id ? 0 : addUser(env, 'admin').id, { job_title: 'x' }), guard('rank'));
});

test('updateProfile: hostile input', async () => {
  const env = await makeEnvWithSchema();
  const rc = await rcAs(env, addUser(env, 'admin'));
  const u = addUser(env, 'employee');
  const before = row(env, u.id);
  for (const v of HOSTILE) {
    if (v && typeof v === 'object' && !Array.isArray(v)) assert.deepEqual((await U.updateProfile(rc, u.id, v)).prior, {}, 'an empty patch changes nothing');
    else await assert.rejects(U.updateProfile(rc, u.id, v), invalid(), `patch ${show(v)}`);
    await assert.rejects(U.updateProfile(rc, v, { full_name: 'x' }), http(404), `id ${show(v)}`);
    if (v !== 'abc') await assert.rejects(U.updateProfile(rc, u.id, { full_name: v }), invalid('full_name'), `full_name ${show(v)}`);
    await assert.rejects(U.updateProfile(rc, u.id, { employee_no: v }), invalid('employee_no'), `employee_no ${show(v)}`);
    const blankish = v === null || v === undefined || v === '' || v === '   ';
    if (!blankish) {
      for (const k of ['username', 'job_title', 'department', 'manager_id', 'phone']) {
        if (v === 'abc' && ['username', 'job_title', 'department'].includes(k)) continue;
        await assert.rejects(U.updateProfile(rc, u.id, { [k]: v }), invalid(k), `${k} ${show(v)}`);
      }
    }
  }
  assert.deepEqual(row(env, u.id), before);
});

// ---------------------------------------------------------------- lockout

test('lockout: ten failures lock for fifteen minutes; nine do not; clear unlocks; the lock lapses', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'employee');
  const t = env.__clock();
  for (let i = 1; i < U.LOCK_AFTER; i++) await U.recordLoginFailure(env, u, t);
  assert.equal(row(env, u.id).failed_logins, 9);
  assert.equal(U.isLocked(row(env, u.id), t), false);
  await U.recordLoginFailure(env, u, t);
  assert.equal(row(env, u.id).locked_until, iso(t + 15 * MINUTE));
  assert.equal(U.isLocked(row(env, u.id), t), true);
  assert.equal(U.isLocked(row(env, u.id), t + 15 * MINUTE - 1), true);
  assert.equal(U.isLocked(row(env, u.id), t + 15 * MINUTE), false);
  await U.clearLoginFailures(env, u.id);
  assert.equal(row(env, u.id).failed_logins, 0);
  assert.equal(row(env, u.id).locked_until, null);
  assert.equal(U.isLocked(row(env, u.id), t), false);

  // Concurrent failures do not under-count.
  await Promise.all(Array.from({ length: 10 }, () => U.recordLoginFailure(env, u, t)));
  assert.equal(row(env, u.id).failed_logins, 10);
  assert.equal(U.isLocked(row(env, u.id), t), true);
  for (const v of HOSTILE) {
    await U.recordLoginFailure(env, v, t);
    await U.recordLoginFailure(env, { id: v }, t);
    await U.clearLoginFailures(env, v);
  }
  assert.equal(row(env, u.id).failed_logins, 10);
});

test('isLocked: a lock that cannot be read is a lock (fail closed)', async () => {
  const t = Date.UTC(2026, 0, 6, 15);
  for (const v of ['garbage', '42', '', '2026-01-06', '2026-13-01T00:00:00Z', 'NaN', 0, 1, true, {}, []]) {
    assert.equal(U.isLocked({ locked_until: v }, t), true, show(v));
  }
  assert.equal(U.isLocked({ locked_until: null }, t), false);
  assert.equal(U.isLocked({}, t), false);
  assert.equal(U.isLocked(null, t), false);
  assert.equal(U.isLocked({ locked_until: iso(t - 1) }, t), false);
  for (const bad of [NaN, undefined, null, 'abc', Infinity]) {
    assert.equal(U.isLocked({ locked_until: iso(t - 1) }, bad), true, `clock ${show(bad)}`);
  }
});

test('knownDeviceFor: signed in here before, and the device is not blocked', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'employee');
  const other = addUser(env, 'employee');
  const t = iso(env.__clock());
  for (const [id, status] of [['dev-ok', 'approved'], ['dev-pending', 'pending'], ['dev-blocked', 'blocked'], ['dev-weird', 'quarantined']]) {
    env.DB.q('INSERT INTO devices (id, status, first_seen, last_seen) VALUES (?, ?, ?, ?)', id, status, t, t);
    env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 1)', id, u.id, t, t);
  }
  env.DB.q('INSERT INTO device_users (device_id, user_id, first_seen, last_seen, sign_ins) VALUES (?, ?, ?, ?, 1)', 'dev-ghost', u.id, t, t);
  assert.equal(await U.knownDeviceFor(env, u.id, 'dev-ok'), true);
  assert.equal(await U.knownDeviceFor(env, u.id, 'dev-pending'), true);
  assert.equal(await U.knownDeviceFor(env, u.id, 'dev-blocked'), false);
  assert.equal(await U.knownDeviceFor(env, u.id, 'dev-weird'), false);
  assert.equal(await U.knownDeviceFor(env, u.id, 'dev-ghost'), false, 'ledger row without a device row');
  assert.equal(await U.knownDeviceFor(env, other.id, 'dev-ok'), false, 'someone else’s device');
  for (const v of HOSTILE) {
    assert.equal(await U.knownDeviceFor(env, u.id, v), false, show(v));
    assert.equal(await U.knownDeviceFor(env, v, 'dev-ok'), false, show(v));
  }
});

// ---------------------------------------------------------------- passwords

test('validatePassword: 12–1024 characters, not the email or username, not one character', () => {
  const ok = ['correct horse battery', 'x'.repeat(11) + 'y', 'ab'.repeat(512), '🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔐'];
  for (const p of ok) U.validatePassword(p, { email: 'jane@acme.com', username: 'jane' });
  const bad = [...HOSTILE, 'short', 'x'.repeat(11), 'a'.repeat(30), ' '.repeat(20), 'ab'.repeat(512) + 'c', 'x'.repeat(5000)];
  for (const p of bad) assert.throws(() => U.validatePassword(p), invalid('password'), show(p));
  assert.throws(() => U.validatePassword('Jane.Doe@Acme.com', { email: 'jane.doe@acme.com' }), invalid());
  assert.throws(() => U.validatePassword('JaneTheUsername', { username: 'janetheusername' }), invalid());
  assert.throws(() => U.validatePassword('short', { field: 'next' }), invalid('next'));
});

test('changeOwnPassword: drops OTHER sessions only, and moves the pin on rather than clearing it', async () => {
  for (const [policy, expectPin] of [[undefined, null], [{ mfa_policy: 'required' }, 'mfa_enroll']]) {
    const env = await makeEnvWithSchema();
    const u = addUser(env, 'employee');
    const other = addUser(env, 'employee');
    await U.setPassword(env, u.id, 'correct horse battery', { mustChange: true });
    assert.equal(row(env, u.id).must_change_password, 1);
    const rc0 = await rcAs(env, u);
    const s1 = await createSession(rc0, u, { pinned: 'password_change' });
    const s2 = await createSession(rc0, u, {});
    const s3 = await createSession(rc0, u, {});
    const s4 = await createSession(rc0, other, {});
    const rc = await rcAs(env, u, { session: { id: s1.id, pinned: 'password_change' }, policy });
    const r = await U.changeOwnPassword(rc, 'correct horse battery', 'a brand new passphrase');
    assert.equal(r.pinned, expectPin);
    const sess = (id) => env.DB.q('SELECT * FROM sessions WHERE id = ?', id)[0];
    assert.equal(sess(s1.id).revoked_at, null, 'this session survives');
    assert.equal(sess(s1.id).pinned, expectPin);
    for (const s of [s2, s3]) assert.equal(sess(s.id).revoke_reason, 'password.change');
    assert.equal(sess(s4.id).revoked_at, null, 'someone else’s session is untouched');
    const after = row(env, u.id);
    assert.equal(after.must_change_password, 0);
    assert.equal(await verifyPassword('a brand new passphrase', after), true);
    assert.equal(await verifyPassword('correct horse battery', after), false);
  }
});

test('changeOwnPassword: the current password is checked after charging; refusals change nothing', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'employee', { email: 'jane@acme.com' });
  await U.setPassword(env, u.id, 'correct horse battery');
  const rc = await rcAs(env, u);
  const hash = row(env, u.id).password_hash;
  await assert.rejects(U.changeOwnPassword(rc, 'wrong password here', 'a brand new passphrase'), invalid('current'));
  assert.equal(count(env, "SELECT COUNT(*) AS n FROM auth_attempts WHERE kind = 'curpw_user' AND subject = ?", String(u.id)), 1);
  await assert.rejects(U.changeOwnPassword(rc, 'correct horse battery', 'short'), invalid('next'));
  await assert.rejects(U.changeOwnPassword(rc, 'correct horse battery', 'jane@acme.com'), invalid('next'));
  await assert.rejects(U.changeOwnPassword(rc, 'correct horse battery', 'correct horse battery'), invalid('next'));
  for (const v of HOSTILE) {
    env.DB.q('DELETE FROM auth_attempts');
    await assert.rejects(U.changeOwnPassword(rc, v, 'a brand new passphrase'), invalid('current'), show(v));
  }
  assert.equal(row(env, u.id).password_hash, hash);

  // The eleventh attempt in the window is refused even with the right password.
  const t = iso(env.__clock());
  for (let i = 0; i < 20; i++) env.DB.q("INSERT INTO auth_attempts (kind, subject, at) VALUES ('curpw_user', ?, ?)", String(u.id), t);
  await assert.rejects(U.changeOwnPassword(rc, 'correct horse battery', 'a brand new passphrase'), http(429));
  assert.equal(row(env, u.id).password_hash, hash);
  await assert.rejects(U.changeOwnPassword({ env, nowMs: env.__clock() }, 'a', 'b'), http(401));
});

test('adminResetPassword: Super Admins only, rank-guarded, shown once, pins the change, ends sessions and grace', async () => {
  const env = await makeEnvWithSchema();
  const sup = addUser(env, 'super_admin');
  const sup2 = addUser(env, 'super_admin');
  const admin = addUser(env, 'admin');
  const u = addUser(env, 'employee');
  await U.setPassword(env, u.id, 'correct horse battery');
  env.DB.q("UPDATE users SET failed_logins = 12, locked_until = '2099-01-01T00:00:00.000Z' WHERE id = ?", u.id);
  const rc = await rcAs(env, sup);
  const s = await createSession(rc, u, {});
  addGrace(env, u.id, 'dev-9');

  await assert.rejects(U.adminResetPassword(await rcAs(env, admin), u.id), http(403));
  assert.equal(env.DB.q('SELECT revoked_at FROM sessions WHERE id = ?', s.id)[0].revoked_at, null);

  const { temporary_password: pw, ...rest } = await U.adminResetPassword(rc, u.id);
  assert.deepEqual(rest, {});
  assert.match(pw, /^[2-9A-HJKMNP-Z]{5}(-[2-9A-HJKMNP-Z]{5}){3}$/);
  const after = row(env, u.id);
  assert.equal(after.must_change_password, 1);
  assert.equal(after.failed_logins, 0);
  assert.equal(after.locked_until, null);
  assert.equal(await verifyPassword(pw, after), true);
  assert.ok(!Object.values(after).includes(pw), 'never stored in the clear');
  assert.equal(env.DB.q('SELECT revoke_reason FROM sessions WHERE id = ?', s.id)[0].revoke_reason, 'password.reset');
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM mfa_grace WHERE user_id = ?', u.id), 0);
  assert.notEqual((await U.adminResetPassword(rc, u.id)).temporary_password, pw);

  assert.match((await U.adminResetPassword(rc, sup2.id)).temporary_password, /-/, 'peers');
  await assert.rejects(U.adminResetPassword(rc, addUser(env, 'employee', { status: 'invited' }).id), http(409));
  for (const v of HOSTILE) await assert.rejects(U.adminResetPassword(rc, v), http(404), show(v));
});

// ---------------------------------------------------------------- reading

test('findUserByIdentifier and getUser: case-insensitive; hostile input finds nobody', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'employee', { email: 'jane@acme.com', username: 'jane.d' });
  assert.equal((await U.findUserByIdentifier(env, '  JANE@Acme.com ')).id, u.id);
  assert.equal((await U.findUserByIdentifier(env, 'Jane.D')).id, u.id);
  assert.equal(await U.findUserByIdentifier(env, 'jane'), null);
  assert.equal(await U.findUserByIdentifier(env, "jane@acme.com' OR 1=1 --"), null);
  assert.equal((await U.getUser(env, String(u.id))).id, u.id);
  for (const v of [...HOSTILE, '%', '_', '*', 'x'.repeat(5000)]) {
    assert.equal(await U.findUserByIdentifier(env, v), null, show(v));
    if (v !== 'abc') assert.equal(await U.getUser(env, v), null, show(v));
  }
});

test('publicUser: exactly the published shape; never a secret; locked only for admin views', async () => {
  const env = await makeEnvWithSchema();
  const u = addUser(env, 'manager', { employee_no: 'ACME000001' });
  env.DB.q("UPDATE users SET password_salt = 'salt', failed_logins = 3, locked_until = '2099-01-01T00:00:00.000Z' WHERE id = ?", u.id);
  const full = row(env, u.id);
  const authz = await effectivePermissions(env, full, env.__clock());
  const keys = ['id', 'email', 'username', 'full_name', 'employee_no', 'job_title', 'department', 'manager_id', 'status', 'role', 'mfa_policy', 'last_login_at', 'created_at'];
  for (const p of [U.publicUser(full, authz), U.publicUser(full, roleRow(env, 'manager')), U.publicUser(full, authz.role)]) {
    assert.deepEqual(Object.keys(p).sort(), [...keys].sort());
    assert.deepEqual(p.role, { id: roleRow(env, 'manager').id, key: 'manager', name: 'Manager', rank: 50 });
    const text = JSON.stringify(p);
    for (const secret of ['placeholder', 'salt', 'failed_logins', 'locked_until', '2099']) assert.ok(!text.includes(secret), secret);
  }
  const admin = U.publicUser(full, authz, { withLocked: true, nowMs: env.__clock() });
  assert.equal(admin.locked, true);
  assert.equal(U.publicUser({ ...full, mfa_policy: 'sometimes' }).mfa_policy, 'required');
  assert.equal(U.publicUser(null), null);
});

test('listUsers: filters, escaped search, paging, hostile filters', async () => {
  const env = await makeEnvWithSchema();
  const mgr = addUser(env, 'manager', { full_name: 'Mona Manager' });
  for (let i = 0; i < 5; i++) addUser(env, 'employee', { full_name: `Emp ${i}` });
  addUser(env, 'employee', { full_name: '100% Real', status: 'suspended' });
  env.DB.q('UPDATE users SET manager_id = ? WHERE full_name LIKE ?', mgr.id, 'Emp%');
  const all = await U.listUsers(env, {});
  assert.equal(all.total, 7);
  assert.ok(all.users.every((p) => !('password_hash' in p) && p.role.key));
  assert.equal((await U.listUsers(env, { status: 'suspended' })).total, 1);
  assert.equal((await U.listUsers(env, { q: '100%' })).total, 1);
  assert.equal((await U.listUsers(env, { q: '%' })).total, 1, '% is a literal');
  assert.equal((await U.listUsers(env, { q: '_' })).total, 0, '_ is a literal');
  assert.equal((await U.listUsers(env, { role: 'manager' })).total, 1);
  assert.equal((await U.listUsers(env, { role: roleRow(env, 'employee').id })).total, 6);
  assert.equal((await U.listUsers(env, { managerId: mgr.id })).total, 5);
  const page = await U.listUsers(env, { limit: 2, offset: 2 });
  assert.equal(page.users.length, 2);
  assert.equal(page.total, 7);
  for (const v of HOSTILE) {
    // 'abc' is a real search term and a (non-existent) role key: it rightly matches nobody.
    const r = await U.listUsers(env, { status: v, q: v === 'abc' ? undefined : v, role: v === 'abc' ? undefined : v, managerId: v, limit: v, offset: v });
    assert.equal(r.total, 7, show(v));
    await U.listUsers(env, v);
  }
  const locked = await U.listUsers(env, { withLocked: true });
  assert.ok(locked.users.every((p) => p.locked === false));
});

test('mfaPolicyFor: person over portal; Super Admin always required; unrecognised reads required', async () => {
  const env = await makeEnvWithSchema();
  const sup = addUser(env, 'super_admin');
  const authz = await effectivePermissions(env, sup, env.__clock());
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'prompt' }, { mfa_policy: 'prompt' }, authz), 'required');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'prompt', role_key: 'super_admin' }, undefined), 'required');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'inherit' }, { mfa_policy: 'required' }), 'required');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'inherit' }, { mfa_policy: 'prompt' }), 'prompt');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'inherit' }, undefined), 'prompt', '§5 default');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'inherit' }, {}), 'prompt');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'required' }, { mfa_policy: 'prompt' }), 'required');
  assert.equal(U.mfaPolicyFor({ mfa_policy: 'prompt' }, { mfa_policy: 'required' }), 'prompt');
  for (const v of [null, '', 'sometimes', 1, {}, 'Prompt']) {
    assert.equal(U.mfaPolicyFor({ mfa_policy: v }, { mfa_policy: 'prompt' }), 'required', `own ${show(v)}`);
    assert.equal(U.mfaPolicyFor({ mfa_policy: 'inherit' }, { mfa_policy: v }), 'required', `global ${show(v)}`);
  }
});

test('countActiveUsers, anyUsers, createOwner (once, and only while empty)', async () => {
  const env = await makeEnvWithSchema();
  assert.equal(await U.anyUsers(env), false);
  assert.equal(await U.countActiveUsers(env), 0);
  for (const v of HOSTILE) await assert.rejects(U.createOwner(env, v, env.__clock()), invalid(), show(v));
  await assert.rejects(U.createOwner(env, { email: 'o@acme.com', full_name: 'Owner', password: 'short' }), invalid('password'));
  const results = await Promise.allSettled([
    U.createOwner(env, { email: 'o@acme.com', full_name: 'Owner', password: 'correct horse battery' }, env.__clock()),
    U.createOwner(env, { email: 'p@acme.com', full_name: 'Other', password: 'correct horse battery' }, env.__clock()),
  ]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  const owner = results.find((r) => r.status === 'fulfilled').value;
  assert.equal(owner.status, 'active');
  assert.equal(owner.role_id, roleRow(env, 'super_admin').id);
  assert.match(owner.employee_no, /^ACME00000\d$/);
  assert.equal(await verifyPassword('correct horse battery', owner), true);
  assert.equal(count(env, 'SELECT COUNT(*) AS n FROM users'), 1);
  await assert.rejects(U.createOwner(env, { email: 'q@acme.com', full_name: 'Q', password: 'correct horse battery' }), http(409));
  assert.equal(await U.anyUsers(env), true);
  addUser(env, 'employee', { status: 'suspended' });
  assert.equal(await U.countActiveUsers(env), 1);
});

await run();
