// Who may do what in the admin console, over HTTP (CONTRACTS §6, §8.4; B §4;
// A §9): rank, minting, reserved permissions, step-up, and the last Super
// Admin — by others, by themselves, and through a revert.

import { test, assert, run } from '../helpers/t.js';
import {
  freshEnv, bootstrap, makeUser, stepUp, client, roleId, q, count, auditRows, advance, setSetting, MINUTE, DAY, nowIso,
} from '../helpers/flows.js';
import { Router } from '../../src/router.js';
import * as adminApi from '../../src/api/admin.js';
import * as securityApi from '../../src/api/admin-security.js';
import { RESERVED, SYSTEM_ROLES } from '../../src/catalog.js';

const ROUTES = securityApi.register(adminApi.register(new Router())).routes;

function concrete(pattern, ids = {}) {
  return pattern.replace(/:([a-zA-Z_]+)/g, (_, n) => String(ids[n] ?? '1'));
}

function call(c, route, ids) {
  const path = concrete(route.pattern, ids);
  return route.method === 'GET' ? c.get(path) : c.request(route.method, path, {});
}

function permsOf(route) {
  const p = route.opts.perm;
  if (typeof p === 'string') return [p];
  return Array.isArray(route.opts.anyOf) ? route.opts.anyOf : [];
}

const AUDITOR = new Set(SYSTEM_ROLES.find((r) => r.key === 'auditor').permissions);

let shared = null;
async function world() {
  if (shared) return shared;
  const env = freshEnv();
  const owner = await bootstrap(env);
  const admin = await makeUser(env, owner.client, { role: 'admin', totp: true });
  const admin2 = await makeUser(env, owner.client, { role: 'admin', totp: true });
  const manager = await makeUser(env, owner.client, { role: 'manager', totp: true });
  const auditor = await makeUser(env, owner.client, { role: 'auditor', totp: true });
  const employee = await makeUser(env, owner.client, { role: 'employee', totp: true });
  shared = { env, owner, admin, admin2, manager, auditor, employee };
  return shared;
}

function snapshot(env) {
  return JSON.stringify({
    users: q(env, 'SELECT id, status, role_id, perm_grants, perm_denies, full_name, password_hash FROM users ORDER BY id'),
    roles: q(env, 'SELECT * FROM roles ORDER BY id'),
    settings: q(env, 'SELECT key, value FROM settings ORDER BY key'),
    allow: q(env, 'SELECT * FROM allowed_ips ORDER BY id'),
    block: q(env, 'SELECT * FROM blocked_ips ORDER BY id'),
    devices: q(env, 'SELECT id, status, label FROM devices ORDER BY id'),
    sessions: q(env, 'SELECT id, revoked_at FROM sessions ORDER BY id'),
    invitations: q(env, 'SELECT id, revoked_at FROM invitations ORDER BY id'),
    streaks: q(env, 'SELECT * FROM streaks ORDER BY user_id'),
    temp: q(env, 'SELECT * FROM user_roles ORDER BY user_id'),
  });
}

test('the route table covers the contract and every admin route needs a permission', () => {
  assert.ok(ROUTES.length >= 50, `only ${ROUTES.length} admin routes registered`);
  for (const r of ROUTES) assert.ok(permsOf(r).length > 0, `${r.method} ${r.pattern} names no permission`);
  const keys = new Set(ROUTES.map((r) => `${r.method} ${r.pattern}`));
  for (const k of [
    'GET /api/admin/overview', 'POST /api/admin/users/:id/status', 'PUT /api/admin/settings', 'POST /api/admin/gate/open',
    'DELETE /api/admin/network/allow/:id', 'POST /api/admin/audit/:id/revert', 'POST /api/admin/users/:id/streak', 'GET /api/directory',
  ]) assert.ok(keys.has(k), `missing ${k}`);
});

test('an employee gets 403 on every admin route — and nothing changes', async () => {
  const { env, employee, owner } = await world();
  const before = snapshot(env);
  const auditBefore = count(env, 'SELECT COUNT(*) FROM audit_log');
  for (const route of ROUTES) {
    await stepUp(env, employee.client); // a fresh step-up: the refusal is the permission, not the factor
    const r = await call(employee.client, route, { id: owner.user.id });
    assert.equal(r.status, 403, `${route.method} ${route.pattern}: ${r.status} ${r.text}`);
    assert.equal(r.body?.code, 'forbidden', `${route.method} ${route.pattern}: ${r.text}`);
  }
  assert.equal(snapshot(env), before);
  assert.deepEqual(
    q(env, "SELECT action FROM audit_log WHERE id > ? AND action NOT IN ('stepup.success')", auditBefore),
    [],
    'no audit rows besides the step-ups',
  );
});

test('an auditor reads everything they may and writes nothing (except verifying the chain)', async () => {
  const { env, auditor, owner } = await world();
  const before = snapshot(env);
  const seen200 = [];
  for (const route of ROUTES) {
    await stepUp(env, auditor.client);
    const r = await call(auditor.client, route, { id: owner.user.id });
    const allowed = permsOf(route).some((p) => AUDITOR.has(p));
    const label = `${route.method} ${route.pattern}: ${r.status} ${r.text.slice(0, 200)}`;
    if (route.method === 'GET') {
      assert.equal(r.status, allowed ? 200 : 403, label);
      if (allowed) seen200.push(route.pattern);
    } else if (route.pattern === '/api/admin/audit/verify') {
      assert.equal(r.status, 200, label);
      assert.equal(r.body.ok, true);
    } else {
      assert.equal(r.status, 403, label);
      assert.equal(r.body?.code, 'forbidden', label);
    }
  }
  for (const p of ['/api/admin/users', '/api/admin/audit', '/api/admin/settings', '/api/admin/network', '/api/admin/devices', '/api/admin/sessions', '/api/admin/streaks', '/api/admin/visitors', '/api/admin/roles', '/api/admin/overview']) {
    assert.ok(seen200.includes(p), `auditor could not read ${p}`);
  }
  assert.ok(!seen200.includes('/api/admin/gate') && !seen200.includes('/api/admin/users/:id/destinations'), 'reserved reads stay reserved');
  assert.equal(snapshot(env), before);
  const settings = (await auditor.client.get('/api/admin/settings')).body.settings;
  assert.ok(settings.every((s) => s.can_edit === false), 'an auditor is offered no editable setting');
});

test('an administrator cannot suspend another administrator, only people ranked below', async () => {
  const { env, admin, admin2, employee } = await world();
  await stepUp(env, admin.client);
  const r = await admin.client.post(`/api/admin/users/${admin2.user.id}/status`, { status: 'suspended' });
  assert.equal(r.status, 403, r.text);
  assert.equal(r.body.code, 'rank');
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', admin2.user.id)[0].status, 'active');
  const denied = auditRows(env, 'user.status').filter((a) => a.outcome === 'denied');
  assert.equal(denied.length, 1, 'the refusal is recorded as denied');
  for (const status of ['disabled']) {
    const d = await admin.client.post(`/api/admin/users/${admin2.user.id}/status`, { status });
    assert.equal(d.status, 403);
  }
  const role = await admin.client.post(`/api/admin/users/${admin2.user.id}/role`, { role_id: roleId(env, 'employee'), perm_grants: [], perm_denies: [] });
  assert.equal(role.status, 403);
  assert.equal(role.body.code, 'rank');
  // …but an employee, yes — and back.
  const ok = await admin.client.post(`/api/admin/users/${employee.user.id}/status`, { status: 'suspended' });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await employee.client.get('/api/me')).status, 401, 'a suspended person is signed out at once');
  const back = await admin.client.post(`/api/admin/users/${employee.user.id}/status`, { status: 'active' });
  assert.equal(back.status, 200);
  // Nobody acts on themselves from the console.
  const self = await admin.client.post(`/api/admin/users/${admin.user.id}/status`, { status: 'suspended' });
  assert.equal(self.status, 403);
});

test('a manager invites employees and guests only, and touches nobody', async () => {
  const { env, manager, employee, owner } = await world();
  const c = manager.client;
  const emp = await c.post('/api/admin/users', { email: 'mgr-emp@acme.com', full_name: 'Emp Invitee' });
  assert.equal(emp.status, 200, emp.text);
  assert.equal(emp.body.user.role.key, 'employee', 'a missing role_id means employee');
  assert.match(emp.body.invitation.url, /\/invite\?token=[A-Za-z0-9_-]{43}$/);
  const guest = await c.post('/api/admin/users', { email: 'mgr-guest@acme.com', full_name: 'Guest Invitee', role_id: roleId(env, 'guest') });
  assert.equal(guest.status, 200, guest.text);
  for (const key of ['manager', 'auditor', 'admin', 'super_admin']) {
    const r = await c.post('/api/admin/users', { email: `mgr-${key}@acme.com`, full_name: 'Too High', role_id: roleId(env, key) });
    assert.equal(r.status, 403, `${key}: ${r.text}`);
    assert.equal(r.body.code, 'minting');
    assert.equal(count(env, 'SELECT COUNT(*) FROM users WHERE email = ?', `mgr-${key}@acme.com`), 0);
  }
  // An administrator still waiting on their invitation: outranks the manager.
  await stepUp(env, owner.client);
  const invitedAdmin = await owner.client.post('/api/admin/users', { email: 'mgr-target@acme.com', full_name: 'Invited Admin', role_id: roleId(env, 'admin') });
  assert.equal(invitedAdmin.status, 200, invitedAdmin.text);
  const before = snapshot(env);
  await stepUp(env, c);
  const reissue = await c.post(`/api/admin/users/${invitedAdmin.body.user.id}/invitation`, {});
  assert.equal(reissue.status, 403, reissue.text);
  assert.equal(reissue.body.code, 'rank');
  for (const [method, path, body] of [
    ['POST', `/api/admin/users/${employee.user.id}/status`, { status: 'suspended' }],
    ['PATCH', `/api/admin/users/${employee.user.id}`, { full_name: 'Renamed' }],
    ['POST', `/api/admin/users/${employee.user.id}/role`, { role_id: roleId(env, 'guest'), perm_grants: [], perm_denies: [] }],
    ['POST', `/api/admin/users/${employee.user.id}/logout`, {}],
    ['POST', `/api/admin/users/${employee.user.id}/reset-mfa`, {}],
    ['POST', `/api/admin/users/${employee.user.id}/streak`, { current: 9, reason: 'x' }],
    ['POST', `/api/admin/users/${employee.user.id}/revoke-devices`, {}],
  ]) {
    const r = await c.request(method, path, body);
    assert.equal(r.status, 403, `${method} ${path}: ${r.text}`);
  }
  assert.equal(snapshot(env), before);
});

test('danger routes demand a step-up, and the window expires after step_up_minutes', async () => {
  const { env, admin, employee, owner } = await world();
  const c = admin.client;
  advance(env, 16 * MINUTE);
  for (const [path, body] of [
    [`/api/admin/users/${employee.user.id}/status`, { status: 'suspended' }],
    [`/api/admin/users/${employee.user.id}/role`, { role_id: roleId(env, 'guest'), perm_grants: [], perm_denies: [] }],
    ['/api/admin/network/block', { cidr: '185.15.56.0/24' }],
  ]) {
    const r = await c.post(path, body);
    assert.equal(r.status, 403, `${path}: ${r.text}`);
    assert.equal(r.body.step_up_required, true);
  }
  const settings = await c.put('/api/admin/settings', { changes: { timezone: 'UTC' } });
  assert.equal(settings.body.step_up_required, true);
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', employee.user.id)[0].status, 'active');
  assert.equal(count(env, 'SELECT COUNT(*) FROM blocked_ips'), 0);
  // Reads never need one.
  assert.equal((await c.get('/api/admin/users')).status, 200);

  await stepUp(env, c);
  const ok = await c.post(`/api/admin/users/${employee.user.id}/status`, { status: 'suspended' });
  assert.equal(ok.status, 200, ok.text);
  await c.post(`/api/admin/users/${employee.user.id}/status`, { status: 'active' });

  // Shorten the window to 5 minutes; 6 minutes later it has lapsed again.
  await stepUp(env, owner.client);
  const w = await owner.client.put('/api/admin/settings', { changes: { step_up_minutes: 5 } });
  assert.equal(w.status, 200, w.text);
  await stepUp(env, c);
  advance(env, 4 * MINUTE);
  assert.equal((await c.post(`/api/admin/users/${employee.user.id}/logout`, {})).status, 200, 'still fresh at 4 minutes');
  advance(env, 2 * MINUTE);
  const stale = await c.post(`/api/admin/users/${employee.user.id}/logout`, {});
  assert.equal(stale.status, 403);
  assert.equal(stale.body.step_up_required, true);
  await stepUp(env, owner.client);
  await owner.client.put('/api/admin/settings', { changes: { step_up_minutes: 15 } });
});

// Giving an existing person a danger role takes users.roles and a step-up.
// Creating a person WITH one — an invitation, an approved access request, a
// new link for someone still invited — is the same outcome, so it takes the
// step-up too; otherwise a stale (or stolen, idle-valid) session mints a
// Super Admin of its own (SPEC §5.5, §7.9).
test('minting an account into a danger role needs a step-up — invitation, approved request and new link alike', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  setSetting(env, 'access_mode', 'request_access');
  const c = owner.client;
  const emp = await makeUser(env, c, { role: 'employee' });
  // An Administrator invited while the owner was fresh, still to accept.
  const pendingAdmin = await c.post('/api/admin/users', { email: 'adam@acme.com', full_name: 'Adam Admin', role_id: roleId(env, 'admin') });
  assert.equal(pendingAdmin.status, 200, pendingAdmin.text);
  const pendingEmp = await c.post('/api/admin/users', { email: 'eve@acme.com', full_name: 'Eve Employee' });
  assert.equal(pendingEmp.status, 200, pendingEmp.text);
  for (const email of ['walkin@example.org', 'other@example.org']) {
    assert.equal((await client(env).post('/api/access-request', { email, full_name: 'Walk In' })).status, 200);
  }
  const reqId = (email) => q(env, 'SELECT id FROM access_requests WHERE email = ?', email)[0].id;
  advance(env, 20 * MINUTE); // stale step-up, live session

  const promote = await c.post(`/api/admin/users/${emp.user.id}/role`, { role_id: roleId(env, 'super_admin') });
  assert.equal(promote.body.step_up_required, true, 'control: the role change asks');
  for (const key of ['super_admin', 'admin']) {
    const r = await c.post('/api/admin/users', { email: `new.${key}@evil.example`, full_name: 'New', role_id: roleId(env, key) });
    assert.equal(r.status, 403, `${key}: ${r.text}`);
    assert.equal(r.body.step_up_required, true);
    assert.equal(r.body.invitation, undefined, 'no link');
  }
  const ap = await c.post(`/api/admin/requests/${reqId('walkin@example.org')}/approve`, { role_id: roleId(env, 'super_admin') });
  assert.equal(ap.status, 403, ap.text);
  assert.equal(ap.body.step_up_required, true);
  assert.equal(q(env, 'SELECT status FROM access_requests WHERE id = ?', reqId('walkin@example.org'))[0].status, 'pending');
  const re = await c.post(`/api/admin/users/${pendingAdmin.body.user.id}/invitation`, {});
  assert.equal(re.status, 403, re.text);
  assert.equal(re.body.step_up_required, true);
  assert.equal(count(env, "SELECT COUNT(*) FROM users WHERE email LIKE 'new.%'"), 0, 'nobody was created');

  // Roles with nothing dangerous in them stay one click.
  assert.equal((await c.post('/api/admin/users', { email: 'emma@acme.com', full_name: 'Emma' })).status, 200);
  assert.equal((await c.post('/api/admin/users', { email: 'aud@acme.com', full_name: 'Aud', role_id: roleId(env, 'auditor') })).status, 200);
  assert.equal((await c.post(`/api/admin/requests/${reqId('other@example.org')}/approve`, {})).status, 200);
  assert.equal((await c.post(`/api/admin/users/${pendingEmp.body.user.id}/invitation`, {})).status, 200);

  // With a fresh step-up, the danger roles are minted as before.
  await stepUp(env, c);
  assert.equal((await c.post('/api/admin/users', { email: 'sue@acme.com', full_name: 'Sue', role_id: roleId(env, 'super_admin') })).status, 200);
  assert.equal((await c.post(`/api/admin/users/${pendingAdmin.body.user.id}/invitation`, {})).status, 200);
});

test('reserved routes refuse an administrator holding every grantable permission plus a temporary role', async () => {
  const { env, owner } = await world();
  const x = await makeUser(env, owner.client, { role: 'admin', totp: true });
  // A tampered custom role and tampered grants: reserved keys are ignored on read.
  const t = nowIso(env);
  q(env, `INSERT INTO roles (key, name, rank, permissions, is_system, created_at, updated_at) VALUES ('sneaky', 'Sneaky', 90, ?, 0, ?, ?)`,
    JSON.stringify(['*', ...RESERVED]), t, t);
  const sneaky = q(env, "SELECT id FROM roles WHERE key = 'sneaky'")[0].id;
  q(env, 'INSERT INTO user_roles (user_id, role_id, granted_by, expires_at, created_at) VALUES (?, ?, ?, ?, ?)', x.user.id, sneaky, owner.user.id, new Date(env.__clock() + 7 * DAY).toISOString(), t);
  q(env, 'UPDATE users SET perm_grants = ? WHERE id = ?', JSON.stringify([...RESERVED]), x.user.id);
  const me = (await x.client.get('/api/me')).body;
  for (const k of RESERVED) assert.ok(!me.permissions.includes(k), `${k} leaked into effective permissions`);
  assert.equal(me.is_super, false);

  const before = snapshot(env);
  const reserved = ROUTES.filter((r) => permsOf(r).every((p) => RESERVED.has(p)));
  assert.ok(reserved.length >= 10, `only ${reserved.length} reserved routes`);
  for (const route of reserved) {
    await stepUp(env, x.client);
    const r = await call(x.client, route, { id: owner.user.id });
    assert.equal(r.status, 403, `${route.method} ${route.pattern}: ${r.text}`);
    assert.equal(r.body.code, 'forbidden');
  }
  await stepUp(env, x.client);
  const sec = await x.client.put('/api/admin/settings', { changes: { access_mode: 'public' } });
  assert.equal(sec.status, 403, 'security.manage is reserved');
  const mixed = await x.client.put('/api/admin/settings', { changes: { timezone: 'UTC', block_tor: false } });
  assert.equal(mixed.status, 403, 'one reserved key refuses the whole change');
  assert.equal(snapshot(env), before);
  const gen = await x.client.put('/api/admin/settings', { changes: { timezone: 'Europe/London' } });
  assert.equal(gen.status, 200, 'settings.manage keys are theirs');
  // Nor can they hand a reserved permission to anyone.
  const grant = await x.client.post(`/api/admin/users/${x.user.id}/role`, { role_id: roleId(env, 'admin'), perm_grants: ['audit.revert'], perm_denies: [] });
  assert.equal(grant.status, 403);
  q(env, 'DELETE FROM user_roles WHERE user_id = ?', x.user.id);
  q(env, 'DELETE FROM roles WHERE id = ?', sneaky);
  q(env, "UPDATE users SET perm_grants = '[]' WHERE id = ?", x.user.id);
});

test('the last Super Admin cannot be suspended, disabled or demoted — by others, by themselves, or by a revert', async () => {
  const env = freshEnv();
  const owner = await bootstrap(env);
  const temp = await makeUser(env, owner.client, { role: 'admin', totp: true });
  const u = await makeUser(env, owner.client, { role: 'admin', totp: true });
  const superId = roleId(env, 'super_admin');
  const adminId = roleId(env, 'admin');
  await stepUp(env, owner.client);
  const g = await owner.client.post(`/api/admin/users/${temp.user.id}/temp-role`, { role_id: superId, expires_at: new Date(env.__clock() + 7 * DAY).toISOString() });
  assert.equal(g.status, 200, g.text);
  // A timed Super Admin is a peer, but never counts as an owner who will remain.
  await stepUp(env, temp.client);
  for (const status of ['suspended', 'disabled']) {
    const r = await temp.client.post(`/api/admin/users/${owner.user.id}/status`, { status });
    assert.equal(r.status, 403, `${status}: ${r.text}`);
    assert.equal(r.body.code, 'last_superuser');
  }
  const demote = await temp.client.post(`/api/admin/users/${owner.user.id}/role`, { role_id: adminId, perm_grants: [], perm_denies: [] });
  assert.equal(demote.status, 403);
  assert.equal(demote.body.code, 'last_superuser');
  assert.equal(q(env, 'SELECT status FROM users WHERE id = ?', owner.user.id)[0].status, 'active');
  // By themselves.
  await stepUp(env, owner.client);
  for (const status of ['suspended', 'disabled']) {
    const r = await owner.client.post(`/api/admin/users/${owner.user.id}/status`, { status });
    assert.equal(r.status, 403, r.text);
  }
  const selfDemote = await owner.client.post(`/api/admin/users/${owner.user.id}/role`, { role_id: adminId, perm_grants: [], perm_denies: [] });
  assert.equal(selfDemote.status, 403);
  assert.equal(q(env, 'SELECT status, role_id FROM users WHERE id = ?', owner.user.id)[0].role_id, superId);

  // Through a revert: the owner promotes U; U demotes the owner; U is now
  // the last permanent Super Admin, so reverting U's promotion is refused.
  const promote = await owner.client.post(`/api/admin/users/${u.user.id}/role`, { role_id: superId, perm_grants: [], perm_denies: [] });
  assert.equal(promote.status, 200, promote.text);
  const promotion = auditRows(env, 'user.role').filter((a) => a.outcome === 'success').pop();
  await stepUp(env, u.client);
  const ownerDown = await u.client.post(`/api/admin/users/${owner.user.id}/role`, { role_id: adminId, perm_grants: [], perm_denies: [] });
  assert.equal(ownerDown.status, 200, ownerDown.text);
  await stepUp(env, temp.client);
  const rev = await temp.client.post(`/api/admin/audit/${promotion.id}/revert`, {});
  assert.equal(rev.status, 403, rev.text);
  assert.equal(rev.body.code, 'last_superuser');
  assert.equal(q(env, 'SELECT role_id FROM users WHERE id = ?', u.user.id)[0].role_id, superId);
  const denied = auditRows(env, 'audit.revert');
  assert.equal(denied.length, 1);
  assert.equal(denied[0].outcome, 'denied');
  assert.equal(denied[0].reverts_id, promotion.id);
  // …and the entry is still offered for revert: a denied attempt is not a revert.
  const list = (await temp.client.get(`/api/admin/audit?action=user.role`)).body.entries;
  assert.equal(list.find((e) => e.id === promotion.id).revertible, true);
});

await run();
